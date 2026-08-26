use std::{collections::HashSet, path::Path, str::FromStr as _};

use anyhow::{Context as _, Result, ensure};
use attached_session_sync_protocol::{
    account::{AccountId, RecordId},
    crypto::OpenedSessionAccessDescriptor,
    limits::{
        MAX_ENDPOINT_TICKET_BYTES, MAX_LIVE_RECORDS, MAX_SESSIONS, validate_host_label,
        validate_session_name,
    },
};
use chrono::{DateTime, Utc};
use iroh_tickets::endpoint::EndpointTicket;
use serde::{Deserialize, Serialize};

use crate::secure_state::{with_exclusive_lock, with_locked_existing};

use super::state::AccountCredentials;

const CATALOG_FILE: &str = "sync-catalog.json";
const CATALOG_LOCK: &str = "sync-catalog.lock";
const MAX_CATALOG_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncedSession {
    pub target: String,
    pub host: String,
    pub session: String,
}

pub(super) struct SessionListing {
    pub(super) sessions: Vec<SyncedSession>,
    pub(super) registry_unavailable: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SyncedAttachment {
    pub endpoint_ticket: String,
    pub endpoint_identity: [u8; 32],
    pub attach_capability: [u8; 32],
    pub herdr_version: [u16; 3],
    pub expires_at: DateTime<Utc>,
    pub session: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Catalog {
    account_id: AccountId,
    service_origin: String,
    pub(super) records: Vec<CatalogRecord>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogRecord {
    pub(super) record_id: RecordId,
    pub(super) service_revision: u64,
    host_label: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    expires_at: DateTime<Utc>,
    endpoint_ticket: String,
    endpoint_identity: [u8; 32],
    attach_capability: [u8; 32],
    herdr_version: [u16; 3],
    sessions: Vec<String>,
}

impl Catalog {
    pub(super) fn empty(account: &AccountCredentials) -> Self {
        Self {
            account_id: account.account_id(),
            service_origin: account.service_origin().to_owned(),
            records: Vec::new(),
        }
    }
}

impl CatalogRecord {
    pub(super) fn from_opened(
        record_id: RecordId,
        service_revision: u64,
        opened: &OpenedSessionAccessDescriptor,
    ) -> Self {
        let descriptor = opened.descriptor();
        Self {
            record_id,
            service_revision,
            host_label: descriptor.host_label().to_owned(),
            expires_at: descriptor.expires_at(),
            endpoint_ticket: descriptor.endpoint_ticket().to_owned(),
            endpoint_identity: descriptor.endpoint_identity(),
            attach_capability: descriptor.attach_capability_bytes(),
            herdr_version: [
                descriptor.herdr_version().major,
                descriptor.herdr_version().minor,
                descriptor.herdr_version().patch,
            ],
            sessions: descriptor.sessions().to_vec(),
        }
    }
}

pub(super) fn load(state_dir: &Path, account: &AccountCredentials) -> Result<Catalog> {
    let encoded = with_locked_existing(state_dir, CATALOG_LOCK, |directory| {
        directory.read_optional_bounded(CATALOG_FILE, MAX_CATALOG_BYTES)
    })?;
    let Some(encoded) = encoded else {
        return Ok(Catalog::empty(account));
    };
    let catalog: Catalog = serde_json::from_slice(&encoded).context("invalid sync catalog")?;
    validate(&catalog, account)?;
    Ok(catalog)
}

pub(super) fn save(
    state_dir: &Path,
    account: &AccountCredentials,
    catalog: &Catalog,
) -> Result<()> {
    validate(catalog, account)?;
    let encoded = serde_json::to_vec(catalog).context("could not encode sync catalog")?;
    ensure!(
        encoded.len() <= MAX_CATALOG_BYTES,
        "sync catalog exceeds local limit"
    );
    with_exclusive_lock(state_dir, CATALOG_LOCK, |directory| {
        if directory
            .read_optional_bounded(CATALOG_FILE, MAX_CATALOG_BYTES)?
            .is_some()
        {
            directory.atomic_replace(CATALOG_FILE, &encoded)
        } else if directory.create_noclobber(CATALOG_FILE, &encoded)? {
            Ok(())
        } else {
            anyhow::bail!("sync catalog was concurrently installed")
        }
    })
}

fn sessions_with_filter(
    state_dir: &Path,
    account: &AccountCredentials,
    now: DateTime<Utc>,
    mut suppress: impl FnMut(&CatalogRecord) -> bool,
) -> Result<Vec<SyncedSession>> {
    let catalog = load(state_dir, account)?;
    let mut sessions = catalog
        .records
        .iter()
        .filter(|record| {
            if now >= record.expires_at {
                tracing::debug!(
                    record_id = %record.record_id,
                    reason = "expired",
                    "catalog record skipped"
                );
                false
            } else {
                !suppress(record)
            }
        })
        .flat_map(|record| {
            let target_host = record.host_label.clone();
            record.sessions.iter().map(move |session| SyncedSession {
                target: format!("{target_host}/{session}"),
                host: record.host_label.clone(),
                session: session.clone(),
            })
        })
        .collect::<Vec<_>>();
    sessions.sort_by(|left, right| left.target.cmp(&right.target));
    Ok(sessions)
}

pub(super) fn sessions_excluding_local_endpoints(
    state_dir: &Path,
    account: &AccountCredentials,
    now: DateTime<Utc>,
    registry_dir: &Path,
) -> Result<SessionListing> {
    let mut registry_unavailable = false;
    let sessions = sessions_with_filter(state_dir, account, now, |record| {
        match crate::endpoint_registry::is_active(registry_dir, record.endpoint_identity) {
            Ok(true) => {
                tracing::debug!(
                    record_id = %record.record_id,
                    reason = "active_local_endpoint",
                    "catalog record skipped"
                );
                true
            }
            Ok(false) => false,
            Err(_) => {
                registry_unavailable = true;
                tracing::warn!(
                    record_id = %record.record_id,
                    reason = "endpoint_registry_unavailable",
                    "catalog record retained"
                );
                false
            }
        }
    })?;
    Ok(SessionListing {
        sessions,
        registry_unavailable,
    })
}

pub fn attachment(
    state_dir: &Path,
    account: &AccountCredentials,
    host: &str,
    session: &str,
    now: DateTime<Utc>,
) -> Result<Option<SyncedAttachment>> {
    let catalog = load(state_dir, account)?;
    let mut matches = catalog.records.iter().filter(|record| {
        record.host_label == host
            && now < record.expires_at
            && record.sessions.iter().any(|candidate| candidate == session)
    });
    let selected = matches.next();
    ensure!(
        matches.next().is_none(),
        "synchronized host label `{host}` is ambiguous"
    );
    Ok(selected.map(|record| SyncedAttachment {
        endpoint_ticket: record.endpoint_ticket.clone(),
        endpoint_identity: record.endpoint_identity,
        attach_capability: record.attach_capability,
        herdr_version: record.herdr_version,
        expires_at: record.expires_at,
        session: session.to_owned(),
    }))
}

fn validate(catalog: &Catalog, account: &AccountCredentials) -> Result<()> {
    ensure!(
        catalog.account_id == account.account_id(),
        "sync catalog account mismatch"
    );
    ensure!(
        catalog.service_origin == account.service_origin(),
        "sync catalog service mismatch"
    );
    ensure!(
        catalog.records.len() <= MAX_LIVE_RECORDS,
        "too many sync records"
    );
    let mut record_ids = HashSet::new();
    for record in &catalog.records {
        ensure!(record_ids.insert(record.record_id), "duplicate sync record");
        ensure!(record.service_revision > 0, "invalid sync service revision");
        ensure!(
            validate_host_label(&record.host_label),
            "invalid synchronized host label"
        );
        ensure!(
            record.expires_at.timestamp() >= 0 && record.expires_at.timestamp_subsec_nanos() == 0,
            "invalid session access descriptor expiration"
        );
        ensure!(
            !record.endpoint_ticket.is_empty()
                && record.endpoint_ticket.len() <= MAX_ENDPOINT_TICKET_BYTES
                && record.endpoint_ticket.is_ascii(),
            "invalid synchronized endpoint"
        );
        let endpoint = EndpointTicket::from_str(&record.endpoint_ticket)
            .context("invalid synchronized endpoint")?;
        ensure!(
            endpoint.to_string() == record.endpoint_ticket
                && endpoint.endpoint_addr().id.as_bytes() == &record.endpoint_identity,
            "invalid synchronized endpoint"
        );
        ensure!(record.sessions.len() <= MAX_SESSIONS, "too many sessions");
        ensure!(
            record
                .sessions
                .iter()
                .all(|session| validate_session_name(session))
                && record.sessions.windows(2).all(|pair| pair[0] < pair[1]),
            "invalid synchronized sessions"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attached_session_sync_protocol::account::ApiKeyScope;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Capture {
        type Writer = CaptureWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CaptureWriter(self.0.clone())
        }
    }

    impl Capture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn capture_info(operation: impl FnOnce()) -> String {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(capture.clone())
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, operation);
        capture.contents()
    }

    fn timestamp(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).expect("fixture timestamp")
    }

    fn record(identity_byte: u8, host: &str, session: &str) -> CatalogRecord {
        let secret = iroh::SecretKey::from_bytes(&[identity_byte; 32]);
        let mut address = ENDPOINT
            .parse::<EndpointTicket>()
            .expect("fixture endpoint")
            .endpoint_addr()
            .clone();
        address.id = secret.public();
        let endpoint_ticket = EndpointTicket::new(address).to_string();
        CatalogRecord {
            record_id: RecordId::from_bytes([identity_byte; 16]),
            service_revision: 1,
            host_label: host.to_owned(),
            expires_at: timestamp(1_800_000_000),
            endpoint_ticket,
            endpoint_identity: *secret.public().as_bytes(),
            attach_capability: [7; 32],
            herdr_version: [1, 2, 3],
            sessions: vec![session.to_owned()],
        }
    }

    #[test]
    fn active_exact_endpoint_sessions_are_suppressed() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        let registry_dir = root.path().join("registry-user/live-endpoints");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        let record = record(0x21, "office", "work");
        let identity = record.endpoint_identity;
        catalog.records.push(record);
        save(&state_dir, &account, &catalog).unwrap();
        let _guard = crate::endpoint_registry::register(&registry_dir, identity).unwrap();

        let mut listed = None;
        let log = capture_info(|| {
            listed = Some(
                sessions_excluding_local_endpoints(
                    &state_dir,
                    &account,
                    timestamp(1_700_000_000),
                    &registry_dir,
                )
                .unwrap(),
            );
        });
        let listed = listed.unwrap();

        assert!(
            listed.sessions.is_empty(),
            "locally served session was listed twice"
        );
        assert!(!listed.registry_unavailable);
        assert!(log.contains("catalog record skipped"), "{log}");
        assert!(log.contains("reason=\"active_local_endpoint\""), "{log}");
    }

    #[test]
    fn expired_records_emit_a_safe_meaningful_skip_event() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        let expired = record(0x51, "expired-host", "private-session");
        let record_id = expired.record_id.to_string();
        catalog.records.push(expired);
        save(&state_dir, &account, &catalog).unwrap();

        let log = capture_info(|| {
            let sessions =
                sessions_with_filter(&state_dir, &account, timestamp(1_900_000_000), |_| false)
                    .unwrap();
            assert!(sessions.is_empty());
        });

        assert!(log.contains("catalog record skipped"), "{log}");
        assert!(log.contains("reason=\"expired\""), "{log}");
        assert!(log.contains(&format!("record_id={record_id}")), "{log}");
        for secret in [ENDPOINT, "private-session", "expired-host", "07070707"] {
            assert!(
                !log.contains(secret),
                "sensitive value {secret:?} leaked in {log:?}"
            );
        }
    }

    #[test]
    fn same_label_different_endpoint_is_retained() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        let registry_dir = root.path().join("registry-user/live-endpoints");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        let local = record(0x31, "office", "work");
        let local_identity = local.endpoint_identity;
        catalog.records.push(local);
        catalog.records.push(record(0x32, "office", "work"));
        save(&state_dir, &account, &catalog).unwrap();
        let _guard = crate::endpoint_registry::register(&registry_dir, local_identity).unwrap();

        let listed = sessions_excluding_local_endpoints(
            &state_dir,
            &account,
            timestamp(1_700_000_000),
            &registry_dir,
        )
        .unwrap();

        assert_eq!(listed.sessions.len(), 1);
        assert_eq!(listed.sessions[0].target, "office/work");
        assert!(!listed.registry_unavailable);
    }

    #[test]
    fn unsafe_registry_fails_open_and_marks_the_listing() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        let registry_root = root.path().join("registry-user");
        std::fs::create_dir(&registry_root).unwrap();
        std::fs::set_permissions(&registry_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let registry_dir = registry_root.join("live-endpoints");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        catalog.records.push(record(0x41, "office", "work"));
        save(&state_dir, &account, &catalog).unwrap();
        std::fs::create_dir(&registry_dir).unwrap();
        std::fs::set_permissions(&registry_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut listed = None;
        let log = capture_info(|| {
            listed = Some(
                sessions_excluding_local_endpoints(
                    &state_dir,
                    &account,
                    timestamp(1_700_000_000),
                    &registry_dir,
                )
                .unwrap(),
            );
        });
        let listed = listed.unwrap();

        assert_eq!(
            listed.sessions.len(),
            1,
            "registry error hid a remote session"
        );
        assert!(listed.registry_unavailable);
        assert!(log.contains("catalog record retained"), "{log}");
        assert!(
            log.contains("reason=\"endpoint_registry_unavailable\""),
            "{log}"
        );
    }
}
