use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    path::Path,
};

use anyhow::{Context as _, Result, ensure};
use attached_session_sync_protocol::{
    account::{ApiKeyScope, RecordId},
    canonical::HerdrVersion as SessionAccessHerdrVersion,
    crypto::{
        Envelope as CryptoEnvelope, VerificationContext,
        open_session_access_descriptor_cursorless_for_native_upgrade,
    },
};
use attached_tunnel_protocol::HerdrVersion;

use super::{
    http::SyncHttpClient,
    state,
    state_catalog::{self, CatalogRecord, SyncedSession},
};

#[derive(Debug)]
pub struct RefreshResult {
    pub sessions: Vec<SyncedSession>,
    pub warnings: Vec<RefreshWarning>,
}

#[derive(Debug)]
pub enum RefreshWarning {
    CatalogRebuilt(anyhow::Error),
    RecordDiscarded {
        record_id: RecordId,
        error: anyhow::Error,
    },
    EndpointRegistryUnavailable,
}

impl RefreshWarning {
    pub(crate) fn is_verbose_only(&self) -> bool {
        matches!(self, Self::RecordDiscarded { .. })
    }
}

impl fmt::Display for RefreshWarning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogRebuilt(error) => write!(
                formatter,
                "could not load synchronized session catalog; rebuilt it after a successful refresh: {error}"
            ),
            Self::RecordDiscarded { record_id, error } => write!(
                formatter,
                "discarded synchronized record {record_id} from the local catalog: {error}"
            ),
            Self::EndpointRegistryUnavailable => formatter.write_str(
                "could not inspect the local endpoint registry; remote sessions were retained",
            ),
        }
    }
}

pub async fn refresh_sessions(
    state_dir: &Path,
    local_version: HerdrVersion,
) -> Result<RefreshResult> {
    match crate::endpoint_registry::default_dir() {
        Ok(registry_dir) => {
            refresh_sessions_with_registry(state_dir, local_version, &registry_dir).await
        }
        Err(_) => {
            let mut result =
                refresh_sessions_with_registry(state_dir, local_version, Path::new("")).await?;
            push_registry_warning(&mut result.warnings);
            Ok(result)
        }
    }
}

async fn refresh_sessions_with_registry(
    state_dir: &Path,
    local_version: HerdrVersion,
    registry_dir: &Path,
) -> Result<RefreshResult> {
    refresh_sessions_with_registry_at(
        state_dir,
        local_version,
        registry_dir,
        super::utc_now_seconds(),
    )
    .await
}

async fn refresh_sessions_with_registry_at(
    state_dir: &Path,
    local_version: HerdrVersion,
    registry_dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RefreshResult> {
    let mut warnings = Vec::new();
    let Some(account) = state::load_account_optional(state_dir, ApiKeyScope::Download)
        .context("could not load synchronization account")?
    else {
        return Ok(RefreshResult {
            sessions: Vec::new(),
            warnings,
        });
    };
    let local_version = descriptor_version(local_version)?;
    let mut catalog = match state_catalog::load(state_dir, &account) {
        Ok(catalog) => catalog,
        Err(error) => {
            warnings.push(RefreshWarning::CatalogRebuilt(error));
            state_catalog::Catalog::empty(&account)
        }
    };
    let client = SyncHttpClient::new().context("could not initialize synchronization refresh")?;
    let index = client
        .list_records(&account)
        .await
        .context("could not refresh the synchronized record index")?;

    let baseline_revisions = catalog
        .records
        .iter()
        .map(|record| (record.record_id, record.service_revision))
        .collect::<HashSet<_>>();
    let baseline_pruned_revisions = catalog.pruned_revision_pairs().collect::<HashSet<_>>();
    let mut existing = std::mem::take(&mut catalog.records)
        .into_iter()
        .map(|record| (record.record_id, record))
        .collect::<BTreeMap<_, _>>();
    let mut accepted = Vec::with_capacity(index.records.len());
    for indexed in index.records {
        let previous = existing.remove(&indexed.record_id);
        if let Some(previous) = previous
            && previous.service_revision == indexed.revision
        {
            if previous.is_expired_at(now) {
                let error = anyhow::anyhow!("session access descriptor expired");
                tracing::debug!(
                    record_id = %indexed.record_id,
                    reason = %error,
                    "discarded invalid synchronized record during refresh"
                );
                warnings.push(RefreshWarning::RecordDiscarded {
                    record_id: indexed.record_id,
                    error,
                });
                continue;
            }
            accepted.push(previous);
            continue;
        }

        let fetched = client
            .get_record(&account, indexed.record_id)
            .await
            .with_context(|| format!("could not fetch synchronized record {}", indexed.record_id))?
            .with_context(|| {
                format!(
                    "synchronized record {} changed while refreshing",
                    indexed.record_id
                )
            })?;
        ensure!(
            fetched.revision == indexed.revision,
            "synchronized record {} changed while refreshing",
            indexed.record_id
        );
        let envelope = CryptoEnvelope::new(fetched.envelope.nonce, fetched.envelope.ciphertext)
            .with_context(|| {
                format!(
                    "synchronized record {} has an invalid envelope",
                    indexed.record_id
                )
            })?;
        let context = VerificationContext {
            account_id: *account.account_id().as_bytes(),
            record_id: *indexed.record_id.as_bytes(),
            now,
            local_version,
        };
        let opened = match open_session_access_descriptor_cursorless_for_native_upgrade(
            &envelope,
            account.account_root_key(),
            &context,
        ) {
            Ok(opened) => opened,
            Err(error) => {
                tracing::debug!(
                    record_id = %indexed.record_id,
                    reason = %error,
                    "discarded invalid synchronized record during refresh"
                );
                warnings.push(RefreshWarning::RecordDiscarded {
                    record_id: indexed.record_id,
                    error: error.into(),
                });
                continue;
            }
        };
        accepted.push(CatalogRecord::from_opened(
            indexed.record_id,
            fetched.revision,
            &opened,
        ));
    }
    accepted.sort_by_key(|record| record.record_id);
    catalog.records = accepted;
    state_catalog::save_refresh(
        state_dir,
        &account,
        &baseline_revisions,
        &baseline_pruned_revisions,
        &catalog,
    )
    .context("could not save synchronized session catalog")?;

    let listing =
        state_catalog::sessions_excluding_local_endpoints(state_dir, &account, now, registry_dir)?;
    Ok(finish_refresh(listing, warnings))
}

fn finish_refresh(
    listing: state_catalog::SessionListing,
    mut warnings: Vec<RefreshWarning>,
) -> RefreshResult {
    if listing.registry_unavailable {
        push_registry_warning(&mut warnings);
    }
    RefreshResult {
        sessions: listing.sessions,
        warnings,
    }
}

fn push_registry_warning(warnings: &mut Vec<RefreshWarning>) {
    if !warnings
        .iter()
        .any(|warning| matches!(warning, RefreshWarning::EndpointRegistryUnavailable))
    {
        warnings.push(RefreshWarning::EndpointRegistryUnavailable);
    }
}

fn descriptor_version(version: HerdrVersion) -> Result<SessionAccessHerdrVersion> {
    Ok(SessionAccessHerdrVersion::new(
        u16::try_from(version.major())
            .context("local Herdr major version exceeds sync protocol")?,
        u16::try_from(version.minor())
            .context("local Herdr minor version exceeds sync protocol")?,
        u16::try_from(version.patch())
            .context("local Herdr patch version exceeds sync protocol")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use attached_session_sync_protocol::{
        account::RecordId,
        api::{Envelope, LiveRecordIndex, LiveRecordIndexEntry},
        canonical::{HerdrVersion as SessionAccessVersion, SessionAccessDescriptor},
        crypto::seal_session_access_descriptor,
    };
    use attached_tunnel_protocol::CapabilitySecret;
    use iroh_tickets::endpoint::EndpointTicket;
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt as _, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";
    const ENDPOINT_ID: [u8; 32] = [
        0xae, 0x58, 0xff, 0x88, 0x33, 0x24, 0x1a, 0xc8, 0x2d, 0x6f, 0xf7, 0x61, 0x10, 0x46, 0xed,
        0x67, 0xb5, 0x07, 0x2d, 0x14, 0x2c, 0x58, 0x8d, 0x00, 0x63, 0xe9, 0x42, 0xd9, 0xa7, 0x55,
        0x02, 0xb6,
    ];

    async fn serve_catalog(
        listener: tokio::net::TcpListener,
        index_path: String,
        index_body: Vec<u8>,
        records: BTreeMap<String, Vec<u8>>,
        request_count: usize,
    ) -> anyhow::Result<()> {
        for _ in 0..request_count {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await?;
                anyhow::ensure!(read != 0, "HTTP request ended before its headers");
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                anyhow::ensure!(request.len() <= 8192, "HTTP request headers too large");
            }
            let request = std::str::from_utf8(&request)?;
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_ascii_whitespace().nth(1))
                .ok_or_else(|| anyhow::anyhow!("malformed HTTP request"))?;
            let (body, etag) = if path == index_path {
                (&index_body, None)
            } else {
                (
                    records
                        .get(path)
                        .ok_or_else(|| anyhow::anyhow!("unexpected HTTP path {path}"))?,
                    Some("ETag: \"1\"\r\n"),
                )
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
                etag.unwrap_or_default(),
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            stream.write_all(body).await?;
            stream.shutdown().await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn native_refresh_persists_versions_and_fails_when_the_service_is_unavailable() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let root = crate::test_support::canonical_tempdir();
            let state_dir = root.path().join("state");
            let registry_dir = root.path().join("registry-user/live-endpoints");
            state::test_support::create_account(&state_dir, &origin).unwrap();
            let account = state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
            let corrupt_catalog = state_dir.join("sync-catalog.json");
            std::fs::write(&corrupt_catalog, b"not JSON").unwrap();
            std::fs::set_permissions(&corrupt_catalog, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            let now = super::super::utc_now_seconds();
            let local = HerdrVersion::new(3, 2, 1);
            let remote_secret = iroh::SecretKey::from_bytes(&[0x42; 32]);
            let mut remote_addr = ENDPOINT
                .parse::<EndpointTicket>()
                .unwrap()
                .endpoint_addr()
                .clone();
            remote_addr.id = remote_secret.public();
            let remote_endpoint = EndpointTicket::new(remote_addr).to_string();
            let fixtures = [
                (
                    5_u8,
                    "aging-host",
                    "soonexpired",
                    SessionAccessVersion::new(3, 2, 1),
                    remote_endpoint.clone(),
                    now - Duration::from_secs(300),
                    now + Duration::from_secs(1),
                ),
                (
                    6_u8,
                    "invalid-host",
                    "corrupt",
                    SessionAccessVersion::new(3, 2, 1),
                    remote_endpoint.clone(),
                    now - Duration::from_secs(1),
                    now + Duration::from_secs(300),
                ),
                (
                    7_u8,
                    "expired-host",
                    "stale",
                    SessionAccessVersion::new(3, 2, 1),
                    remote_endpoint.clone(),
                    now - Duration::from_secs(300),
                    now - Duration::from_secs(1),
                ),
                (
                    8_u8,
                    "duplicate-host",
                    "work",
                    SessionAccessVersion::new(3, 2, 1),
                    ENDPOINT.to_owned(),
                    now - Duration::from_secs(1),
                    now + Duration::from_secs(300),
                ),
                (
                    9_u8,
                    "duplicate-host",
                    "work",
                    SessionAccessVersion::new(3, 2, 1),
                    remote_endpoint.clone(),
                    now - Duration::from_secs(1),
                    now + Duration::from_secs(300),
                ),
                (
                    10_u8,
                    "patch-host",
                    "patch",
                    SessionAccessVersion::new(3, 2, 0),
                    remote_endpoint.clone(),
                    now - Duration::from_secs(1),
                    now + Duration::from_secs(300),
                ),
                (
                    11_u8,
                    "minor-host",
                    "minor",
                    SessionAccessVersion::new(3, 1, 9),
                    remote_endpoint.clone(),
                    now - Duration::from_secs(1),
                    now + Duration::from_secs(300),
                ),
                (
                    12_u8,
                    "major-host",
                    "major",
                    SessionAccessVersion::new(2, 9, 9),
                    remote_endpoint,
                    now - Duration::from_secs(1),
                    now + Duration::from_secs(300),
                ),
            ];
            let mut entries = Vec::new();
            let mut records = BTreeMap::new();
            for (byte, host, session, version, endpoint_ticket, issued_at, expires_at) in fixtures {
                let record_id = RecordId::from_bytes([byte; 16]);
                let descriptor = SessionAccessDescriptor::new(
                    host.to_owned(),
                    issued_at,
                    expires_at,
                    endpoint_ticket,
                    CapabilitySecret::from_bytes([byte; 32]),
                    version,
                    vec![session.to_owned()],
                )
                .unwrap();
                let crypto = seal_session_access_descriptor(
                    &descriptor,
                    account.account_root_key(),
                    account.account_id().as_bytes(),
                    record_id.as_bytes(),
                )
                .unwrap();
                let (nonce, ciphertext) = crypto.into_parts();
                let ciphertext = if byte == 6 { vec![0] } else { ciphertext };
                let body = serde_json::to_vec(&Envelope::new(nonce, ciphertext).unwrap()).unwrap();
                let path = format!("/v1/accounts/{}/records/{record_id}", account.account_id());
                records.insert(path, body);
                entries.push(LiveRecordIndexEntry {
                    record_id,
                    revision: 1,
                });
            }
            let index = LiveRecordIndex::new(entries).unwrap();
            let index_body = serde_json::to_vec(&index).unwrap();
            let index_path = format!("/v1/accounts/{}/records", account.account_id());
            let request_count = records.len() + 4;
            let server = tokio::spawn(serve_catalog(
                listener,
                index_path,
                index_body,
                records,
                request_count,
            ));
            let _guard = crate::endpoint_registry::register(&registry_dir, ENDPOINT_ID).unwrap();

            let refreshed =
                refresh_sessions_with_registry_at(&state_dir, local, &registry_dir, now)
                    .await
                    .unwrap();
            assert_eq!(refreshed.warnings.len(), 3, "{:?}", refreshed.warnings);
            assert!(
                refreshed.warnings.iter().any(|warning| warning
                    .to_string()
                    .contains("rebuilt it after a successful refresh")),
                "{:?}",
                refreshed.warnings
            );
            assert!(
                refreshed.warnings.iter().any(|warning| {
                    let warning = warning.to_string();
                    warning.contains("discarded synchronized record")
                        && warning.contains(&RecordId::from_bytes([7; 16]).to_string())
                        && warning.contains("expired")
                }),
                "{:?}",
                refreshed.warnings
            );
            assert!(
                refreshed.warnings.iter().any(|warning| {
                    let warning = warning.to_string();
                    warning.contains("discarded synchronized record")
                        && warning.contains(&RecordId::from_bytes([6; 16]).to_string())
                        && warning.contains("decryption failed")
                }),
                "{:?}",
                refreshed.warnings
            );
            assert_eq!(refreshed.sessions.len(), 5);
            assert!(
                refreshed
                    .sessions
                    .iter()
                    .any(|session| session.target == "aging-host/soonexpired")
            );

            let refreshed_after_expiration = refresh_sessions_with_registry_at(
                &state_dir,
                local,
                &registry_dir,
                now + Duration::from_secs(2),
            )
            .await
            .unwrap();
            assert_eq!(
                refreshed_after_expiration.sessions.len(),
                4,
                "an expired cached record hid otherwise valid sessions"
            );
            assert!(
                refreshed_after_expiration.warnings.iter().any(|warning| {
                    let warning = warning.to_string();
                    warning.contains(&RecordId::from_bytes([5; 16]).to_string())
                        && warning.contains("expired")
                }),
                "{:?}",
                refreshed_after_expiration.warnings
            );
            let persisted_catalog = state_catalog::load(&state_dir, &account).unwrap();
            assert!(
                persisted_catalog.records.iter().all(|record| {
                    ![
                        RecordId::from_bytes([5; 16]),
                        RecordId::from_bytes([6; 16]),
                        RecordId::from_bytes([7; 16]),
                    ]
                    .contains(&record.record_id)
                }),
                "discarded records remained in the local catalog"
            );
            assert_eq!(
                refreshed
                    .sessions
                    .iter()
                    .filter(|candidate| candidate.target == "duplicate-host/work")
                    .count(),
                1,
                "fresh refresh did not filter only the active exact endpoint"
            );
            for (host, session, expected) in [
                ("patch-host", "patch", [3, 2, 0]),
                ("minor-host", "minor", [3, 1, 9]),
                ("major-host", "major", [2, 9, 9]),
            ] {
                assert!(
                    refreshed
                        .sessions
                        .iter()
                        .any(|candidate| candidate.target == format!("{host}/{session}"))
                );
                let persisted = state_catalog::attachment(&state_dir, &account, host, session, now)
                    .unwrap()
                    .expect("persisted attachment remains selectable");
                assert_eq!(persisted.herdr_version, expected);
                let remote = HerdrVersion::new(
                    u32::from(expected[0]),
                    u32::from(expected[1]),
                    u32::from(expected[2]),
                );
                assert!(
                    super::super::attach::decide_upgrade(
                        local,
                        remote,
                        true,
                        false,
                        &mut std::io::Cursor::new(b""),
                        &mut Vec::new(),
                    )
                    .unwrap()
                );
            }
            server.await.unwrap().unwrap();

            let error = refresh_sessions_with_registry(&state_dir, local, &registry_dir)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("record index"), "{error}");
            assert!(
                state_catalog::attachment(&state_dir, &account, "patch-host", "patch", now,)
                    .unwrap()
                    .is_some(),
                "a failed refresh replaced the previous catalog"
            );
        })
        .await
        .expect("native refresh and persisted-selection scenario timed out");
    }
}
