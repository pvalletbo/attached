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
    pub published_at: Option<DateTime<Utc>>,
}

pub(super) struct SessionListing {
    pub(super) sessions: Vec<SyncedSession>,
    pub(super) registry_unavailable: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SyncedAttachment {
    pub(super) record_id: RecordId,
    pub(super) service_revision: u64,
    pub endpoint_ticket: String,
    pub endpoint_identity: [u8; 32],
    pub attach_capability: [u8; 32],
    pub herdr_version: [u16; 3],
    pub expires_at: DateTime<Utc>,
    pub session: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Catalog {
    account_id: AccountId,
    service_origin: String,
    #[serde(default)]
    generation: u64,
    pub(super) records: Vec<CatalogRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pruned_revisions: Vec<PrunedRevision>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrunedRevision {
    record_id: RecordId,
    service_revision: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogRecord {
    pub(super) record_id: RecordId,
    pub(super) service_revision: u64,
    host_label: String,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    published_at: Option<DateTime<Utc>>,
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
            generation: 0,
            records: Vec::new(),
            pruned_revisions: Vec::new(),
        }
    }

    pub(super) fn pruned_revision_pairs(&self) -> impl Iterator<Item = (RecordId, u64)> + '_ {
        self.pruned_revisions
            .iter()
            .map(|pruned| (pruned.record_id, pruned.service_revision))
    }
}

impl CatalogRecord {
    pub(super) fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

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
            published_at: Some(descriptor.issued_at()),
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

#[cfg(test)]
pub(super) fn save(
    state_dir: &Path,
    account: &AccountCredentials,
    catalog: &Catalog,
) -> Result<()> {
    validate(catalog, account)?;
    with_exclusive_lock(state_dir, CATALOG_LOCK, |directory| {
        let current = directory.read_optional_bounded(CATALOG_FILE, MAX_CATALOG_BYTES)?;
        let current_generation = current
            .as_deref()
            .and_then(|encoded| serde_json::from_slice::<Catalog>(encoded).ok())
            .map_or(0, |catalog| catalog.generation);
        let mut next = catalog.clone();
        next.generation = current_generation
            .checked_add(1)
            .context("sync catalog generation exhausted")?;
        let encoded = serde_json::to_vec(&next).context("could not encode sync catalog")?;
        ensure!(
            encoded.len() <= MAX_CATALOG_BYTES,
            "sync catalog exceeds local limit"
        );
        if current.is_some() {
            directory.atomic_replace(CATALOG_FILE, &encoded)
        } else if directory.create_noclobber(CATALOG_FILE, &encoded)? {
            Ok(())
        } else {
            anyhow::bail!("sync catalog was concurrently installed")
        }
    })
}

pub(super) fn save_refresh(
    state_dir: &Path,
    account: &AccountCredentials,
    baseline_revisions: &HashSet<(RecordId, u64)>,
    baseline_pruned_revisions: &HashSet<(RecordId, u64)>,
    refreshed: &Catalog,
) -> Result<()> {
    validate(refreshed, account)?;
    with_exclusive_lock(state_dir, CATALOG_LOCK, |directory| {
        let current = directory
            .read_optional_bounded(CATALOG_FILE, MAX_CATALOG_BYTES)?
            .and_then(|encoded| serde_json::from_slice::<Catalog>(&encoded).ok())
            .filter(|catalog| validate(catalog, account).is_ok())
            .unwrap_or_else(|| Catalog::empty(account));
        let current_generation = current.generation;
        let mut current_records = current
            .records
            .into_iter()
            .map(|record| (record.record_id, record))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut current_tombstones = current
            .pruned_revisions
            .into_iter()
            .map(|pruned| (pruned.record_id, pruned.service_revision))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut reconciled = Catalog::empty(account);
        for candidate in &refreshed.records {
            if (current_generation != refreshed.generation
                && !baseline_revisions.contains(&(candidate.record_id, candidate.service_revision))
                && !current_records.contains_key(&candidate.record_id)
                && !current_tombstones
                    .get(&candidate.record_id)
                    .is_some_and(|revision| *revision < candidate.service_revision))
                || baseline_pruned_revisions
                    .iter()
                    .any(|(record_id, revision)| {
                        *record_id == candidate.record_id && *revision >= candidate.service_revision
                    })
                || current_tombstones
                    .get(&candidate.record_id)
                    .is_some_and(|revision| *revision >= candidate.service_revision)
            {
                continue;
            }
            current_tombstones.remove(&candidate.record_id);
            let current = current_records.remove(&candidate.record_id);
            let selected = match current {
                Some(current) if current.service_revision > candidate.service_revision => current,
                Some(current)
                    if baseline_revisions
                        .contains(&(candidate.record_id, candidate.service_revision))
                        && current.service_revision != candidate.service_revision =>
                {
                    continue;
                }
                None if baseline_revisions
                    .contains(&(candidate.record_id, candidate.service_revision)) =>
                {
                    continue;
                }
                _ => candidate.clone(),
            };
            reconciled.records.push(selected);
        }
        reconciled
            .records
            .extend(current_records.into_values().filter(|record| {
                !baseline_revisions.contains(&(record.record_id, record.service_revision))
            }));
        let refreshed_revisions = refreshed
            .records
            .iter()
            .map(|record| (record.record_id, record.service_revision))
            .collect::<std::collections::BTreeMap<_, _>>();
        reconciled.pruned_revisions.extend(
            current_tombstones
                .into_iter()
                .filter(|(record_id, revision)| {
                    !baseline_pruned_revisions.contains(&(*record_id, *revision))
                        || refreshed_revisions
                            .get(record_id)
                            .is_some_and(|refreshed_revision| refreshed_revision <= revision)
                })
                .map(|(record_id, service_revision)| PrunedRevision {
                    record_id,
                    service_revision,
                }),
        );
        reconciled.records.sort_by_key(|record| record.record_id);
        reconciled
            .pruned_revisions
            .sort_by_key(|pruned| pruned.record_id);
        reconciled.generation = current_generation
            .checked_add(1)
            .context("sync catalog generation exhausted")?;
        validate(&reconciled, account)?;
        let encoded = serde_json::to_vec(&reconciled).context("could not encode sync catalog")?;
        ensure!(
            encoded.len() <= MAX_CATALOG_BYTES,
            "sync catalog exceeds local limit"
        );
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

pub(super) fn remove_if_revision(
    state_dir: &Path,
    account: &AccountCredentials,
    record_id: RecordId,
    service_revision: u64,
) -> Result<bool> {
    with_exclusive_lock(state_dir, CATALOG_LOCK, |directory| {
        let Some(encoded) = directory.read_optional_bounded(CATALOG_FILE, MAX_CATALOG_BYTES)?
        else {
            return Ok(false);
        };
        let mut catalog: Catalog =
            serde_json::from_slice(&encoded).context("invalid sync catalog")?;
        validate(&catalog, account)?;
        let previous_len = catalog.records.len();
        catalog.records.retain(|record| {
            record.record_id != record_id || record.service_revision != service_revision
        });
        if catalog.records.len() == previous_len {
            return Ok(false);
        }
        match catalog
            .pruned_revisions
            .iter_mut()
            .find(|pruned| pruned.record_id == record_id)
        {
            Some(pruned) => pruned.service_revision = pruned.service_revision.max(service_revision),
            None => catalog.pruned_revisions.push(PrunedRevision {
                record_id,
                service_revision,
            }),
        }
        catalog
            .pruned_revisions
            .sort_by_key(|pruned| pruned.record_id);
        catalog.generation = catalog
            .generation
            .checked_add(1)
            .context("sync catalog generation exhausted")?;
        validate(&catalog, account)?;
        let encoded = serde_json::to_vec(&catalog).context("could not encode sync catalog")?;
        ensure!(
            encoded.len() <= MAX_CATALOG_BYTES,
            "sync catalog exceeds local limit"
        );
        directory.atomic_replace(CATALOG_FILE, &encoded)?;
        Ok(true)
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
        .filter(|record| now < record.expires_at && !suppress(record))
        .flat_map(|record| {
            let target_host = record.host_label.clone();
            record.sessions.iter().map(move |session| SyncedSession {
                target: format!("{target_host}/{session}"),
                host: record.host_label.clone(),
                session: session.clone(),
                published_at: record.published_at,
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
            Ok(active) => active,
            Err(_) => {
                registry_unavailable = true;
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
        record_id: record.record_id,
        service_revision: record.service_revision,
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
    ensure!(
        catalog.pruned_revisions.len() <= MAX_LIVE_RECORDS,
        "too many pruned sync records"
    );
    let mut pruned_ids = HashSet::new();
    for pruned in &catalog.pruned_revisions {
        ensure!(pruned.service_revision > 0, "invalid pruned sync revision");
        ensure!(
            pruned_ids.insert(pruned.record_id),
            "duplicate pruned sync record"
        );
    }
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
            record.published_at.is_none_or(|published_at| {
                published_at.timestamp() >= 0
                    && published_at.timestamp_subsec_nanos() == 0
                    && published_at <= record.expires_at
            }),
            "invalid session access descriptor publication time"
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

    const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";

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
            published_at: Some(timestamp(1_700_000_000)),
            expires_at: timestamp(1_800_000_000),
            endpoint_ticket,
            endpoint_identity: *secret.public().as_bytes(),
            attach_capability: [7; 32],
            herdr_version: [1, 2, 3],
            sessions: vec![session.to_owned()],
        }
    }

    #[test]
    fn failed_attachment_removes_only_the_selected_catalog_revision() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        let selected = record(0x51, "office", "work");
        let record_id = selected.record_id;
        catalog.records.push(selected);
        save(&state_dir, &account, &catalog).unwrap();

        assert!(remove_if_revision(&state_dir, &account, record_id, 1).unwrap());
        assert!(
            attachment(
                &state_dir,
                &account,
                "office",
                "work",
                timestamp(1_700_000_000)
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn republished_revision_survives_an_older_attachment_failure() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        let mut republished = record(0x52, "office", "work");
        let record_id = republished.record_id;
        republished.service_revision = 2;
        catalog.records.push(republished);
        save(&state_dir, &account, &catalog).unwrap();

        assert!(!remove_if_revision(&state_dir, &account, record_id, 1).unwrap());
        assert!(
            attachment(
                &state_dir,
                &account,
                "office",
                "work",
                timestamp(1_700_000_000)
            )
            .unwrap()
            .is_some(),
            "a newer publisher revision was removed by an older failed attachment"
        );
    }

    #[test]
    fn refresh_save_does_not_resurrect_a_concurrently_pruned_revision() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut baseline = Catalog::empty(&account);
        let selected = record(0x53, "office", "work");
        let record_id = selected.record_id;
        baseline.records.push(selected);
        save(&state_dir, &account, &baseline).unwrap();

        assert!(remove_if_revision(&state_dir, &account, record_id, 1).unwrap());
        let baseline_revisions = HashSet::from([(record_id, 1)]);
        save_refresh(
            &state_dir,
            &account,
            &baseline_revisions,
            &HashSet::new(),
            &baseline,
        )
        .unwrap();

        assert!(
            attachment(
                &state_dir,
                &account,
                "office",
                "work",
                timestamp(1_700_000_000)
            )
            .unwrap()
            .is_none(),
            "a stale in-flight refresh resurrected a pruned revision"
        );
    }

    #[test]
    fn refresh_save_preserves_a_concurrently_published_newer_revision() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut baseline = Catalog::empty(&account);
        baseline.records.push(record(0x54, "office", "work"));
        save(&state_dir, &account, &baseline).unwrap();

        let mut newer = Catalog::empty(&account);
        let mut newer_record = record(0x54, "office", "work");
        newer_record.service_revision = 2;
        newer.records.push(newer_record);
        save(&state_dir, &account, &newer).unwrap();
        let baseline_revisions = HashSet::from([(baseline.records[0].record_id, 1)]);
        save_refresh(
            &state_dir,
            &account,
            &baseline_revisions,
            &HashSet::new(),
            &baseline,
        )
        .unwrap();

        let stored = load(&state_dir, &account).unwrap();
        assert_eq!(stored.records[0].service_revision, 2);
    }

    #[test]
    fn refresh_save_preserves_a_concurrently_added_record_it_did_not_observe() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let baseline = Catalog::empty(&account);
        save(&state_dir, &account, &baseline).unwrap();
        let mut concurrent = Catalog::empty(&account);
        concurrent.records.push(record(0x56, "new-host", "work"));
        save(&state_dir, &account, &concurrent).unwrap();

        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &HashSet::new(),
            &baseline,
        )
        .unwrap();

        let stored = load(&state_dir, &account).unwrap();
        assert_eq!(stored.records.len(), 1);
        assert_eq!(
            stored.records[0].record_id,
            RecordId::from_bytes([0x56; 16])
        );
    }

    #[test]
    fn refresh_save_preserves_an_omitted_concurrent_newer_revision() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut baseline = Catalog::empty(&account);
        baseline.records.push(record(0x57, "office", "work"));
        save(&state_dir, &account, &baseline).unwrap();
        let baseline_revisions = HashSet::from([(baseline.records[0].record_id, 1)]);
        let mut newer = Catalog::empty(&account);
        let mut newer_record = record(0x57, "office", "work");
        newer_record.service_revision = 2;
        newer.records.push(newer_record);
        save(&state_dir, &account, &newer).unwrap();
        let empty_refresh = Catalog::empty(&account);

        save_refresh(
            &state_dir,
            &account,
            &baseline_revisions,
            &HashSet::new(),
            &empty_refresh,
        )
        .unwrap();

        let stored = load(&state_dir, &account).unwrap();
        assert_eq!(stored.records.len(), 1);
        assert_eq!(stored.records[0].service_revision, 2);
    }

    #[test]
    fn refresh_save_does_not_resurrect_a_new_record_pruned_after_fetch() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut fetched = Catalog::empty(&account);
        let fetched_record = record(0x58, "new-host", "work");
        let record_id = fetched_record.record_id;
        fetched.records.push(fetched_record);
        save(&state_dir, &account, &fetched).unwrap();
        assert!(remove_if_revision(&state_dir, &account, record_id, 1).unwrap());

        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &HashSet::new(),
            &fetched,
        )
        .unwrap();

        assert!(load(&state_dir, &account).unwrap().records.is_empty());
    }

    #[test]
    fn refresh_save_does_not_resurrect_a_baseline_tombstone_after_concurrent_gc() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut fetched = Catalog::empty(&account);
        let fetched_record = record(0x5a, "office", "work");
        let record_id = fetched_record.record_id;
        fetched.records.push(fetched_record);
        save(&state_dir, &account, &fetched).unwrap();
        assert!(remove_if_revision(&state_dir, &account, record_id, 1).unwrap());
        let baseline_pruned_revisions = HashSet::from([(record_id, 1)]);

        let empty_refresh = Catalog::empty(&account);
        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &baseline_pruned_revisions,
            &empty_refresh,
        )
        .unwrap();
        assert!(
            load(&state_dir, &account)
                .unwrap()
                .pruned_revisions
                .is_empty(),
            "the newer refresh did not garbage-collect the observed tombstone"
        );

        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &baseline_pruned_revisions,
            &fetched,
        )
        .unwrap();

        assert!(
            load(&state_dir, &account).unwrap().records.is_empty(),
            "an older refresh resurrected the exact revision from its baseline tombstone"
        );
    }

    #[test]
    fn tombstone_lifecycle_retains_current_collects_absent_and_accepts_newer_revision() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut revision_one = Catalog::empty(&account);
        let initial = record(0x5b, "office", "work");
        let record_id = initial.record_id;
        revision_one.records.push(initial);
        save(&state_dir, &account, &revision_one).unwrap();
        assert!(remove_if_revision(&state_dir, &account, record_id, 1).unwrap());
        let baseline_tombstones = HashSet::from([(record_id, 1)]);

        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &baseline_tombstones,
            &revision_one,
        )
        .unwrap();
        let retained = load(&state_dir, &account).unwrap();
        assert!(retained.records.is_empty());
        assert_eq!(
            retained.pruned_revision_pairs().collect::<Vec<_>>(),
            vec![(record_id, 1)]
        );

        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &baseline_tombstones,
            &Catalog::empty(&account),
        )
        .unwrap();
        assert!(
            load(&state_dir, &account)
                .unwrap()
                .pruned_revisions
                .is_empty()
        );

        save(&state_dir, &account, &revision_one).unwrap();
        assert!(remove_if_revision(&state_dir, &account, record_id, 1).unwrap());
        let mut revision_two = load(&state_dir, &account).unwrap();
        let mut newer = record(0x5b, "office", "work");
        newer.service_revision = 2;
        revision_two.records.push(newer);
        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &baseline_tombstones,
            &revision_two,
        )
        .unwrap();
        let superseded = load(&state_dir, &account).unwrap();
        assert_eq!(superseded.records.len(), 1);
        assert_eq!(superseded.records[0].service_revision, 2);
        assert!(superseded.pruned_revisions.is_empty());
    }

    #[test]
    fn legacy_catalog_without_pruned_revisions_loads_with_empty_tombstones() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        catalog.records.push(record(0x5c, "legacy", "work"));
        let mut legacy = serde_json::to_value(&catalog).unwrap();
        legacy.as_object_mut().unwrap().remove("generation");
        legacy.as_object_mut().unwrap().remove("pruned_revisions");

        let encoded = serde_json::to_vec(&legacy).unwrap();
        let decoded: Catalog = serde_json::from_slice(&encoded).unwrap();

        validate(&decoded, &account).unwrap();
        assert_eq!(decoded.records.len(), 1);
        assert!(decoded.pruned_revisions.is_empty());
    }

    #[test]
    fn in_flight_newer_revision_survives_concurrent_pruning_of_older_revision() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut revision_one = Catalog::empty(&account);
        let initial = record(0x5e, "office", "work");
        let record_id = initial.record_id;
        revision_one.records.push(initial);
        save(&state_dir, &account, &revision_one).unwrap();

        let mut fetched_revision_two = load(&state_dir, &account).unwrap();
        fetched_revision_two.records[0].service_revision = 2;
        let baseline_revisions = HashSet::from([(record_id, 1)]);
        assert!(remove_if_revision(&state_dir, &account, record_id, 1).unwrap());

        save_refresh(
            &state_dir,
            &account,
            &baseline_revisions,
            &HashSet::new(),
            &fetched_revision_two,
        )
        .unwrap();

        let stored = load(&state_dir, &account).unwrap();
        assert_eq!(stored.records.len(), 1);
        assert_eq!(stored.records[0].service_revision, 2);
        assert!(stored.pruned_revisions.is_empty());
    }

    #[test]
    fn stale_empty_baseline_refresh_cannot_resurrect_a_pruned_and_collected_revision() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut fetched = Catalog::empty(&account);
        let fetched_record = record(0x5d, "office", "work");
        let record_id = fetched_record.record_id;
        fetched.records.push(fetched_record);

        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &HashSet::new(),
            &fetched,
        )
        .unwrap();
        assert!(remove_if_revision(&state_dir, &account, record_id, 1).unwrap());
        let observed_tombstones = HashSet::from([(record_id, 1)]);
        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &observed_tombstones,
            &Catalog::empty(&account),
        )
        .unwrap();
        assert!(
            load(&state_dir, &account)
                .unwrap()
                .pruned_revisions
                .is_empty()
        );

        save_refresh(
            &state_dir,
            &account,
            &HashSet::new(),
            &HashSet::new(),
            &fetched,
        )
        .unwrap();

        assert!(
            load(&state_dir, &account).unwrap().records.is_empty(),
            "a refresh with an empty stale baseline resurrected a pruned revision"
        );
    }

    #[test]
    fn refresh_save_does_not_resurrect_a_new_revision_pruned_after_fetch() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut baseline = Catalog::empty(&account);
        baseline.records.push(record(0x59, "office", "work"));
        let baseline_revisions = HashSet::from([(baseline.records[0].record_id, 1)]);
        save(&state_dir, &account, &baseline).unwrap();
        let mut fetched = Catalog::empty(&account);
        let mut fetched_record = record(0x59, "office", "work");
        fetched_record.service_revision = 2;
        let record_id = fetched_record.record_id;
        fetched.records.push(fetched_record);
        save(&state_dir, &account, &fetched).unwrap();
        assert!(remove_if_revision(&state_dir, &account, record_id, 2).unwrap());

        save_refresh(
            &state_dir,
            &account,
            &baseline_revisions,
            &HashSet::new(),
            &fetched,
        )
        .unwrap();

        assert!(load(&state_dir, &account).unwrap().records.is_empty());
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

        let listed = sessions_excluding_local_endpoints(
            &state_dir,
            &account,
            timestamp(1_700_000_000),
            &registry_dir,
        )
        .unwrap();

        assert!(
            listed.sessions.is_empty(),
            "locally served session was listed twice"
        );
        assert!(!listed.registry_unavailable);
    }

    #[test]
    fn legacy_catalog_without_publication_time_remains_readable() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        catalog.records.push(record(0x25, "legacy", "work"));
        save(&state_dir, &account, &catalog).unwrap();
        let catalog_path = state_dir.join(CATALOG_FILE);
        let encoded = std::fs::read(&catalog_path).unwrap();
        let mut encoded: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        encoded["records"][0]
            .as_object_mut()
            .unwrap()
            .remove("published_at");
        std::fs::write(&catalog_path, serde_json::to_vec(&encoded).unwrap()).unwrap();

        let legacy = load(&state_dir, &account).unwrap();
        assert_eq!(legacy.records[0].published_at, None);
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

        let listed = sessions_excluding_local_endpoints(
            &state_dir,
            &account,
            timestamp(1_700_000_000),
            &registry_dir,
        )
        .unwrap();

        assert_eq!(
            listed.sessions.len(),
            1,
            "registry error hid a remote session"
        );
        assert!(listed.registry_unavailable);
    }
}
