use std::{collections::HashSet, path::Path, str::FromStr as _};

use anyhow::{Context as _, Result, ensure};
use attached_session_sync_protocol::{
    account::{AccountId, RecordId},
    crypto::OpenedHostAccessDescriptor,
    limits::{MAX_ENDPOINT_TICKET_BYTES, MAX_LIVE_RECORDS, validate_host_label},
};
use chrono::{DateTime, Utc};
use iroh_tickets::endpoint::EndpointTicket;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    local_encryption::{
        MasterKeyStore, Purpose, active_store, has_envelope_shape, is_envelope, open, seal,
        stored_limit, with_master_key, with_master_key_store,
    },
    secure_state::{StateDir, with_exclusive_lock, with_locked_existing},
};

use super::state::AccountCredentials;

const CATALOG_FILE: &str = "host-catalog.json";
const CATALOG_LOCK: &str = "host-catalog.lock";
const MAX_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_STORED_CATALOG_BYTES: usize = stored_limit(MAX_CATALOG_BYTES);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncedHost {
    pub target: String,
    pub host: String,
    pub attached_version: [u16; 3],
    pub published_at: Option<DateTime<Utc>>,
}

pub(super) struct HostListing {
    pub(super) hosts: Vec<SyncedHost>,
    pub(super) registry_unavailable: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HostConnection {
    pub(crate) record_id: RecordId,
    pub(crate) service_revision: u64,
    pub endpoint_ticket: String,
    pub endpoint_identity: [u8; 32],
    pub attach_capability: [u8; 32],
    pub attached_version: [u16; 3],
    pub expires_at: DateTime<Utc>,
    pub ssh_enabled: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Catalog {
    account_id: AccountId,
    service_origin: String,
    #[serde(default)]
    generation: u64,
    pub(super) records: Vec<CatalogRecord>,
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
    attached_version: [u16; 3],
    ssh_enabled: bool,
}

impl Catalog {
    pub(super) fn empty(account: &AccountCredentials) -> Self {
        Self {
            account_id: account.account_id(),
            service_origin: account.service_origin().to_owned(),
            generation: 0,
            records: Vec::new(),
        }
    }
}

impl CatalogRecord {
    pub(super) fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    pub(super) fn ssh_attachment(&self) -> HostConnection {
        HostConnection {
            record_id: self.record_id,
            service_revision: self.service_revision,
            endpoint_ticket: self.endpoint_ticket.clone(),
            endpoint_identity: self.endpoint_identity,
            attach_capability: self.attach_capability,
            attached_version: self.attached_version,
            ssh_enabled: self.ssh_enabled,
            expires_at: self.expires_at,
        }
    }

    pub(super) fn from_opened(
        record_id: RecordId,
        service_revision: u64,
        opened: &OpenedHostAccessDescriptor,
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
            attached_version: [
                descriptor.attached_version().major,
                descriptor.attached_version().minor,
                descriptor.attached_version().patch,
            ],
            ssh_enabled: descriptor.ssh_enabled(),
        }
    }
}

/// Resolve a published machine by label or stable identity.
/// Stable endpoint IDs are accepted; ambiguous human labels fail closed.
pub(crate) fn host(
    state_dir: &Path,
    account: &AccountCredentials,
    target: &str,
    now: DateTime<Utc>,
) -> Result<HostConnection> {
    let catalog = load(state_dir, account)?;
    // An explicit endpoint identity must never fall back to a mutable label.
    // Otherwise another publisher can name itself after an absent/expired host's
    // ID and bypass the caller's identity selection (and its existing host pin).
    let target_identity = target.parse::<iroh::EndpointId>().ok();
    let mut matches = catalog.records.iter().filter(|record| {
        !record.is_expired_at(now)
            && match target_identity {
                Some(identity) => &record.endpoint_identity == identity.as_bytes(),
                None => record.host_label == target,
            }
    });
    let record = matches
        .next()
        .context("SSH publisher not found; use its host label or stable endpoint ID")?;
    ensure!(
        matches.next().is_none(),
        "ambiguous publisher label; use its stable endpoint ID"
    );
    Ok(record.ssh_attachment())
}

#[tracing::instrument(name = "load_sync_catalog", level = "debug", skip_all)]
pub(super) fn load(state_dir: &Path, account: &AccountCredentials) -> Result<Catalog> {
    with_locked_existing(state_dir, CATALOG_LOCK, |directory| {
        Ok(read_catalog(directory, account, true)?.unwrap_or_else(|| Catalog::empty(account)))
    })
}

#[cfg(test)]
pub(super) fn save(
    state_dir: &Path,
    account: &AccountCredentials,
    catalog: &Catalog,
) -> Result<()> {
    validate(catalog, account)?;
    with_exclusive_lock(state_dir, CATALOG_LOCK, |directory| {
        let current = read_catalog(directory, account, false)?;
        let current_generation = current.as_ref().map_or(0, |catalog| catalog.generation);
        let mut next = catalog.clone();
        next.generation = current_generation
            .checked_add(1)
            .context("sync catalog generation exhausted")?;
        write_catalog(directory, &next, current.is_some())
    })
}

#[tracing::instrument(name = "save_sync_catalog", level = "debug", skip_all)]
pub(super) fn save_refresh(
    state_dir: &Path,
    account: &AccountCredentials,
    baseline_revisions: &HashSet<(RecordId, u64)>,
    refreshed: &Catalog,
) -> Result<()> {
    validate(refreshed, account)?;
    with_exclusive_lock(state_dir, CATALOG_LOCK, |directory| {
        let (current, existed) = match read_catalog(directory, account, false) {
            Ok(current) => {
                let existed = current.is_some();
                (current, existed)
            }
            Err(_) if has_corrupt_legacy_catalog(directory)? => (None, true),
            Err(error) => return Err(error),
        };
        let current = current.unwrap_or_else(|| Catalog::empty(account));
        let current_generation = current.generation;
        let mut current_records = current
            .records
            .into_iter()
            .map(|record| (record.record_id, record))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut reconciled = Catalog::empty(account);
        for candidate in &refreshed.records {
            // A newer completed refresh may have removed this record. Do not
            // resurrect it from an older in-flight index observation.
            if current_generation != refreshed.generation
                && !current_records.contains_key(&candidate.record_id)
            {
                continue;
            }
            let selected = match current_records.remove(&candidate.record_id) {
                Some(current) if current.service_revision > candidate.service_revision => current,
                _ => candidate.clone(),
            };
            reconciled.records.push(selected);
        }
        reconciled
            .records
            .extend(current_records.into_values().filter(|record| {
                !baseline_revisions.contains(&(record.record_id, record.service_revision))
            }));
        reconciled.records.sort_by_key(|record| record.record_id);
        reconciled.generation = current_generation
            .checked_add(1)
            .context("sync catalog generation exhausted")?;
        validate(&reconciled, account)?;
        write_catalog(directory, &reconciled, existed)
    })
}

fn has_corrupt_legacy_catalog(directory: &StateDir) -> Result<bool> {
    let Some(stored) =
        directory.read_secret_optional_bounded(CATALOG_FILE, MAX_STORED_CATALOG_BYTES)?
    else {
        return Ok(false);
    };
    Ok(!has_envelope_shape(&stored) && serde_json::from_slice::<Catalog>(&stored).is_err())
}

fn read_catalog(
    directory: &StateDir,
    account: &AccountCredentials,
    migrate_legacy: bool,
) -> Result<Option<Catalog>> {
    read_catalog_with_store(directory, account, migrate_legacy, active_store())
}

#[tracing::instrument(name = "read_sync_catalog", level = "debug", skip_all)]
fn read_catalog_with_store(
    directory: &StateDir,
    account: &AccountCredentials,
    migrate_legacy: bool,
    store: &dyn MasterKeyStore,
) -> Result<Option<Catalog>> {
    let Some(stored) =
        directory.read_secret_optional_bounded(CATALOG_FILE, MAX_STORED_CATALOG_BYTES)?
    else {
        return Ok(None);
    };
    let legacy = !is_envelope(&stored);
    let plaintext = if !legacy {
        with_master_key_store(directory, store, false, |key| {
            open(key, Purpose::SyncCatalog, &stored, MAX_CATALOG_BYTES)
        })?
    } else {
        stored
    };
    let catalog: Catalog = serde_json::from_slice(&plaintext).context("invalid sync catalog")?;
    validate(&catalog, account)?;
    if migrate_legacy && legacy {
        with_master_key_store(directory, store, true, |key| {
            let encrypted = seal(key, Purpose::SyncCatalog, &plaintext, MAX_CATALOG_BYTES)?;
            directory.atomic_replace(CATALOG_FILE, &encrypted)
        })?;
        tracing::info!(
            event = "local_secret_migrated",
            purpose = Purpose::SyncCatalog.name(),
            "migrated legacy local secret to encrypted storage"
        );
    }
    Ok(Some(catalog))
}

#[tracing::instrument(name = "write_sync_catalog", level = "debug", skip_all)]
fn write_catalog(directory: &StateDir, catalog: &Catalog, replace: bool) -> Result<()> {
    let plaintext = encode_catalog(catalog)?;
    with_master_key(directory, true, |key| {
        let encrypted = seal(key, Purpose::SyncCatalog, &plaintext, MAX_CATALOG_BYTES)?;
        if replace {
            directory.atomic_replace(CATALOG_FILE, &encrypted)
        } else if directory.create_noclobber(CATALOG_FILE, &encrypted)? {
            Ok(())
        } else {
            anyhow::bail!("sync catalog was concurrently installed")
        }
    })
}

fn encode_catalog(catalog: &Catalog) -> Result<Zeroizing<Vec<u8>>> {
    let mut encoded = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *encoded, catalog).context("could not encode sync catalog")?;
    ensure!(
        encoded.len() <= MAX_CATALOG_BYTES,
        "sync catalog exceeds local limit"
    );
    Ok(encoded)
}

/// SSH configuration exports include local publishers too: unlike the human
/// discovery listing, they must provide aliases for every advertised SSH host.
pub(super) fn all_ssh_hosts(
    state_dir: &Path,
    account: &AccountCredentials,
    now: DateTime<Utc>,
) -> Result<Vec<SyncedHost>> {
    hosts_with_filter(state_dir, account, now, |_| false)
}

fn hosts_with_filter(
    state_dir: &Path,
    account: &AccountCredentials,
    now: DateTime<Utc>,
    mut suppress: impl FnMut(&CatalogRecord) -> bool,
) -> Result<Vec<SyncedHost>> {
    let catalog = load(state_dir, account)?;
    let mut hosts = catalog
        .records
        .iter()
        .filter(|record| record.ssh_enabled && now < record.expires_at && !suppress(record))
        .map(|record| SyncedHost {
            target: iroh::EndpointId::from_bytes(&record.endpoint_identity)
                .expect("catalog validates endpoint identities")
                .to_string(),
            host: record.host_label.clone(),
            attached_version: record.attached_version,
            published_at: record.published_at,
        })
        .collect::<Vec<_>>();
    hosts.sort_by(|left, right| {
        left.host
            .cmp(&right.host)
            .then(left.target.cmp(&right.target))
    });
    Ok(hosts)
}

#[tracing::instrument(name = "list_sync_hosts", level = "debug", skip_all)]
pub(super) fn hosts_excluding_local_endpoints(
    state_dir: &Path,
    account: &AccountCredentials,
    now: DateTime<Utc>,
    registry_dir: &Path,
) -> Result<HostListing> {
    let mut registry_unavailable = false;
    let hosts = hosts_with_filter(state_dir, account, now, |record| {
        match crate::endpoint_registry::is_active(registry_dir, record.endpoint_identity) {
            Ok(active) => active,
            Err(_) => {
                registry_unavailable = true;
                false
            }
        }
    })?;
    Ok(HostListing {
        hosts,
        registry_unavailable,
    })
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
            "invalid host access descriptor expiration"
        );
        ensure!(
            record.published_at.is_none_or(|published_at| {
                published_at.timestamp() >= 0
                    && published_at.timestamp_subsec_nanos() == 0
                    && published_at <= record.expires_at
            }),
            "invalid host access descriptor publication time"
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
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use attached_session_sync_protocol::account::ApiKeyScope;

    struct FixedStore(Option<[u8; 32]>);

    impl crate::local_encryption::MasterKeyStore for FixedStore {
        fn load_or_create(
            &self,
            _directory: &StateDir,
            _create: bool,
        ) -> Result<Zeroizing<[u8; 32]>> {
            self.0.map(Zeroizing::new).context("synthetic missing key")
        }
    }

    const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";

    fn timestamp(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).expect("fixture timestamp")
    }

    fn record(identity_byte: u8, host: &str) -> CatalogRecord {
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
            attached_version: [0, 2, 0],
            ssh_enabled: true,
        }
    }

    #[test]
    fn resolves_publishers_by_host_and_rejects_ambiguous_or_expired_hosts() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        let publisher = record(0x51, "office");
        let id = iroh::EndpointId::from_bytes(&publisher.endpoint_identity)
            .unwrap()
            .to_string();
        catalog.records.push(publisher);
        save(&state_dir, &account, &catalog).unwrap();
        let now = timestamp(1_700_000_000);
        assert!(
            host(&state_dir, &account, "office", now)
                .unwrap()
                .ssh_enabled
        );
        assert!(host(&state_dir, &account, &id, now).is_ok());
        assert!(host(&state_dir, &account, "office/work", now).is_err());
        catalog.records.push(record(0x52, "office"));
        save(&state_dir, &account, &catalog).unwrap();
        assert!(host(&state_dir, &account, "office", now).is_err());
        assert!(host(&state_dir, &account, &id, now).is_ok());
        assert!(host(&state_dir, &account, &id, timestamp(1_900_000_000)).is_err());
    }

    #[test]
    fn explicit_ssh_endpoint_identity_never_matches_another_publishers_label() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        let intended = record(0x61, "office");
        let identity = iroh::EndpointId::from_bytes(&intended.endpoint_identity).unwrap();
        let target = identity.to_string();
        let other = record(0x62, &target);
        let now = timestamp(1_700_000_000);

        // A label cannot impersonate an absent endpoint, even on first use.
        catalog.records = vec![other.clone()];
        save(&state_dir, &account, &catalog).unwrap();
        assert!(host(&state_dir, &account, &target, now).is_err());

        // Nor may an expired descriptor redirect a previously pinned identity.
        let mut expired = intended.clone();
        expired.published_at = Some(now - chrono::Duration::seconds(90));
        expired.expires_at = now;
        catalog.records = vec![expired, other.clone()];
        save(&state_dir, &account, &catalog).unwrap();
        assert!(host(&state_dir, &account, &target, now).is_err());

        // When the intended endpoint is present, its identity takes precedence
        // over a colliding label; normal human-label selection still works.
        catalog.records = vec![intended, other];
        save(&state_dir, &account, &catalog).unwrap();
        for target in [&*target, "office"] {
            assert_eq!(
                host(&state_dir, &account, target, now)
                    .unwrap()
                    .endpoint_identity,
                *identity.as_bytes(),
            );
        }
    }

    #[test]
    fn catalog_serialization_uses_a_pre_zeroizing_output_buffer() {
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();

        let encoded = encode_catalog(&Catalog::empty(&account)).unwrap();

        assert_zeroizing(&encoded);
        assert!(serde_json::from_slice::<Catalog>(&encoded).is_ok());
    }

    #[test]
    fn missing_and_wrong_catalog_keys_leave_ciphertext_byte_exact() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let plaintext = encode_catalog(&Catalog::empty(&account)).unwrap();
        let envelope = seal(
            &[0x44; 32],
            Purpose::SyncCatalog,
            &plaintext,
            MAX_CATALOG_BYTES,
        )
        .unwrap();
        std::fs::write(state_dir.join(CATALOG_FILE), &envelope).unwrap();
        std::fs::set_permissions(
            state_dir.join(CATALOG_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let directory = StateDir::open(&state_dir).unwrap();

        for store in [FixedStore(None), FixedStore(Some([0x45; 32]))] {
            assert!(read_catalog_with_store(&directory, &account, true, &store).is_err());
            assert_eq!(
                std::fs::read(state_dir.join(CATALOG_FILE)).unwrap(),
                envelope.as_slice()
            );
        }
    }

    #[test]
    fn legacy_plaintext_catalog_migrates_and_preserves_records_and_capabilities() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut expected = Catalog::empty(&account);
        expected.records.push(record(0x59, "office"));
        let plaintext = serde_json::to_vec(&expected).unwrap();
        std::fs::write(state_dir.join(CATALOG_FILE), &plaintext).unwrap();
        std::fs::set_permissions(
            state_dir.join(CATALOG_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let loaded = load(&state_dir, &account).unwrap();

        assert_eq!(loaded.records.len(), 1);
        assert_eq!(loaded.records[0].record_id, expected.records[0].record_id);
        assert_eq!(
            loaded.records[0].attach_capability,
            expected.records[0].attach_capability
        );
        assert_eq!(
            loaded.records[0].ssh_enabled,
            expected.records[0].ssh_enabled
        );
        let migrated = std::fs::read(state_dir.join(CATALOG_FILE)).unwrap();
        assert!(crate::local_encryption::is_envelope(&migrated));
        assert_ne!(migrated, plaintext);
    }

    #[test]
    fn refresh_rejects_magic_corrupted_envelope_without_replacing_it() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let catalog = Catalog::empty(&account);
        save(&state_dir, &account, &catalog).unwrap();
        let path = state_dir.join(CATALOG_FILE);
        let envelope = std::fs::read(&path).unwrap();
        for offset in 0..8 {
            let mut corrupted = envelope.clone();
            corrupted[offset] = if offset == 0 {
                b'{'
            } else {
                corrupted[offset] ^ 1
            };
            std::fs::write(&path, &corrupted).unwrap();

            assert!(
                save_refresh(&state_dir, &account, &HashSet::new(), &catalog,).is_err(),
                "magic corruption at offset {offset} was accepted"
            );
            assert_eq!(std::fs::read(&path).unwrap(), corrupted);
        }

        let mut unsupported_version = envelope.clone();
        unsupported_version[8] ^= 1;
        let mut two_magic_bytes = envelope.clone();
        two_magic_bytes[0] ^= 1;
        two_magic_bytes[1] ^= 1;
        let variants = [
            ("unsupported version", unsupported_version),
            ("two corrupt magic bytes", two_magic_bytes),
            ("truncated header", envelope[..8].to_vec()),
            (
                "truncated ciphertext",
                envelope[..envelope.len() - 1].to_vec(),
            ),
        ];
        for (name, corrupted) in variants {
            std::fs::write(&path, &corrupted).unwrap();
            assert!(
                save_refresh(&state_dir, &account, &HashSet::new(), &catalog,).is_err(),
                "{name} was accepted"
            );
            assert_eq!(std::fs::read(&path).unwrap(), corrupted, "{name}");
        }
    }

    #[test]
    fn refresh_save_preserves_a_concurrently_published_newer_revision() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut baseline = Catalog::empty(&account);
        baseline.records.push(record(0x54, "office"));
        save(&state_dir, &account, &baseline).unwrap();

        let mut newer = Catalog::empty(&account);
        let mut newer_record = record(0x54, "office");
        newer_record.service_revision = 2;
        newer.records.push(newer_record);
        save(&state_dir, &account, &newer).unwrap();
        let baseline_revisions = HashSet::from([(baseline.records[0].record_id, 1)]);
        save_refresh(&state_dir, &account, &baseline_revisions, &baseline).unwrap();

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
        concurrent.records.push(record(0x56, "new-host"));
        save(&state_dir, &account, &concurrent).unwrap();

        save_refresh(&state_dir, &account, &HashSet::new(), &baseline).unwrap();

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
        baseline.records.push(record(0x57, "office"));
        save(&state_dir, &account, &baseline).unwrap();
        let baseline_revisions = HashSet::from([(baseline.records[0].record_id, 1)]);
        let mut newer = Catalog::empty(&account);
        let mut newer_record = record(0x57, "office");
        newer_record.service_revision = 2;
        newer.records.push(newer_record);
        save(&state_dir, &account, &newer).unwrap();
        let empty_refresh = Catalog::empty(&account);

        save_refresh(&state_dir, &account, &baseline_revisions, &empty_refresh).unwrap();

        let stored = load(&state_dir, &account).unwrap();
        assert_eq!(stored.records.len(), 1);
        assert_eq!(stored.records[0].service_revision, 2);
    }

    #[test]
    fn stale_refresh_cannot_resurrect_a_host_without_a_fresh_observation() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut initial = Catalog::empty(&account);
        initial.records.push(record(0x51, "office"));
        save(&state_dir, &account, &initial).unwrap();
        let stale = load(&state_dir, &account).unwrap();
        let baseline = HashSet::from([(stale.records[0].record_id, 1)]);
        // A newer completed refresh saw the publisher disappear.
        save(&state_dir, &account, &Catalog::empty(&account)).unwrap();
        save_refresh(&state_dir, &account, &baseline, &stale).unwrap();
        let mut current = load(&state_dir, &account).unwrap();
        assert!(current.records.is_empty());
        // A fresh observation can discover the host again.
        current.records.push(record(0x51, "office"));
        save_refresh(&state_dir, &account, &HashSet::new(), &current).unwrap();
        assert_eq!(load(&state_dir, &account).unwrap().records.len(), 1);
    }

    #[test]
    fn stale_refresh_cannot_restore_revoked_ssh_permission() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut initial = Catalog::empty(&account);
        initial.records.push(record(0x51, "office"));
        save(&state_dir, &account, &initial).unwrap();
        let stale = load(&state_dir, &account).unwrap();
        let baseline = HashSet::from([(stale.records[0].record_id, 1)]);
        let mut revoked = stale.clone();
        revoked.records[0].service_revision = 2;
        revoked.records[0].ssh_enabled = false;
        save(&state_dir, &account, &revoked).unwrap();
        save_refresh(&state_dir, &account, &baseline, &stale).unwrap();
        let now = timestamp(1_700_000_000);
        assert!(
            !host(&state_dir, &account, "office", now)
                .unwrap()
                .ssh_enabled
        );
        assert!(
            hosts_excluding_local_endpoints(
                &state_dir,
                &account,
                now,
                &root.path().join("registry")
            )
            .unwrap()
            .hosts
            .is_empty()
        );
    }

    #[test]
    fn active_exact_endpoint_hosts_are_suppressed() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        let registry_dir = root.path().join("registry-user/live-endpoints");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        let record = record(0x21, "office");
        let identity = record.endpoint_identity;
        catalog.records.push(record);
        save(&state_dir, &account, &catalog).unwrap();
        let _guard = crate::endpoint_registry::register(&registry_dir, identity).unwrap();

        let listed = hosts_excluding_local_endpoints(
            &state_dir,
            &account,
            timestamp(1_700_000_000),
            &registry_dir,
        )
        .unwrap();

        assert!(
            listed.hosts.is_empty(),
            "locally served session was listed twice"
        );
        assert!(!listed.registry_unavailable);
        let exported = all_ssh_hosts(&state_dir, &account, timestamp(1_700_000_000)).unwrap();
        assert_eq!(
            exported.len(),
            1,
            "SSH exports must not omit a local publisher"
        );
        assert_eq!(exported[0].host, "office");
    }

    #[test]
    fn legacy_catalog_without_publication_time_remains_readable() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        super::super::state::test_support::create_account(&state_dir, "https://sync.example")
            .unwrap();
        let account = super::super::state::load_account(&state_dir, ApiKeyScope::Download).unwrap();
        let mut catalog = Catalog::empty(&account);
        catalog.records.push(record(0x25, "legacy"));
        let catalog_path = state_dir.join(CATALOG_FILE);
        let mut encoded: serde_json::Value =
            serde_json::to_value(&catalog).expect("catalog fixture serializes");
        encoded["records"][0]
            .as_object_mut()
            .unwrap()
            .remove("published_at");
        std::fs::write(&catalog_path, serde_json::to_vec(&encoded).unwrap()).unwrap();
        std::fs::set_permissions(&catalog_path, std::fs::Permissions::from_mode(0o600)).unwrap();

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
        let local = record(0x31, "office");
        let local_identity = local.endpoint_identity;
        catalog.records.push(local);
        catalog.records.push(record(0x32, "office"));
        save(&state_dir, &account, &catalog).unwrap();
        let _guard = crate::endpoint_registry::register(&registry_dir, local_identity).unwrap();

        let listed = hosts_excluding_local_endpoints(
            &state_dir,
            &account,
            timestamp(1_700_000_000),
            &registry_dir,
        )
        .unwrap();

        assert_eq!(listed.hosts.len(), 1);
        assert_eq!(listed.hosts[0].host, "office");
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
        catalog.records.push(record(0x41, "office"));
        save(&state_dir, &account, &catalog).unwrap();
        std::fs::create_dir(&registry_dir).unwrap();
        std::fs::set_permissions(&registry_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let listed = hosts_excluding_local_endpoints(
            &state_dir,
            &account,
            timestamp(1_700_000_000),
            &registry_dir,
        )
        .unwrap();

        assert_eq!(listed.hosts.len(), 1, "registry error hid a remote session");
        assert!(listed.registry_unavailable);
    }
}
