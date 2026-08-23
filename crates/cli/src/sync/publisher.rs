use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use attached_session_sync_protocol::{
    account::{ApiKeyScope, RecordId},
    api::Envelope as ApiEnvelope,
    canonical::{HerdrVersion as SessionAccessHerdrVersion, SessionAccessDescriptor},
    crypto::seal_session_access_descriptor,
    limits::validate_host_label,
};
use attached_tunnel_protocol::{CapabilitySecret, HerdrVersion};
use iroh::EndpointAddr;
use iroh_tickets::endpoint::EndpointTicket;
use sha2::{Digest as _, Sha256};

use super::{http::SyncHttpClient, state, state::AccountCredentials};

const RECORD_ID_DOMAIN: &[u8] = b"herdr/session-record/v1";
const SESSION_ACCESS_DESCRIPTOR_LIFETIME: Duration = Duration::from_secs(300);
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    Unchanged,
    Published { revision: u64 },
}

pub struct Publisher {
    account: AccountCredentials,
    record_id: RecordId,
    last_input_digest: Option<[u8; 32]>,
    next_refresh_at: Option<Instant>,
}

impl Publisher {
    pub fn load(state_dir: &std::path::Path, endpoint_identity: [u8; 32]) -> Result<Self> {
        let account = state::load_account(state_dir, ApiKeyScope::Publish)?;
        let record_id = derive_record_id(account.account_id().as_bytes(), &endpoint_identity);
        Ok(Self {
            account,
            record_id,
            last_input_digest: None,
            next_refresh_at: None,
        })
    }

    pub async fn publish_snapshot(
        &mut self,
        host_label: &str,
        endpoint: EndpointAddr,
        attach_capability: &CapabilitySecret,
        herdr_version: HerdrVersion,
        mut sessions: Vec<String>,
    ) -> Result<PublishOutcome> {
        ensure!(
            validate_host_label(host_label),
            "sync host label is invalid"
        );
        sessions.sort();
        sessions.dedup();
        let now = super::utc_now_seconds();
        let endpoint_ticket = EndpointTicket::from(endpoint).to_string();
        let input_digest = snapshot_digest(
            host_label,
            &endpoint_ticket,
            attach_capability,
            herdr_version,
            &sessions,
        );
        if self.last_input_digest == Some(input_digest)
            && self
                .next_refresh_at
                .is_some_and(|deadline| Instant::now() < deadline)
        {
            return Ok(PublishOutcome::Unchanged);
        }

        let expires_at = now + SESSION_ACCESS_DESCRIPTOR_LIFETIME;
        let next_refresh_at = Instant::now() + REPUBLISH_INTERVAL;
        let descriptor_version = SessionAccessHerdrVersion::new(
            u16::try_from(herdr_version.major())
                .context("Herdr major version exceeds session access descriptor")?,
            u16::try_from(herdr_version.minor())
                .context("Herdr minor version exceeds session access descriptor")?,
            u16::try_from(herdr_version.patch())
                .context("Herdr patch version exceeds session access descriptor")?,
        );
        let descriptor = SessionAccessDescriptor::new(
            host_label.to_owned(),
            now,
            expires_at,
            endpoint_ticket,
            attach_capability.clone(),
            descriptor_version,
            sessions,
        )
        .context("could not build session access descriptor")?;
        let envelope = seal_session_access_descriptor(
            &descriptor,
            self.account.account_root_key(),
            self.account.account_id().as_bytes(),
            self.record_id.as_bytes(),
        )
        .context("could not encrypt session access descriptor")?;
        let (nonce, ciphertext) = envelope.into_parts();
        let envelope = ApiEnvelope::new(nonce, ciphertext).map_err(|_| {
            anyhow::anyhow!("encrypted session access descriptor exceeds record limit")
        })?;
        let revision = SyncHttpClient::new()?
            .put_record(&self.account, self.record_id, &envelope)
            .await?;
        self.last_input_digest = Some(input_digest);
        self.next_refresh_at = Some(next_refresh_at);
        Ok(PublishOutcome::Published { revision })
    }
}

pub fn default_host_label(endpoint: &EndpointAddr) -> String {
    let id = endpoint.id.to_string();
    format!("host-{}", &id[..id.len().min(12)])
}

pub fn derive_record_id(account_id: &[u8; 16], endpoint_identity: &[u8; 32]) -> RecordId {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(RECORD_ID_DOMAIN)
        .chain_update(account_id)
        .chain_update(endpoint_identity)
        .finalize()
        .into();
    let mut record_id = [0_u8; 16];
    record_id.copy_from_slice(&digest[..16]);
    RecordId::from_bytes(record_id)
}

fn snapshot_digest(
    host_label: &str,
    endpoint_ticket: &str,
    attach_capability: &CapabilitySecret,
    version: HerdrVersion,
    sessions: &[String],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"herdr/session-sync/publisher-input/v2\0");
    digest.update((host_label.len() as u32).to_be_bytes());
    digest.update(host_label.as_bytes());
    digest.update((endpoint_ticket.len() as u32).to_be_bytes());
    digest.update(endpoint_ticket.as_bytes());
    digest.update(attach_capability.to_bytes().as_ref());
    digest.update(version.major().to_be_bytes());
    digest.update(version.minor().to_be_bytes());
    digest.update(version.patch().to_be_bytes());
    for session in sessions {
        digest.update((session.len() as u32).to_be_bytes());
        digest.update(session.as_bytes());
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_id_is_deterministic_and_bound_to_account_and_endpoint() {
        let first = derive_record_id(&[1; 16], &[2; 32]);
        assert_eq!(first.encode(), "bj-IPD__4nSbRhdl8nKC-w");
        assert_eq!(first, derive_record_id(&[1; 16], &[2; 32]));
        assert_ne!(first, derive_record_id(&[3; 16], &[2; 32]));
        assert_ne!(first, derive_record_id(&[1; 16], &[4; 32]));
    }

    #[test]
    fn host_label_changes_affect_publication_memoization() {
        let endpoint = "endpoint-ticket";
        let capability = CapabilitySecret::from_bytes([7; 32]);
        let version = HerdrVersion::new(1, 2, 3);
        let sessions = vec!["work".to_owned()];
        assert_ne!(
            snapshot_digest("office", endpoint, &capability, version, &sessions),
            snapshot_digest("renamed", endpoint, &capability, version, &sessions)
        );
    }

    #[test]
    fn obsolete_signing_and_publisher_files_are_ignored_and_retained() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::test_support::canonical_tempdir();
        let owner_dir = root.path().join("owner");
        let host_dir = root.path().join("host");
        state::test_support::create_account(&owner_dir, "https://sync.example").unwrap();
        let bundle = state::export_account(&owner_dir, ApiKeyScope::Publish).unwrap();
        state::import_account(&host_dir, bundle.as_bytes()).unwrap();
        for name in ["sync-host-signing.key", "sync-publisher.json"] {
            let path = host_dir.join(name);
            std::fs::write(&path, b"obsolete synthetic fixture").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let publisher = Publisher::load(&host_dir, [2; 32]).expect("publisher ignores old files");
        assert_eq!(
            publisher.record_id,
            derive_record_id(publisher.account.account_id().as_bytes(), &[2; 32])
        );
        assert!(host_dir.join("sync-host-signing.key").exists());
        assert!(host_dir.join("sync-publisher.json").exists());
        assert!(!host_dir.join("sync-host-signing.lock").exists());
        assert!(!host_dir.join("sync-publisher.lock").exists());
    }
}
