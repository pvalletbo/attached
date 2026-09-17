use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, ensure};
use attached_session_sync_protocol::{
    account::{ApiKeyScope, RecordId},
    api::Envelope as ApiEnvelope,
    canonical::{AttachedVersion, HostAccessDescriptor},
    crypto::seal_host_access_descriptor,
    limits::validate_host_label,
};
use attached_tunnel_protocol::CapabilitySecret;
use iroh::EndpointAddr;
use iroh_tickets::endpoint::EndpointTicket;
use sha2::{Digest as _, Sha256};

use super::{http::SyncHttpClient, state, state::AccountCredentials};

// Keep the established record namespace: publishing host-only data must replace
// this endpoint's old record rather than consume a second slot on the backend.
const RECORD_ID_DOMAIN: &[u8] = b"herdr/session-record/v1";
// Two retry opportunities before a stopped publisher disappears from discovery.
const DESCRIPTOR_LIFETIME: Duration = Duration::from_secs(90);
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishOutcome {
    Unchanged,
    Published { revision: u64 },
}

pub struct Publisher {
    account: AccountCredentials,
    state_dir: PathBuf,
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
            state_dir: state_dir.to_owned(),
            record_id,
            last_input_digest: None,
            next_refresh_at: None,
        })
    }

    pub async fn publish_snapshot(
        &mut self,
        host_label: &str,
        endpoint: EndpointAddr,
        capability: &CapabilitySecret,
    ) -> Result<PublishOutcome> {
        ensure!(
            validate_host_label(host_label),
            "sync host label is invalid"
        );
        let consumer = self
            .account
            .authorized_consumer_identity()
            .context("publish account has no authorized consumer")?;
        let ssh_enabled = crate::ssh::access_enabled(&self.state_dir, consumer.as_bytes());
        let now = super::utc_now_seconds();
        let endpoint_ticket = EndpointTicket::from(endpoint).to_string();
        let version = current_attached_version()?;
        let input_digest = snapshot_digest(
            host_label,
            &endpoint_ticket,
            capability,
            version,
            ssh_enabled,
        );
        if self.last_input_digest == Some(input_digest)
            && self
                .next_refresh_at
                .is_some_and(|deadline| Instant::now() < deadline)
        {
            return Ok(PublishOutcome::Unchanged);
        }
        // Measure from the start of publication, not after the HTTP response:
        // otherwise the next periodic tick could skip renewal by a few milliseconds.
        let next_refresh_at = Instant::now() + REPUBLISH_INTERVAL;
        let descriptor = HostAccessDescriptor::new(
            host_label.to_owned(),
            now,
            now + DESCRIPTOR_LIFETIME,
            endpoint_ticket,
            capability.clone(),
            version,
            ssh_enabled,
        )
        .context("could not build host access descriptor")?;
        let envelope = seal_host_access_descriptor(
            &descriptor,
            self.account.account_root_key(),
            self.account.account_id().as_bytes(),
            self.record_id.as_bytes(),
        )
        .context("could not encrypt host access descriptor")?;
        let (nonce, ciphertext) = envelope.into_parts();
        let envelope = ApiEnvelope::new(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("encrypted host descriptor exceeds record limit"))?;
        let revision = SyncHttpClient::new()?
            .put_record(&self.account, self.record_id, &envelope)
            .await?;
        self.last_input_digest = Some(input_digest);
        self.next_refresh_at = Some(next_refresh_at);
        Ok(PublishOutcome::Published { revision })
    }
}

fn current_attached_version() -> Result<AttachedVersion> {
    let version = crate::attached_version::current();
    let component = |value, name| {
        u16::try_from(value)
            .with_context(|| format!("Attached {name} version exceeds sync protocol"))
    };
    Ok(AttachedVersion::new(
        component(version.major(), "major")?,
        component(version.minor(), "minor")?,
        component(version.patch(), "patch")?,
    ))
}

pub fn default_host_label(endpoint: &EndpointAddr) -> String {
    let id = endpoint.id.to_string();
    format!("host-{}", &id[..id.len().min(12)])
}

pub fn derive_record_id(account_id: &[u8; 16], endpoint_identity: &[u8; 32]) -> RecordId {
    let digest = Sha256::new()
        .chain_update(RECORD_ID_DOMAIN)
        .chain_update(account_id)
        .chain_update(endpoint_identity)
        .finalize();
    let mut record_id = [0; 16];
    record_id.copy_from_slice(&digest[..16]);
    RecordId::from_bytes(record_id)
}

fn snapshot_digest(
    host: &str,
    ticket: &str,
    capability: &CapabilitySecret,
    version: AttachedVersion,
    ssh_enabled: bool,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"attached/host-sync/publisher-input/v1\0");
    for field in [host, ticket] {
        digest.update((field.len() as u32).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.update(capability.to_bytes());
    digest.update(version.major.to_be_bytes());
    digest.update(version.minor.to_be_bytes());
    digest.update(version.patch.to_be_bytes());
    digest.update([u8::from(ssh_enabled)]);
    digest.finalize().into()
}

#[cfg(test)]
#[path = "publisher_tests.rs"]
mod integration_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopped_hosts_expire_and_record_ids_are_account_and_endpoint_bound() {
        assert!(DESCRIPTOR_LIFETIME <= Duration::from_secs(90));
        assert_eq!(
            derive_record_id(&[1; 16], &[2; 32]).encode(),
            "bj-IPD__4nSbRhdl8nKC-w"
        );
        assert!(REPUBLISH_INTERVAL * 3 <= DESCRIPTOR_LIFETIME);
        assert_eq!(
            derive_record_id(&[1; 16], &[2; 32]),
            derive_record_id(&[1; 16], &[2; 32])
        );
        assert_ne!(
            derive_record_id(&[1; 16], &[2; 32]),
            derive_record_id(&[3; 16], &[2; 32])
        );
        assert_ne!(
            derive_record_id(&[1; 16], &[2; 32]),
            derive_record_id(&[1; 16], &[3; 32])
        );
    }

    #[test]
    fn all_connection_metadata_and_consent_invalidate_publication_memoization() {
        let key = CapabilitySecret::from_bytes([7; 32]);
        let version = AttachedVersion::new(1, 2, 3);
        let original = snapshot_digest("office", "ticket", &key, version, true);
        for digest in [
            snapshot_digest("renamed", "ticket", &key, version, true),
            snapshot_digest("office", "new-ticket", &key, version, true),
            snapshot_digest(
                "office",
                "ticket",
                &CapabilitySecret::from_bytes([8; 32]),
                version,
                true,
            ),
            snapshot_digest(
                "office",
                "ticket",
                &key,
                AttachedVersion::new(1, 2, 4),
                true,
            ),
            snapshot_digest("office", "ticket", &key, version, false),
        ] {
            assert_ne!(original, digest);
        }
        assert!(current_attached_version().is_ok());
    }
}
