use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use attached_session_sync_protocol::account::{
    AccountBundle, ApiKeyScope, ConsumerIdentitySecret, ServiceOrigin,
};

use super::{http::SyncHttpClient, state};

pub async fn create(state_dir: &Path, service_origin: &str) -> Result<()> {
    let service_origin = ServiceOrigin::parse(service_origin)
        .map_err(|_| anyhow::anyhow!("invalid sync service origin"))?;
    state::ensure_account_slot_available(state_dir)?;
    let consumer_identity = iroh::SecretKey::generate();
    let response = SyncHttpClient::new()?
        .create_account(&service_origin)
        .await?;
    state::install_created_account(
        state_dir,
        service_origin,
        response,
        ConsumerIdentitySecret::from_bytes(consumer_identity.to_bytes()),
    )
    .context(
        "the service created the account, but its credentials could not be saved locally; create another account",
    )
}

pub fn install_publish(state_dir: &Path, encoded: &[u8]) -> Result<()> {
    let bundle =
        AccountBundle::parse(encoded).map_err(|_| anyhow::anyhow!("invalid account bundle"))?;
    ensure!(
        matches!(
            &bundle,
            AccountBundle::Scoped(bundle) if bundle.api_key_scope() == ApiKeyScope::Publish
        ),
        "a publish-only account bundle is required"
    );
    state::import_account(state_dir, encoded)
}

pub fn export(state_dir: &Path, scope: ApiKeyScope) -> Result<String> {
    state::export_account(state_dir, scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_installation_rejects_download_credentials_without_poisoning_state() {
        let root = crate::test_support::canonical_tempdir();
        let owner = root.path().join("owner");
        state::test_support::create_account(&owner, "https://sync.example").unwrap();
        let download = state::export_account(&owner, ApiKeyScope::Download).unwrap();
        let host = root.path().join("host");
        crate::secure_state::prepare_private_dir(&host).unwrap();

        let error = install_publish(&host, download.as_bytes())
            .unwrap_err()
            .to_string();

        assert!(error.contains("publish-only"), "{error}");
        assert!(
            state::load_account_optional(&host, ApiKeyScope::Publish)
                .unwrap()
                .is_none()
        );
    }
}
