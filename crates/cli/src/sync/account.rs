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
    install_scoped(state_dir, encoded, ApiKeyScope::Publish)
}

pub fn install_download(state_dir: &Path, encoded: &[u8]) -> Result<()> {
    install_scoped(state_dir, encoded, ApiKeyScope::Download)
}

fn install_scoped(state_dir: &Path, encoded: &[u8], required_scope: ApiKeyScope) -> Result<()> {
    let bundle =
        AccountBundle::parse(encoded).map_err(|_| anyhow::anyhow!("invalid account bundle"))?;
    ensure!(
        matches!(
            &bundle,
            AccountBundle::Scoped(bundle) if bundle.api_key_scope() == required_scope
        ),
        "a {}-only account bundle is required",
        match required_scope {
            ApiKeyScope::Publish => "publish",
            ApiKeyScope::Download => "download",
        }
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
    fn scoped_installation_rejects_the_wrong_role_without_poisoning_state() {
        let root = crate::test_support::canonical_tempdir();
        let owner = root.path().join("owner");
        state::test_support::create_account(&owner, "https://sync.example").unwrap();
        let publish = state::export_account(&owner, ApiKeyScope::Publish).unwrap();
        let download = state::export_account(&owner, ApiKeyScope::Download).unwrap();
        let publish_host = root.path().join("publish-host");
        let downloader = root.path().join("downloader");
        crate::secure_state::prepare_private_dir(&publish_host).unwrap();
        crate::secure_state::prepare_private_dir(&downloader).unwrap();

        for (state_dir, result, expected_scope) in [
            (
                &publish_host,
                install_publish(&publish_host, download.as_bytes()),
                ApiKeyScope::Publish,
            ),
            (
                &downloader,
                install_download(&downloader, publish.as_bytes()),
                ApiKeyScope::Download,
            ),
        ] {
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains(match expected_scope {
                    ApiKeyScope::Publish => "publish-only",
                    ApiKeyScope::Download => "download-only",
                }),
                "{error}"
            );
            assert!(
                state::load_account_optional(state_dir, expected_scope)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn download_installation_creates_download_only_state() {
        let root = crate::test_support::canonical_tempdir();
        let owner = root.path().join("owner");
        state::test_support::create_account(&owner, "https://sync.example").unwrap();
        let download = state::export_account(&owner, ApiKeyScope::Download).unwrap();
        let downloader = root.path().join("downloader");

        install_download(&downloader, download.as_bytes()).unwrap();

        assert!(state::load_account(&downloader, ApiKeyScope::Download).is_ok());
        assert!(state::load_account(&downloader, ApiKeyScope::Publish).is_err());
    }
}
