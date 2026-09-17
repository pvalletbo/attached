use std::{fs::File, path::Path};

use anyhow::{Context as _, Result, ensure};
use attached_session_sync_protocol::account::{
    AccountBundle, ApiKeyScope, ConsumerIdentitySecret, ServiceOrigin,
};

use crate::{
    local_encryption::{MasterKeyStore, active_store, with_master_key_store},
    secure_state::StateDir,
};

use super::{http::SyncHttpClient, state};

const ACCOUNT_MUTATION_LOCK: &str = "sync-account-mutation.lock";

struct AccountMutationGuard {
    _directory: StateDir,
    _lock: File,
}

impl AccountMutationGuard {
    fn acquire(state_dir: &Path) -> Result<Self> {
        let directory =
            StateDir::open(state_dir).context("could not open synchronization account state")?;
        let lock = directory
            .open_private_lock_file(ACCOUNT_MUTATION_LOCK, true)?
            .context("synchronization account mutation lock is missing")?;
        fs4::FileExt::lock(&lock).context("could not lock synchronization account mutations")?;
        directory
            .verify_locked_file(state_dir, ACCOUNT_MUTATION_LOCK, &lock)
            .context("could not verify synchronization account mutation lock")?;
        Ok(Self {
            _directory: directory,
            _lock: lock,
        })
    }
}

pub async fn create(state_dir: &Path, service_origin: &str) -> Result<()> {
    create_with_store(state_dir, service_origin, active_store()).await
}

async fn create_with_store(
    state_dir: &Path,
    service_origin: &str,
    store: &dyn MasterKeyStore,
) -> Result<()> {
    let service_origin = ServiceOrigin::parse(service_origin)
        .map_err(|_| anyhow::anyhow!("invalid sync service origin"))?;
    state::ensure_account_slot_available(state_dir)?;
    prepare_encrypted_account_storage(state_dir, store)?;

    // Recheck the account slot while holding a lock that spans the remote side
    // effect and the local install. Without this, two concurrent `account create`
    // invocations can both create service accounts before only one wins the
    // local no-clobber write, leaving the other remote account orphaned.
    let _mutation = AccountMutationGuard::acquire(state_dir)?;
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

fn prepare_encrypted_account_storage(state_dir: &Path, store: &dyn MasterKeyStore) -> Result<()> {
    let directory =
        StateDir::open(state_dir).context("could not open synchronization account state")?;
    with_master_key_store(&directory, store, true, |_| Ok(()))
        .context("could not prepare encrypted synchronization account storage")
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
    let _mutation = AccountMutationGuard::acquire(state_dir)?;
    state::import_account(state_dir, encoded)
}

pub fn export(state_dir: &Path, scope: ApiKeyScope) -> Result<String> {
    state::export_account(state_dir, scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use attached_session_sync_protocol::{
        account::{AccountId, ApiToken},
        api::CreateAccountResponse,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct FailingStore;

    impl MasterKeyStore for FailingStore {
        fn load_or_create(
            &self,
            _directory: &StateDir,
            _create: bool,
        ) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
            anyhow::bail!("synthetic encryption backend failure")
        }
    }

    async fn read_request_headers(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        loop {
            let byte = stream
                .read_u8()
                .await
                .expect("request ended before headers");
            bytes.push(byte);
            assert!(bytes.len() <= 8192, "oversized fixture request");
            if bytes.ends_with(b"\r\n\r\n") {
                return String::from_utf8(bytes).unwrap();
            }
        }
    }

    async fn respond_created(stream: &mut tokio::net::TcpStream) {
        let response = CreateAccountResponse::new(
            AccountId::parse("01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2").unwrap(),
            ApiToken::from_bytes([1; 32]),
            ApiToken::from_bytes([2; 32]),
        )
        .unwrap();
        let body = serde_json::to_vec(&response).unwrap();
        let headers = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn account_creation_preflights_encryption_before_remote_request() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("account-state");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service_origin = format!("http://{}", listener.local_addr().unwrap());
        let store = FailingStore;

        let error = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            create_with_store(&state_dir, &service_origin, &store),
        )
        .await
        .expect("local encryption preflight should fail without waiting for the service")
        .unwrap_err();
        let error = format!("{error:#}");

        assert!(
            error.contains("could not prepare encrypted synchronization account storage"),
            "{error}"
        );
        assert!(
            error.contains("synthetic encryption backend failure"),
            "{error}"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
                .await
                .is_err(),
            "the synchronization service received a connection before local encryption was ready"
        );
        assert!(!state_dir.join("sync-account.bundle").exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_account_creation_issues_only_one_remote_account() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("account-state");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service_origin = format!("http://{}", listener.local_addr().unwrap());

        let first_state = state_dir.clone();
        let first_origin = service_origin.clone();
        let first = tokio::spawn(async move {
            create_with_store(&first_state, &first_origin, active_store()).await
        });
        let (mut request, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
                .await
                .expect("first account creation never reached the service")
                .unwrap();
        let headers = read_request_headers(&mut request).await;
        assert_eq!(headers.lines().next(), Some("POST /v1/accounts HTTP/1.1"));

        let second_state = state_dir.clone();
        let second_origin = service_origin.clone();
        let second = tokio::spawn(async move {
            create_with_store(&second_state, &second_origin, active_store()).await
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept(),)
                .await
                .is_err(),
            "a concurrent creator reached the service before the first account was installed"
        );

        respond_created(&mut request).await;
        first.await.unwrap().unwrap();

        let error = second.await.unwrap().unwrap_err().to_string();
        assert!(
            error.contains("a synchronization account is already configured"),
            "{error}"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept(),)
                .await
                .is_err(),
            "the losing creator still created a remote account"
        );
        assert!(state_dir.join("sync-account.bundle").exists());
    }

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
