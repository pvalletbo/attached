use std::{fmt, path::Path};

use anyhow::{Context as _, Result, bail, ensure};
use attached_session_sync_protocol::{
    account::{
        AccountBundle, AccountId, AccountRootKey, ApiKeyScope, ApiToken,
        AuthorizedConsumerIdentity, ConsumerIdentitySecret, OwnerAccountBundle,
        ScopedAccountBundle, ServiceOrigin,
    },
    api::CreateAccountResponse,
    limits::MAX_BUNDLE_ENCODED_BYTES,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    local_encryption::{
        MasterKeyStore, Purpose, active_store, is_envelope, open, seal, stored_limit,
        with_master_key, with_master_key_store,
    },
    secure_state::{StateDir, prepare_private_dir, with_exclusive_lock, with_locked_existing},
};

const ACCOUNT_FILE: &str = "sync-account.bundle";
const ACCOUNT_LOCK: &str = "sync-account.lock";
const PUBLISH_FILE: &str = "sync-account.publish.bundle";
const DOWNLOAD_FILE: &str = "sync-account.download.bundle";
const ACCOUNT_FILES: [&str; 3] = [ACCOUNT_FILE, PUBLISH_FILE, DOWNLOAD_FILE];
const MAX_ACCOUNT_STATE_BYTES: usize = MAX_BUNDLE_ENCODED_BYTES;
const MAX_STORED_ACCOUNT_BYTES: usize = stored_limit(MAX_ACCOUNT_STATE_BYTES);

pub struct AccountCredentials {
    service_origin: String,
    account_id: AccountId,
    api_key_scope: ApiKeyScope,
    api_token: [u8; 32],
    account_root_key: [u8; 32],
    authorized_consumer_identity: Option<AuthorizedConsumerIdentity>,
    consumer_identity_secret: Option<[u8; 32]>,
}

impl fmt::Debug for AccountCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountCredentials")
            .field("service_origin", &self.service_origin)
            .field("account_id", &self.account_id)
            .field("api_key_scope", &self.api_key_scope)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

impl Drop for AccountCredentials {
    fn drop(&mut self) {
        self.api_token.zeroize();
        self.account_root_key.zeroize();
        self.consumer_identity_secret.zeroize();
    }
}

impl AccountCredentials {
    fn from_bundle(bundle: ScopedAccountBundle) -> Self {
        let api_key_scope = bundle.api_key_scope();
        let authorized_consumer_identity = bundle.authorized_consumer_identity();
        let consumer_identity_secret = bundle
            .consumer_identity_secret()
            .map(|secret| *secret.as_bytes());
        bundle.consume(|origin, account_id, api_token, account_root_key| Self {
            service_origin: origin.as_str().to_owned(),
            account_id,
            api_key_scope,
            api_token: *api_token,
            account_root_key: *account_root_key,
            authorized_consumer_identity,
            consumer_identity_secret,
        })
    }

    pub fn service_origin(&self) -> &str {
        &self.service_origin
    }

    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub const fn api_key_scope(&self) -> ApiKeyScope {
        self.api_key_scope
    }

    pub fn account_root_key(&self) -> &[u8; 32] {
        &self.account_root_key
    }

    pub const fn authorized_consumer_identity(&self) -> Option<AuthorizedConsumerIdentity> {
        self.authorized_consumer_identity
    }

    pub const fn consumer_identity_secret(&self) -> Option<&[u8; 32]> {
        self.consumer_identity_secret.as_ref()
    }

    fn consumer_public_key(&self) -> Option<AuthorizedConsumerIdentity> {
        self.authorized_consumer_identity.or_else(|| {
            self.consumer_identity_secret
                .map(|secret| ConsumerIdentitySecret::from_bytes(secret).authorized_identity())
        })
    }

    fn same_account(&self, other: &Self) -> bool {
        self.service_origin == other.service_origin
            && self.account_id == other.account_id
            && self.account_root_key == other.account_root_key
            && self.consumer_public_key() == other.consumer_public_key()
    }

    fn encode(&self) -> Result<String> {
        let origin = ServiceOrigin::parse(&self.service_origin)
            .map_err(|_| anyhow::anyhow!("invalid stored service origin"))?;
        let token = ApiToken::from_bytes(self.api_token);
        let root = AccountRootKey::from_bytes(self.account_root_key);
        let bundle = match self.api_key_scope {
            ApiKeyScope::Publish => ScopedAccountBundle::from_parts(
                origin,
                self.account_id,
                self.api_key_scope,
                token,
                root,
                self.authorized_consumer_identity,
            ),
            ApiKeyScope::Download => ScopedAccountBundle::from_download_parts(
                origin,
                self.account_id,
                token,
                root,
                ConsumerIdentitySecret::from_bytes(
                    self.consumer_identity_secret
                        .context("download bundle has no consumer identity")?,
                ),
            ),
        }
        .map_err(|_| anyhow::anyhow!("invalid stored account credentials"))?;
        Ok(AccountBundle::Scoped(bundle).encode())
    }

    pub fn bearer_value(&self) -> String {
        let token = ApiToken::from_bytes(self.api_token);
        let encoded = token.encode();
        let mut value = String::with_capacity(7 + encoded.len());
        value.push_str("Bearer ");
        value.push_str(&encoded);
        value
    }
}

#[derive(Default)]
struct StoredAccounts {
    publish: Option<AccountCredentials>,
    download: Option<AccountCredentials>,
}

impl StoredAccounts {
    fn add(&mut self, bundle: AccountBundle) -> Result<()> {
        if let AccountBundle::Owner(owner) = bundle {
            self.add(AccountBundle::Scoped(owner.scoped(ApiKeyScope::Publish)))?;
            return self.add(AccountBundle::Scoped(
                owner.into_scoped(ApiKeyScope::Download),
            ));
        }
        let AccountBundle::Scoped(bundle) = bundle else {
            unreachable!()
        };
        let credentials = AccountCredentials::from_bundle(bundle);
        if let Some(existing) = self.publish.as_ref().or(self.download.as_ref()) {
            ensure!(
                existing.same_account(&credentials),
                "a different synchronization account is already configured in this workspace (account, service, encryption key, or consumer identity mismatch); select a different --workspace"
            );
        }
        let slot = match credentials.api_key_scope {
            ApiKeyScope::Publish => &mut self.publish,
            ApiKeyScope::Download => &mut self.download,
        };
        if let Some(existing) = slot {
            ensure!(
                existing.api_token == credentials.api_token,
                "different credentials for this account role are already configured; refusing to replace them"
            );
        } else {
            *slot = Some(credentials);
        }
        Ok(())
    }

    fn get(&self, scope: ApiKeyScope) -> Option<&AccountCredentials> {
        match scope {
            ApiKeyScope::Publish => self.publish.as_ref(),
            ApiKeyScope::Download => self.download.as_ref(),
        }
    }

    fn take(self, scope: ApiKeyScope) -> Option<AccountCredentials> {
        match scope {
            ApiKeyScope::Publish => self.publish,
            ApiKeyScope::Download => self.download,
        }
    }
}

pub fn ensure_account_slot_available(state_dir: &Path) -> Result<()> {
    prepare_private_dir(state_dir)?;
    with_exclusive_lock(state_dir, ACCOUNT_LOCK, |directory| {
        for name in ACCOUNT_FILES {
            ensure!(
                directory
                    .read_secret_optional_bounded(name, MAX_STORED_ACCOUNT_BYTES)?
                    .is_none(),
                "a synchronization account is already configured; select a new --workspace"
            );
        }
        Ok(())
    })
}

pub fn install_created_account(
    state_dir: &Path,
    service_origin: ServiceOrigin,
    response: CreateAccountResponse,
    consumer_identity_secret: ConsumerIdentitySecret,
) -> Result<()> {
    let root_key = AccountRootKey::generate().context("could not generate the account root key")?;
    let (account_id, publish_token, download_token) = response.into_parts();
    let owner = OwnerAccountBundle::from_parts(
        service_origin,
        account_id,
        publish_token,
        download_token,
        root_key,
        consumer_identity_secret,
    )
    .map_err(|_| anyhow::anyhow!("could not create owner account bundle"))?;
    let owner_encoded = Zeroizing::new(AccountBundle::Owner(owner).encode());
    install_account(state_dir, owner_encoded.as_bytes(), false)
}

pub fn import_account(state_dir: &Path, encoded: &[u8]) -> Result<()> {
    let bundle =
        AccountBundle::parse(encoded).map_err(|_| anyhow::anyhow!("invalid account bundle"))?;
    ensure!(
        matches!(bundle, AccountBundle::Scoped(_)),
        "only a scoped account bundle can be imported"
    );
    install_account(state_dir, encoded, true)
}

pub fn export_account(state_dir: &Path, scope: ApiKeyScope) -> Result<String> {
    export_account_with_store(state_dir, scope, active_store())
}

fn export_account_with_store(
    state_dir: &Path,
    scope: ApiKeyScope,
    store: &dyn MasterKeyStore,
) -> Result<String> {
    let accounts = load_accounts_with_store(state_dir, store)?;
    accounts
        .get(scope)
        .with_context(|| {
            format!(
                "no {} credentials are configured in this workspace",
                scope_name(scope)
            )
        })?
        .encode()
}

fn install_account(state_dir: &Path, encoded: &[u8], allow_idempotent: bool) -> Result<()> {
    if encoded.len() > MAX_ACCOUNT_STATE_BYTES {
        bail!("account bundle exceeds local state limit");
    }
    let incoming =
        AccountBundle::parse(encoded).map_err(|_| anyhow::anyhow!("invalid account bundle"))?;
    prepare_private_dir(state_dir)?;
    with_exclusive_lock(state_dir, ACCOUNT_LOCK, |directory| {
        // Validate without migrating: a rejected import must not change even
        // legacy plaintext state. New roles only ever supplement matching accounts.
        let mut accounts = read_accounts(directory, active_store(), false)?;
        let occupied = accounts.publish.is_some() || accounts.download.is_some();
        ensure!(
            !occupied || allow_idempotent,
            "a synchronization account is already configured"
        );
        let (scope, already_present) = match &incoming {
            AccountBundle::Scoped(bundle) => (
                Some(bundle.api_key_scope()),
                accounts.get(bundle.api_key_scope()).is_some(),
            ),
            AccountBundle::Owner(_) => (None, false),
        };
        accounts.add(incoming)?;
        if occupied {
            // After validating the new role, also protect any legacy primary
            // bundle. Supplementing it must not leave the original plaintext.
            read_accounts(directory, active_store(), true)?;
        }
        if already_present {
            return Ok(());
        }
        let name = if occupied {
            match scope.context("cannot supplement an account with owner credentials")? {
                ApiKeyScope::Publish => PUBLISH_FILE,
                ApiKeyScope::Download => DOWNLOAD_FILE,
            }
        } else {
            ACCOUNT_FILE
        };
        let installed = with_master_key(directory, true, |key| {
            let encrypted = seal(key, Purpose::SyncAccount, encoded, MAX_ACCOUNT_STATE_BYTES)?;
            directory.create_noclobber(name, &encrypted)
        })?;
        if installed {
            Ok(())
        } else {
            anyhow::bail!("synchronization account was concurrently installed")
        }
    })
}

#[tracing::instrument(name = "load_sync_account", level = "debug", skip_all)]
pub fn load_account(state_dir: &Path, required_scope: ApiKeyScope) -> Result<AccountCredentials> {
    load_account_optional(state_dir, required_scope)?.with_context(|| format!(
        "no {} credentials are configured in this workspace; import a {}-only bundle (a publish bundle never grants consumer access)",
        scope_name(required_scope), scope_name(required_scope)
    ))
}

#[cfg(test)]
pub fn has_download_account(state_dir: &Path) -> Result<bool> {
    Ok(load_account_optional(state_dir, ApiKeyScope::Download)?.is_some())
}

pub(crate) fn capabilities(state_dir: &Path) -> Result<(bool, bool)> {
    let accounts = load_accounts_with_store(state_dir, active_store())?;
    Ok((accounts.publish.is_some(), accounts.download.is_some()))
}

#[tracing::instrument(name = "load_optional_sync_account", level = "debug", skip_all)]
pub fn load_account_optional(
    state_dir: &Path,
    required_scope: ApiKeyScope,
) -> Result<Option<AccountCredentials>> {
    Ok(load_accounts_with_store(state_dir, active_store())?.take(required_scope))
}

#[tracing::instrument(name = "read_sync_account", level = "debug", skip_all)]
fn load_accounts_with_store(
    state_dir: &Path,
    store: &dyn MasterKeyStore,
) -> Result<StoredAccounts> {
    with_locked_existing(state_dir, ACCOUNT_LOCK, |directory| {
        read_accounts(directory, store, true)
    })
}

fn read_accounts(
    directory: &StateDir,
    store: &dyn MasterKeyStore,
    migrate: bool,
) -> Result<StoredAccounts> {
    let mut accounts = StoredAccounts::default();
    for name in ACCOUNT_FILES {
        let Some(encoded) =
            directory.read_secret_optional_bounded(name, MAX_STORED_ACCOUNT_BYTES)?
        else {
            continue;
        };
        let encoded = decrypt_account_with_store(directory, store, name, encoded, migrate)?;
        let bundle = AccountBundle::parse(&encoded)
            .map_err(|_| anyhow::anyhow!("stored synchronization account is invalid"))?;
        if name != ACCOUNT_FILE {
            let expected = if name == PUBLISH_FILE {
                ApiKeyScope::Publish
            } else {
                ApiKeyScope::Download
            };
            ensure!(
                matches!(&bundle, AccountBundle::Scoped(bundle) if bundle.api_key_scope() == expected),
                "stored account role does not match its slot"
            );
        }
        accounts.add(bundle)?;
    }
    Ok(accounts)
}

fn decrypt_account_with_store(
    directory: &StateDir,
    store: &dyn MasterKeyStore,
    name: &str,
    encoded: Zeroizing<Vec<u8>>,
    migrate_legacy: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if is_envelope(&encoded) {
        return with_master_key_store(directory, store, false, |key| {
            open(key, Purpose::SyncAccount, &encoded, MAX_ACCOUNT_STATE_BYTES)
        });
    }
    AccountBundle::parse(&encoded)
        .map_err(|_| anyhow::anyhow!("stored synchronization account is invalid"))?;
    if migrate_legacy {
        with_master_key_store(directory, store, true, |key| {
            let encrypted = seal(key, Purpose::SyncAccount, &encoded, MAX_ACCOUNT_STATE_BYTES)?;
            directory.atomic_replace(name, &encrypted)
        })?;
        tracing::info!(
            event = "local_secret_migrated",
            purpose = Purpose::SyncAccount.name(),
            "migrated legacy local secret to encrypted storage"
        );
    }
    Ok(encoded)
}

const fn scope_name(scope: ApiKeyScope) -> &'static str {
    match scope {
        ApiKeyScope::Publish => "publish",
        ApiKeyScope::Download => "download",
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn create_publisher(state_dir: &Path, service_origin: &str) -> Result<()> {
        let creator = crate::test_support::canonical_tempdir();
        create_account(creator.path(), service_origin)?;
        let bundle = export_account(creator.path(), ApiKeyScope::Publish)?;
        import_account(state_dir, bundle.as_bytes())
    }

    pub(crate) fn create_account(state_dir: &Path, service_origin: &str) -> Result<()> {
        let service_origin = ServiceOrigin::parse(service_origin)
            .map_err(|_| anyhow::anyhow!("invalid sync service origin"))?;
        let response = CreateAccountResponse::new(
            AccountId::parse("01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2")
                .expect("synthetic UUIDv7 fixture is valid"),
            ApiToken::from_bytes([0x41; 32]),
            ApiToken::from_bytes([0x42; 32]),
        )
        .expect("synthetic account response is valid");
        install_created_account(
            state_dir,
            service_origin,
            response,
            ConsumerIdentitySecret::from_bytes([0x43; 32]),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    struct FixedStore([u8; 32]);

    struct MissingStore;

    impl crate::local_encryption::MasterKeyStore for MissingStore {
        fn load_or_create(
            &self,
            _directory: &StateDir,
            _create: bool,
        ) -> Result<Zeroizing<[u8; 32]>> {
            anyhow::bail!("synthetic missing key")
        }
    }

    struct StoreFailsAfterNone;

    impl crate::local_encryption::MasterKeyStore for StoreFailsAfterNone {
        fn load_or_create(
            &self,
            _directory: &StateDir,
            _create: bool,
        ) -> Result<Zeroizing<[u8; 32]>> {
            anyhow::bail!("synthetic store failure")
        }
    }

    impl crate::local_encryption::MasterKeyStore for FixedStore {
        fn load_or_create(
            &self,
            _directory: &StateDir,
            _create: bool,
        ) -> Result<Zeroizing<[u8; 32]>> {
            Ok(Zeroizing::new(self.0))
        }
    }

    fn fixture_account_id() -> AccountId {
        AccountId::parse("01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2").unwrap()
    }

    fn fixture_response() -> CreateAccountResponse {
        CreateAccountResponse::new(
            fixture_account_id(),
            ApiToken::from_bytes([1; 32]),
            ApiToken::from_bytes([2; 32]),
        )
        .unwrap()
    }

    fn install_fixture(state_dir: &Path) {
        install_created_account(
            state_dir,
            ServiceOrigin::parse("https://sync.example").unwrap(),
            fixture_response(),
            ConsumerIdentitySecret::from_bytes([4; 32]),
        )
        .unwrap();
    }

    #[test]
    fn account_credentials_debug_output_is_redacted() {
        let credentials = AccountCredentials {
            service_origin: "http://127.0.0.1:8080".to_owned(),
            account_id: fixture_account_id(),
            api_key_scope: ApiKeyScope::Publish,
            api_token: [2; 32],
            account_root_key: [3; 32],
            authorized_consumer_identity: Some(AuthorizedConsumerIdentity::from_bytes([4; 32])),
            consumer_identity_secret: None,
        };
        let debug = format!("{credentials:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&format!("{:?}", [2; 32])));
        assert!(!debug.contains(&format!("{:?}", [3; 32])));
    }

    fn fixture_owner() -> OwnerAccountBundle {
        OwnerAccountBundle::from_parts(
            ServiceOrigin::parse("https://sync.example").unwrap(),
            fixture_account_id(),
            ApiToken::from_bytes([1; 32]),
            ApiToken::from_bytes([2; 32]),
            AccountRootKey::from_bytes([3; 32]),
            ConsumerIdentitySecret::from_bytes([4; 32]),
        )
        .unwrap()
    }

    fn parse_scoped(encoded: &str) -> ScopedAccountBundle {
        match AccountBundle::parse(encoded.as_bytes()).unwrap() {
            AccountBundle::Scoped(bundle) => bundle,
            AccountBundle::Owner(_) => panic!("expected a scoped bundle"),
        }
    }

    fn assert_same_account_with_distinct_tokens(
        publish: ScopedAccountBundle,
        download: ScopedAccountBundle,
    ) {
        let publish = publish.consume(|origin, account_id, api_token, root_key| {
            (
                origin.as_str().to_owned(),
                account_id,
                *api_token,
                *root_key,
            )
        });
        let download = download.consume(|origin, account_id, api_token, root_key| {
            (
                origin.as_str().to_owned(),
                account_id,
                *api_token,
                *root_key,
            )
        });
        assert_eq!(publish.0, download.0);
        assert_eq!(publish.1, download.1);
        assert_ne!(publish.2, download.2);
        assert_eq!(publish.3, download.3);
    }

    #[test]
    fn owner_bundle_roundtrips_both_scopes_without_exporting_both_keys() {
        let encoded = AccountBundle::Owner(fixture_owner()).encode();
        assert!(
            encoded
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') })
        );

        let mut accounts = StoredAccounts::default();
        accounts
            .add(AccountBundle::parse(encoded.as_bytes()).unwrap())
            .unwrap();
        let publish = parse_scoped(
            &accounts
                .get(ApiKeyScope::Publish)
                .unwrap()
                .encode()
                .unwrap(),
        );
        let download = parse_scoped(
            &accounts
                .get(ApiKeyScope::Download)
                .unwrap()
                .encode()
                .unwrap(),
        );
        assert_eq!(publish.api_key_scope(), ApiKeyScope::Publish);
        assert_eq!(download.api_key_scope(), ApiKeyScope::Download);
        assert!(publish.consumer_identity_secret().is_none());
        assert!(download.consumer_identity_secret().is_some());
        assert_same_account_with_distinct_tokens(publish, download);
    }

    #[test]
    fn issued_account_is_encrypted_and_exports_separate_scopes_on_demand() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        install_fixture(&state);
        let stored = std::fs::read(state.join(ACCOUNT_FILE)).unwrap();
        assert!(
            crate::local_encryption::is_envelope(&stored),
            "account state was not encrypted"
        );
        assert!(
            AccountBundle::parse(&stored).is_err(),
            "portable account bundle remained plaintext at rest"
        );
        let publish_text = export_account(&state, ApiKeyScope::Publish).unwrap();
        let download_text = export_account(&state, ApiKeyScope::Download).unwrap();
        let exported_download = export_account(&state, ApiKeyScope::Download).unwrap();
        assert_eq!(download_text.as_bytes(), exported_download.as_bytes());

        let publish = parse_scoped(&publish_text);
        let download = parse_scoped(&download_text);
        assert_eq!(publish.api_key_scope(), ApiKeyScope::Publish);
        assert_eq!(download.api_key_scope(), ApiKeyScope::Download);
        assert_same_account_with_distinct_tokens(publish, download);
        assert_eq!(
            load_account(&state, ApiKeyScope::Publish)
                .unwrap()
                .api_key_scope(),
            ApiKeyScope::Publish
        );
        assert_eq!(
            load_account(&state, ApiKeyScope::Download)
                .unwrap()
                .api_key_scope(),
            ApiKeyScope::Download
        );
        assert!(has_download_account(&state).unwrap());
    }

    #[test]
    fn configured_account_is_rejected_before_another_issuance() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        install_fixture(&state);
        let error = ensure_account_slot_available(&state)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already configured"), "{error}");
    }

    #[test]
    fn imported_publish_bundle_cannot_be_loaded_for_download() {
        let root = crate::test_support::canonical_tempdir();
        let owner_state = root.path().join("owner");
        install_fixture(&owner_state);
        let publish = export_account(&owner_state, ApiKeyScope::Publish).unwrap();

        let publisher_state = root.path().join("publisher");
        prepare_private_dir(&publisher_state).unwrap();
        assert!(!has_download_account(&publisher_state).unwrap());
        import_account(&publisher_state, publish.as_bytes()).unwrap();
        assert!(!has_download_account(&publisher_state).unwrap());
        assert!(load_account(&publisher_state, ApiKeyScope::Publish).is_ok());
        let error = load_account(&publisher_state, ApiKeyScope::Download)
            .unwrap_err()
            .to_string();
        assert!(error.contains("download-only"), "{error}");
    }

    #[test]
    fn idempotent_import_migrates_legacy_plaintext_account() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let expected = AccountBundle::Scoped(fixture_owner().scoped(ApiKeyScope::Publish)).encode();
        std::fs::write(state.join(ACCOUNT_FILE), expected.as_bytes()).unwrap();
        std::fs::set_permissions(
            state.join(ACCOUNT_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        import_account(&state, expected.as_bytes()).unwrap();

        let migrated = std::fs::read(state.join(ACCOUNT_FILE)).unwrap();
        assert!(crate::local_encryption::is_envelope(&migrated));
        assert_ne!(migrated, expected.as_bytes());
        assert_eq!(
            export_account(&state, ApiKeyScope::Publish).unwrap(),
            expected
        );
    }

    #[test]
    fn different_import_over_legacy_plaintext_leaves_original_bytes_unchanged() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let original = AccountBundle::Scoped(fixture_owner().scoped(ApiKeyScope::Publish)).encode();
        let different = AccountBundle::Scoped(
            ScopedAccountBundle::from_download_parts(
                ServiceOrigin::parse("https://other.example").unwrap(),
                fixture_account_id(),
                ApiToken::from_bytes([2; 32]),
                AccountRootKey::from_bytes([3; 32]),
                ConsumerIdentitySecret::from_bytes([4; 32]),
            )
            .unwrap(),
        )
        .encode();
        std::fs::write(state.join(ACCOUNT_FILE), original.as_bytes()).unwrap();
        std::fs::set_permissions(
            state.join(ACCOUNT_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let error = import_account(&state, different.as_bytes())
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("different synchronization account"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(state.join(ACCOUNT_FILE)).unwrap(),
            original.as_bytes()
        );
    }

    #[test]
    fn complementary_roles_coexist_in_both_import_orders_without_replacing_state() {
        for first_scope in [ApiKeyScope::Publish, ApiKeyScope::Download] {
            let root = crate::test_support::canonical_tempdir();
            let first = AccountBundle::Scoped(fixture_owner().scoped(first_scope)).encode();
            let second_scope = if first_scope == ApiKeyScope::Publish {
                ApiKeyScope::Download
            } else {
                ApiKeyScope::Publish
            };
            let second = AccountBundle::Scoped(fixture_owner().scoped(second_scope)).encode();
            import_account(root.path(), first.as_bytes()).unwrap();
            let primary = std::fs::read(root.path().join(ACCOUNT_FILE)).unwrap();
            assert!(
                load_account_optional(root.path(), second_scope)
                    .unwrap()
                    .is_none()
            );
            import_account(root.path(), second.as_bytes()).unwrap();
            import_account(root.path(), first.as_bytes()).unwrap();
            import_account(root.path(), second.as_bytes()).unwrap();
            assert_eq!(capabilities(root.path()).unwrap(), (true, true));
            assert_eq!(export_account(root.path(), first_scope).unwrap(), first);
            assert_eq!(export_account(root.path(), second_scope).unwrap(), second);
            assert_eq!(
                std::fs::read(root.path().join(ACCOUNT_FILE)).unwrap(),
                primary
            );
            for name in ACCOUNT_FILES {
                if let Ok(bytes) = std::fs::read(root.path().join(name)) {
                    assert!(is_envelope(&bytes));
                }
            }
        }
    }

    #[test]
    fn adding_a_role_migrates_a_matching_legacy_primary_without_changing_credentials() {
        let root = crate::test_support::canonical_tempdir();
        prepare_private_dir(root.path()).unwrap();
        let publish = AccountBundle::Scoped(fixture_owner().scoped(ApiKeyScope::Publish)).encode();
        let download =
            AccountBundle::Scoped(fixture_owner().scoped(ApiKeyScope::Download)).encode();
        let directory = StateDir::open(root.path()).unwrap();
        directory
            .create_noclobber(ACCOUNT_FILE, publish.as_bytes())
            .unwrap();
        import_account(root.path(), download.as_bytes()).unwrap();
        assert!(is_envelope(
            &std::fs::read(root.path().join(ACCOUNT_FILE)).unwrap()
        ));
        assert!(is_envelope(
            &std::fs::read(root.path().join(DOWNLOAD_FILE)).unwrap()
        ));
        assert_eq!(
            export_account(root.path(), ApiKeyScope::Publish).unwrap(),
            publish
        );
        assert_eq!(
            export_account(root.path(), ApiKeyScope::Download).unwrap(),
            download
        );
    }

    #[test]
    fn invalid_supplemental_state_fails_closed_without_replacing_primary_credentials() {
        let root = crate::test_support::canonical_tempdir();
        let publish = AccountBundle::Scoped(fixture_owner().scoped(ApiKeyScope::Publish)).encode();
        let download =
            AccountBundle::Scoped(fixture_owner().scoped(ApiKeyScope::Download)).encode();
        import_account(root.path(), publish.as_bytes()).unwrap();
        import_account(root.path(), download.as_bytes()).unwrap();
        let primary = std::fs::read(root.path().join(ACCOUNT_FILE)).unwrap();
        let directory = StateDir::open(root.path()).unwrap();
        for invalid in [b"corrupt".as_slice(), primary.as_slice()] {
            directory.atomic_replace(DOWNLOAD_FILE, invalid).unwrap();
            assert!(load_account(root.path(), ApiKeyScope::Publish).is_err());
            assert!(load_account(root.path(), ApiKeyScope::Download).is_err());
            assert!(import_account(root.path(), download.as_bytes()).is_err());
            assert_eq!(
                std::fs::read(root.path().join(ACCOUNT_FILE)).unwrap(),
                primary
            );
        }
    }

    #[test]
    fn complementary_role_requires_matching_service_account_root_and_consumer() {
        for (origin, id, key, identity) in [
            (
                "https://other.example",
                fixture_account_id(),
                [3; 32],
                [4; 32],
            ),
            (
                "https://sync.example",
                AccountId::parse("01900000-0000-7000-8000-000000000001").unwrap(),
                [3; 32],
                [4; 32],
            ),
            (
                "https://sync.example",
                fixture_account_id(),
                [9; 32],
                [4; 32],
            ),
            (
                "https://sync.example",
                fixture_account_id(),
                [3; 32],
                [9; 32],
            ),
        ] {
            let root = crate::test_support::canonical_tempdir();
            let publish =
                AccountBundle::Scoped(fixture_owner().scoped(ApiKeyScope::Publish)).encode();
            import_account(root.path(), publish.as_bytes()).unwrap();
            let before = std::fs::read(root.path().join(ACCOUNT_FILE)).unwrap();
            let download = AccountBundle::Scoped(
                ScopedAccountBundle::from_download_parts(
                    ServiceOrigin::parse(origin).unwrap(),
                    id,
                    ApiToken::from_bytes([2; 32]),
                    AccountRootKey::from_bytes(key),
                    ConsumerIdentitySecret::from_bytes(identity),
                )
                .unwrap(),
            )
            .encode();
            let error = import_account(root.path(), download.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("different synchronization account"),
                "{error}"
            );
            assert_eq!(
                std::fs::read(root.path().join(ACCOUNT_FILE)).unwrap(),
                before
            );
            assert!(!root.path().join(DOWNLOAD_FILE).exists());
            assert_eq!(capabilities(root.path()).unwrap(), (true, false));
        }
    }

    #[test]
    fn legacy_plaintext_account_migrates_and_preserves_exact_export() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let expected = AccountBundle::Scoped(fixture_owner().scoped(ApiKeyScope::Publish)).encode();
        std::fs::write(state.join(ACCOUNT_FILE), expected.as_bytes()).unwrap();
        std::fs::set_permissions(
            state.join(ACCOUNT_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let exported =
            export_account_with_store(&state, ApiKeyScope::Publish, &FixedStore([0x44; 32]))
                .unwrap();

        assert_eq!(exported, expected);
        let migrated = std::fs::read(state.join(ACCOUNT_FILE)).unwrap();
        assert!(crate::local_encryption::is_envelope(&migrated));
        assert_ne!(migrated, expected.as_bytes());
    }

    #[test]
    fn missing_and_wrong_account_keys_leave_ciphertext_byte_exact() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let plaintext = Zeroizing::new(AccountBundle::Owner(fixture_owner()).encode());
        let envelope = seal(
            &[0x44; 32],
            Purpose::SyncAccount,
            plaintext.as_bytes(),
            MAX_ACCOUNT_STATE_BYTES,
        )
        .unwrap();
        std::fs::write(state.join(ACCOUNT_FILE), &envelope).unwrap();
        std::fs::set_permissions(
            state.join(ACCOUNT_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        for store in [
            &MissingStore as &dyn MasterKeyStore,
            &FixedStore([0x45; 32]),
        ] {
            assert!(export_account_with_store(&state, ApiKeyScope::Publish, store).is_err());
            assert_eq!(
                std::fs::read(state.join(ACCOUNT_FILE)).unwrap(),
                envelope.as_slice()
            );
        }
    }

    #[test]
    fn store_failure_after_initial_none_leaves_legacy_account_byte_exact() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let plaintext = AccountBundle::Owner(fixture_owner()).encode();
        std::fs::write(state.join(ACCOUNT_FILE), plaintext.as_bytes()).unwrap();
        std::fs::set_permissions(
            state.join(ACCOUNT_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        assert!(
            export_account_with_store(&state, ApiKeyScope::Publish, &StoreFailsAfterNone).is_err()
        );
        assert_eq!(
            std::fs::read(state.join(ACCOUNT_FILE)).unwrap(),
            plaintext.as_bytes()
        );
    }
}
