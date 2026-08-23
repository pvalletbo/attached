use std::{fmt, path::Path};

use anyhow::{Context as _, Result, bail, ensure};
use attached_session_sync_protocol::{
    account::{
        AccountBundle, AccountId, AccountRootKey, ApiKeyScope, ApiToken, OwnerAccountBundle,
        ScopedAccountBundle, ServiceOrigin,
    },
    api::CreateAccountResponse,
    limits::MAX_BUNDLE_ENCODED_BYTES,
};
use zeroize::{Zeroize, Zeroizing};

use crate::secure_state::{prepare_private_dir, with_exclusive_lock, with_locked_existing};

const ACCOUNT_FILE: &str = "sync-account.bundle";
const ACCOUNT_LOCK: &str = "sync-account.lock";
const MAX_ACCOUNT_STATE_BYTES: usize = MAX_BUNDLE_ENCODED_BYTES;

pub struct AccountCredentials {
    service_origin: String,
    account_id: AccountId,
    api_key_scope: ApiKeyScope,
    api_token: [u8; 32],
    account_root_key: [u8; 32],
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
    }
}

impl AccountCredentials {
    fn from_bundle(bundle: ScopedAccountBundle) -> Self {
        let api_key_scope = bundle.api_key_scope();
        bundle.consume(|origin, account_id, api_token, account_root_key| Self {
            service_origin: origin.as_str().to_owned(),
            account_id,
            api_key_scope,
            api_token: *api_token,
            account_root_key: *account_root_key,
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

    pub fn bearer_value(&self) -> String {
        let token = ApiToken::from_bytes(self.api_token);
        let encoded = token.encode();
        let mut value = String::with_capacity(7 + encoded.len());
        value.push_str("Bearer ");
        value.push_str(&encoded);
        value
    }
}

fn into_export_scope(
    stored: AccountBundle,
    required_scope: ApiKeyScope,
) -> Result<ScopedAccountBundle> {
    let bundle = match stored {
        AccountBundle::Scoped(bundle) => bundle,
        AccountBundle::Owner(bundle) => bundle.into_scoped(required_scope),
    };
    ensure!(
        bundle.api_key_scope() == required_scope,
        "the configured account bundle is {}-only; a {} bundle is required",
        scope_name(bundle.api_key_scope()),
        scope_name(required_scope)
    );
    Ok(bundle)
}

fn into_operational_scope(
    stored: AccountBundle,
    required_scope: ApiKeyScope,
) -> Result<ScopedAccountBundle> {
    match (stored, required_scope) {
        (AccountBundle::Owner(_), ApiKeyScope::Publish) => bail!(
            "account-creator state also contains the download key; export the publish bundle and import it into a separate publish-only state before running `serve`"
        ),
        (stored, required_scope) => into_export_scope(stored, required_scope),
    }
}

pub fn ensure_account_slot_available(state_dir: &Path) -> Result<()> {
    prepare_private_dir(state_dir)?;
    with_exclusive_lock(state_dir, ACCOUNT_LOCK, |directory| {
        ensure!(
            directory
                .read_optional_bounded(ACCOUNT_FILE, MAX_ACCOUNT_STATE_BYTES)?
                .is_none(),
            "a synchronization account is already configured"
        );
        Ok(())
    })
}

pub fn install_created_account(
    state_dir: &Path,
    service_origin: ServiceOrigin,
    response: CreateAccountResponse,
) -> Result<String> {
    let root_key = AccountRootKey::generate().context("could not generate the account root key")?;
    let (account_id, publish_token, download_token) = response.into_parts();
    let owner = OwnerAccountBundle::from_parts(
        service_origin,
        account_id,
        publish_token,
        download_token,
        root_key,
    )
    .map_err(|_| anyhow::anyhow!("could not create owner account bundle"))?;
    let download = owner.scoped(ApiKeyScope::Download);
    let download_encoded = AccountBundle::Scoped(download).encode();
    let owner_encoded = Zeroizing::new(AccountBundle::Owner(owner).encode());
    install_account(state_dir, owner_encoded.as_bytes(), false)?;
    Ok(download_encoded)
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
    let stored =
        load_stored_account(state_dir)?.context("no synchronization account is configured")?;
    Ok(AccountBundle::Scoped(into_export_scope(stored, scope)?).encode())
}

fn install_account(state_dir: &Path, encoded: &[u8], allow_idempotent: bool) -> Result<()> {
    if encoded.len() > MAX_ACCOUNT_STATE_BYTES {
        bail!("account bundle exceeds local state limit");
    }
    prepare_private_dir(state_dir)?;
    with_exclusive_lock(state_dir, ACCOUNT_LOCK, |directory| {
        if let Some(existing) =
            directory.read_optional_bounded(ACCOUNT_FILE, MAX_ACCOUNT_STATE_BYTES)?
        {
            if allow_idempotent && existing == encoded {
                return Ok(());
            }
            anyhow::bail!("a different synchronization account is already configured");
        }
        if directory.create_noclobber(ACCOUNT_FILE, encoded)? {
            Ok(())
        } else {
            anyhow::bail!("synchronization account was concurrently installed")
        }
    })
}

pub fn load_account(state_dir: &Path, required_scope: ApiKeyScope) -> Result<AccountCredentials> {
    load_account_optional(state_dir, required_scope)?
        .context("no synchronization account is configured")
}

pub fn has_download_account(state_dir: &Path) -> Result<bool> {
    Ok(match load_stored_account(state_dir)? {
        None => false,
        Some(AccountBundle::Scoped(bundle)) => bundle.api_key_scope() == ApiKeyScope::Download,
        Some(AccountBundle::Owner(_)) => true,
    })
}

pub fn load_account_optional(
    state_dir: &Path,
    required_scope: ApiKeyScope,
) -> Result<Option<AccountCredentials>> {
    load_stored_account(state_dir)?
        .map(|stored| {
            into_operational_scope(stored, required_scope).map(AccountCredentials::from_bundle)
        })
        .transpose()
}

fn load_stored_account(state_dir: &Path) -> Result<Option<AccountBundle>> {
    let encoded = with_locked_existing(state_dir, ACCOUNT_LOCK, |directory| {
        directory.read_optional_bounded(ACCOUNT_FILE, MAX_ACCOUNT_STATE_BYTES)
    })?;
    encoded
        .map(|encoded| {
            AccountBundle::parse(&encoded)
                .map_err(|_| anyhow::anyhow!("stored synchronization account is invalid"))
        })
        .transpose()
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

    pub(crate) fn create_account(state_dir: &Path, service_origin: &str) -> Result<String> {
        let service_origin = ServiceOrigin::parse(service_origin)
            .map_err(|_| anyhow::anyhow!("invalid sync service origin"))?;
        let response = CreateAccountResponse::new(
            AccountId::parse("01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2")
                .expect("synthetic UUIDv7 fixture is valid"),
            ApiToken::from_bytes([0x41; 32]),
            ApiToken::from_bytes([0x42; 32]),
        )
        .expect("synthetic account response is valid");
        install_created_account(state_dir, service_origin, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn install_fixture(state_dir: &Path) -> String {
        install_created_account(
            state_dir,
            ServiceOrigin::parse("https://sync.example").unwrap(),
            fixture_response(),
        )
        .unwrap()
    }

    #[test]
    fn account_credentials_debug_output_is_redacted() {
        let credentials = AccountCredentials {
            service_origin: "http://127.0.0.1:8080".to_owned(),
            account_id: fixture_account_id(),
            api_key_scope: ApiKeyScope::Publish,
            api_token: [2; 32],
            account_root_key: [3; 32],
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

        let publish = into_export_scope(
            AccountBundle::parse(encoded.as_bytes()).unwrap(),
            ApiKeyScope::Publish,
        )
        .unwrap();
        let download = into_export_scope(
            AccountBundle::parse(encoded.as_bytes()).unwrap(),
            ApiKeyScope::Download,
        )
        .unwrap();
        assert_eq!(publish.api_key_scope(), ApiKeyScope::Publish);
        assert_eq!(download.api_key_scope(), ApiKeyScope::Download);
        assert_same_account_with_distinct_tokens(publish, download);
        let error = into_operational_scope(
            AccountBundle::parse(encoded.as_bytes()).unwrap(),
            ApiKeyScope::Publish,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("publish-only state"), "{error}");
    }

    #[test]
    fn issued_account_exports_separate_consistent_scopes() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        let download_text = install_fixture(&state);
        let stored = std::fs::read(state.join(ACCOUNT_FILE)).unwrap();
        assert!(
            stored
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert!(matches!(
            AccountBundle::parse(&stored).unwrap(),
            AccountBundle::Owner(_)
        ));
        let publish_text = export_account(&state, ApiKeyScope::Publish).unwrap();
        let exported_download = export_account(&state, ApiKeyScope::Download).unwrap();
        assert_eq!(download_text.as_bytes(), exported_download.as_bytes());

        let publish = parse_scoped(&publish_text);
        let download = parse_scoped(&download_text);
        assert_eq!(publish.api_key_scope(), ApiKeyScope::Publish);
        assert_eq!(download.api_key_scope(), ApiKeyScope::Download);
        assert_same_account_with_distinct_tokens(publish, download);
        let error = load_account(&state, ApiKeyScope::Publish)
            .unwrap_err()
            .to_string();
        assert!(error.contains("publish-only state"), "{error}");
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
        assert!(error.contains("publish-only"), "{error}");
    }
}
