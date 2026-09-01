use std::{
    io::BufRead as _,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(not(test))]
use std::{
    process::{Command, Stdio},
    sync::LazyLock,
};

use anyhow::{Context as _, Result, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce, aead::AeadInOut as _};
use serde::Deserialize;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ATSECR01";
const VERSION: u8 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = MAGIC.len() + 1 + NONCE_BYTES;
const MASTER_KEY_BYTES: usize = 32;
const KDF_SALT_FILE: &str = "encryption-salt.argon2id-v1";
const KDF_SALT_BYTES: usize = 16;
const PRODUCTION_KDF_MEMORY_KIB: u32 = 19 * 1024;
const PRODUCTION_KDF_ITERATIONS: u32 = 2;
const KDF_PARALLELISM: u32 = 1;
#[cfg(not(test))]
const KDF_MEMORY_KIB: u32 = PRODUCTION_KDF_MEMORY_KIB;
#[cfg(test)]
const KDF_MEMORY_KIB: u32 = 64;
#[cfg(not(test))]
const KDF_ITERATIONS: u32 = PRODUCTION_KDF_ITERATIONS;
#[cfg(test)]
const KDF_ITERATIONS: u32 = 1;
const MAX_PASSWORD_BYTES: usize = 1024;
const ONE_PASSWORD_ITEM_TITLE: &str = "Attached encryption password";
const ONE_PASSWORD_ITEM_TAG: &str = "com.pvalletbo.attached/encryption-password-v1";
const ONE_PASSWORD_FIELD: &str = "password";
const ONE_PASSWORD_UNAVAILABLE: &str =
    "1Password is unavailable; unlock or sign in with the `op` CLI and retry";
#[cfg(not(test))]
const MAX_ONE_PASSWORD_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const COORDINATION_DIRECTORY: &str = "attached-encryption";
const MASTER_KEY_LOCK: &str = "local-master-key.lock";

static USE_ONE_PASSWORD: AtomicBool = AtomicBool::new(false);
static USE_PASSWORD_STDIN: AtomicBool = AtomicBool::new(false);

pub(crate) fn configure_password_provider(use_one_password: bool, use_password_stdin: bool) {
    USE_ONE_PASSWORD.store(use_one_password, Ordering::SeqCst);
    USE_PASSWORD_STDIN.store(use_password_stdin, Ordering::SeqCst);
}

pub(crate) trait MasterKeyStore: Send + Sync {
    fn load_or_create(
        &self,
        directory: &crate::secure_state::StateDir,
        create: bool,
    ) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>>;

    fn remove(&self) -> Result<()> {
        bail!("managed encryption password removal is unavailable")
    }
}

trait PasswordProvider: Send + Sync {
    fn password(&self, create: bool) -> Result<Zeroizing<Vec<u8>>>;

    fn remove(&self) -> Result<()> {
        bail!("user-provided encryption password is not stored")
    }
}

trait PasswordPrompt: Send + Sync {
    fn read_password(&self, prompt: &str) -> Result<Zeroizing<Vec<u8>>>;
}

#[cfg(not(test))]
struct TtyPasswordPrompt;

#[cfg(not(test))]
impl PasswordPrompt for TtyPasswordPrompt {
    fn read_password(&self, prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
        let password = rpassword::prompt_password(prompt)
            .context("could not read the encryption password from the controlling terminal")?;
        Ok(Zeroizing::new(password.into_bytes()))
    }
}

#[cfg(not(test))]
struct StdinPasswordPrompt;

#[cfg(not(test))]
impl PasswordPrompt for StdinPasswordPrompt {
    fn read_password(&self, _prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
        let mut input = std::io::stdin().lock();
        read_password_line(&mut input)
            .context("could not read the encryption password from standard input")
    }
}

fn read_password_line(reader: &mut impl std::io::BufRead) -> Result<Zeroizing<Vec<u8>>> {
    let mut password = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES));
    let mut limited = std::io::Read::take(&mut *reader, (MAX_PASSWORD_BYTES + 2) as u64);
    limited
        .read_until(b'\n', &mut password)
        .context("could not read encryption password input")?;
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    validate_password(&password)?;
    Ok(password)
}

struct UserPasswordProvider<P> {
    prompt: P,
    cached: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl<P: PasswordPrompt> PasswordProvider for UserPasswordProvider<P> {
    fn password(&self, create: bool) -> Result<Zeroizing<Vec<u8>>> {
        let mut cached = self
            .cached
            .lock()
            .map_err(|_| anyhow::anyhow!("encryption password cache is unavailable"))?;
        if let Some(password) = cached.as_ref() {
            return Ok(Zeroizing::new(password.to_vec()));
        }

        let prompt = if create {
            "Create Attached encryption password: "
        } else {
            "Attached encryption password: "
        };
        let password = self.prompt.read_password(prompt)?;
        validate_password(&password)?;
        if create {
            let confirmation = self
                .prompt
                .read_password("Confirm Attached encryption password: ")?;
            validate_password(&confirmation)?;
            ensure!(
                password.as_slice() == confirmation.as_slice(),
                "encryption passwords do not match"
            );
        }

        *cached = Some(Zeroizing::new(password.to_vec()));
        Ok(password)
    }
}

fn validate_password(password: &[u8]) -> Result<()> {
    ensure!(!password.is_empty(), "encryption password cannot be empty");
    ensure!(
        password.len() <= MAX_PASSWORD_BYTES,
        "encryption password exceeds {MAX_PASSWORD_BYTES} bytes"
    );
    Ok(())
}

struct PasswordMasterKeyStore<P> {
    passwords: P,
}

impl<P: PasswordProvider> MasterKeyStore for PasswordMasterKeyStore<P> {
    fn load_or_create(
        &self,
        directory: &crate::secure_state::StateDir,
        create: bool,
    ) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>> {
        let salt = load_or_create_kdf_salt(directory, create)?;
        let password = self.passwords.password(create)?;
        derive_master_key(&password, &salt)
    }

    fn remove(&self) -> Result<()> {
        self.passwords.remove()
    }
}

fn load_or_create_kdf_salt(
    directory: &crate::secure_state::StateDir,
    create: bool,
) -> Result<[u8; KDF_SALT_BYTES]> {
    if let Some(stored) = directory.read_secret_optional_bounded(KDF_SALT_FILE, KDF_SALT_BYTES)? {
        return parse_kdf_salt(&stored);
    }
    ensure!(create, "local encryption salt is missing");

    let mut candidate = [0u8; KDF_SALT_BYTES];
    getrandom::fill(&mut candidate)
        .context("operating-system randomness is unavailable while creating encryption salt")?;
    if directory.create_noclobber(KDF_SALT_FILE, &candidate)? {
        tracing::info!(
            event = "local_master_key_created",
            "initialized password-derived local encryption"
        );
        Ok(candidate)
    } else {
        let stored = directory.read_secret_bounded(KDF_SALT_FILE, KDF_SALT_BYTES)?;
        parse_kdf_salt(&stored)
    }
}

fn parse_kdf_salt(stored: &[u8]) -> Result<[u8; KDF_SALT_BYTES]> {
    ensure!(
        stored.len() == KDF_SALT_BYTES,
        "local encryption salt has {} bytes, expected {KDF_SALT_BYTES}",
        stored.len()
    );
    let mut salt = [0u8; KDF_SALT_BYTES];
    salt.copy_from_slice(stored);
    Ok(salt)
}

fn derive_master_key(
    password: &[u8],
    salt: &[u8; KDF_SALT_BYTES],
) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>> {
    validate_password(password)?;
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(MASTER_KEY_BYTES),
    )
    .map_err(|_| anyhow::anyhow!("local encryption KDF parameters are invalid"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; MASTER_KEY_BYTES]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| anyhow::anyhow!("could not derive the local encryption key"))?;
    Ok(key)
}

struct OpOutput {
    success: bool,
    stdout: Zeroizing<Vec<u8>>,
}

trait OpRunner: Send + Sync {
    fn run(&self, arguments: &[String]) -> Result<OpOutput>;
}

#[cfg(not(test))]
struct ProcessOpRunner {
    executable: PathBuf,
}

#[cfg(not(test))]
impl OpRunner for ProcessOpRunner {
    fn run(&self, arguments: &[String]) -> Result<OpOutput> {
        let output = Command::new(&self.executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .context("could not run the 1Password CLI")?;
        let stdout = Zeroizing::new(output.stdout);
        ensure!(
            stdout.len() <= MAX_ONE_PASSWORD_OUTPUT_BYTES,
            "1Password CLI output exceeded the local limit"
        );
        Ok(OpOutput {
            success: output.status.success(),
            stdout,
        })
    }
}

struct OnePasswordProvider<R> {
    runner: R,
    cached: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

#[derive(Deserialize)]
struct ListedItem {
    id: String,
    title: String,
    vault: ListedVault,
}

#[derive(Deserialize)]
struct ListedVault {
    id: String,
}

impl<R: OpRunner> OnePasswordProvider<R> {
    fn item(&self) -> Result<Option<ListedItem>> {
        let output = self.runner.run(&[
            "item".to_owned(),
            "list".to_owned(),
            "--categories=Password".to_owned(),
            format!("--tags={ONE_PASSWORD_ITEM_TAG}"),
            "--format=json".to_owned(),
        ])?;
        ensure!(output.success, ONE_PASSWORD_UNAVAILABLE);
        let listed: Vec<ListedItem> = serde_json::from_slice(&output.stdout)
            .context("1Password CLI returned invalid item metadata")?;
        let mut matches = listed
            .into_iter()
            .filter(|item| item.title == ONE_PASSWORD_ITEM_TITLE);
        let selected = matches.next();
        ensure!(
            matches.next().is_none(),
            "1Password contains multiple Attached encryption password items"
        );
        let Some(selected) = selected else {
            return Ok(None);
        };
        ensure!(
            !selected.id.is_empty() && selected.id.bytes().all(|byte| byte.is_ascii_alphanumeric()),
            "1Password returned an invalid item identifier"
        );
        ensure!(
            !selected.vault.id.is_empty()
                && selected
                    .vault
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric()),
            "1Password returned an invalid vault identifier"
        );
        Ok(Some(selected))
    }

    fn read_item_password(&self, item: ListedItem) -> Result<Zeroizing<Vec<u8>>> {
        let output = self.runner.run(&[
            "item".to_owned(),
            "get".to_owned(),
            item.id,
            format!("--vault={}", item.vault.id),
            format!("--fields=label={ONE_PASSWORD_FIELD}"),
            "--reveal".to_owned(),
        ])?;
        ensure!(output.success, ONE_PASSWORD_UNAVAILABLE);
        parse_one_password_output(output.stdout)
    }

    fn create_item(&self) -> Result<()> {
        let output = self.runner.run(&[
            "item".to_owned(),
            "create".to_owned(),
            "--category=Password".to_owned(),
            format!("--title={ONE_PASSWORD_ITEM_TITLE}"),
            format!("--tags={ONE_PASSWORD_ITEM_TAG}"),
            "--generate-password=letters,digits,symbols,64".to_owned(),
        ])?;
        ensure!(output.success, ONE_PASSWORD_UNAVAILABLE);
        tracing::info!(
            event = "one_password_encryption_password_created",
            "created managed encryption password in 1Password"
        );
        Ok(())
    }
}

impl<R: OpRunner> PasswordProvider for OnePasswordProvider<R> {
    fn password(&self, create: bool) -> Result<Zeroizing<Vec<u8>>> {
        let mut cached = self
            .cached
            .lock()
            .map_err(|_| anyhow::anyhow!("encryption password cache is unavailable"))?;
        if let Some(password) = cached.as_ref() {
            return Ok(Zeroizing::new(password.to_vec()));
        }

        let item = match self.item()? {
            Some(item) => item,
            None if create => {
                self.create_item()?;
                self.item()?
                    .context("1Password encryption password readback failed")?
            }
            None => bail!("encryption password is missing from 1Password"),
        };
        let password = self.read_item_password(item)?;
        *cached = Some(Zeroizing::new(password.to_vec()));
        Ok(password)
    }

    fn remove(&self) -> Result<()> {
        let Some(item) = self.item()? else {
            return Ok(());
        };
        let output = self.runner.run(&[
            "item".to_owned(),
            "delete".to_owned(),
            item.id,
            format!("--vault={}", item.vault.id),
        ])?;
        ensure!(output.success, ONE_PASSWORD_UNAVAILABLE);
        Ok(())
    }
}

fn parse_one_password_output(mut password: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    while matches!(password.last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    ensure!(
        !password.contains(&b'\n') && !password.contains(&b'\r'),
        "1Password returned a malformed encryption password"
    );
    validate_password(&password)
        .context("1Password contains an invalid Attached encryption password")?;
    Ok(password)
}

#[cfg(not(test))]
static USER_PASSWORD_STORE: LazyLock<
    PasswordMasterKeyStore<UserPasswordProvider<TtyPasswordPrompt>>,
> = LazyLock::new(|| PasswordMasterKeyStore {
    passwords: UserPasswordProvider {
        prompt: TtyPasswordPrompt,
        cached: Mutex::new(None),
    },
});

#[cfg(not(test))]
static STDIN_PASSWORD_STORE: LazyLock<
    PasswordMasterKeyStore<UserPasswordProvider<StdinPasswordPrompt>>,
> = LazyLock::new(|| PasswordMasterKeyStore {
    passwords: UserPasswordProvider {
        prompt: StdinPasswordPrompt,
        cached: Mutex::new(None),
    },
});

#[cfg(not(test))]
static ONE_PASSWORD_STORE: LazyLock<PasswordMasterKeyStore<OnePasswordProvider<ProcessOpRunner>>> =
    LazyLock::new(|| PasswordMasterKeyStore {
        passwords: OnePasswordProvider {
            runner: ProcessOpRunner {
                executable: PathBuf::from("op"),
            },
            cached: Mutex::new(None),
        },
    });

// Uninstall deliberately preserves a shared 1Password-managed password because
// custom state directories and other computers are undiscoverable. Keep the
// safe removal primitive for any future explicit password-reset operation.
#[allow(dead_code)]
pub(crate) fn remove_master_key(store: &dyn MasterKeyStore) -> Result<()> {
    remove_master_key_at(&coordination_dir()?, store)
}

fn remove_master_key_at(coordination: &Path, store: &dyn MasterKeyStore) -> Result<()> {
    crate::secure_state::with_exclusive_lock(coordination, MASTER_KEY_LOCK, |_| {
        store
            .remove()
            .map_err(|_| anyhow::anyhow!("encryption password cleanup failed"))?;
        tracing::info!(
            event = "local_master_key_removed",
            "removed managed encryption password"
        );
        Ok(())
    })
}

pub(crate) fn load_or_create_master_key(
    directory: &crate::secure_state::StateDir,
    store: &dyn MasterKeyStore,
    create: bool,
) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>> {
    store.load_or_create(directory, create)
}

pub(crate) fn with_master_key<T>(
    directory: &crate::secure_state::StateDir,
    create: bool,
    operation: impl FnOnce(&[u8; 32]) -> Result<T>,
) -> Result<T> {
    let coordination = coordination_dir()?;
    with_master_key_store_at(directory, &coordination, active_store(), create, operation)
}

pub(crate) fn with_key_coordination<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let coordination = coordination_dir()?;
    crate::secure_state::with_exclusive_lock(&coordination, MASTER_KEY_LOCK, |_| operation())
}

pub(crate) fn with_master_key_store<T>(
    directory: &crate::secure_state::StateDir,
    store: &dyn MasterKeyStore,
    create: bool,
    operation: impl FnOnce(&[u8; 32]) -> Result<T>,
) -> Result<T> {
    let coordination = coordination_dir()?;
    with_master_key_store_at(directory, &coordination, store, create, operation)
}

fn with_master_key_store_at<T>(
    directory: &crate::secure_state::StateDir,
    coordination: &Path,
    store: &dyn MasterKeyStore,
    create: bool,
    operation: impl FnOnce(&[u8; 32]) -> Result<T>,
) -> Result<T> {
    crate::secure_state::with_exclusive_lock(coordination, MASTER_KEY_LOCK, |_| {
        let key = load_or_create_master_key(directory, store, create)?;
        operation(&key)
    })
}

pub(crate) fn coordination_dir() -> Result<PathBuf> {
    #[cfg(test)]
    {
        let temporary_root = std::fs::canonicalize(std::env::temp_dir())
            .context("could not resolve the test coordination directory")?;
        Ok(temporary_root.join(format!(
            "{COORDINATION_DIRECTORY}-{}",
            rustix::process::geteuid().as_raw()
        )))
    }
    #[cfg(not(test))]
    {
        Ok(coordination_dir_for_home(Path::new("/ignored")))
    }
}

pub(crate) fn coordination_dir_for_home(_home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    let temporary_root = Path::new("/private/var/tmp");
    #[cfg(not(target_os = "macos"))]
    let temporary_root = Path::new("/var/tmp");
    temporary_root.join(format!(
        "{COORDINATION_DIRECTORY}-{}",
        rustix::process::geteuid().as_raw()
    ))
}

pub(crate) const fn stored_limit(plaintext_limit: usize) -> usize {
    HEADER_BYTES + TAG_BYTES + plaintext_limit
}

#[cfg(not(test))]
pub(crate) fn active_store() -> &'static dyn MasterKeyStore {
    if USE_ONE_PASSWORD.load(Ordering::SeqCst) {
        &*ONE_PASSWORD_STORE
    } else if USE_PASSWORD_STDIN.load(Ordering::SeqCst) {
        &*STDIN_PASSWORD_STORE
    } else {
        &*USER_PASSWORD_STORE
    }
}

#[cfg(test)]
pub(crate) fn active_store() -> &'static dyn MasterKeyStore {
    struct FixedTestStore;

    impl MasterKeyStore for FixedTestStore {
        fn load_or_create(
            &self,
            _directory: &crate::secure_state::StateDir,
            _create: bool,
        ) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>> {
            Ok(Zeroizing::new([0x9d; MASTER_KEY_BYTES]))
        }
    }

    static STORE: FixedTestStore = FixedTestStore;
    &STORE
}

#[derive(Clone, Copy)]
pub(crate) enum Purpose {
    AdminIdentity,
    SyncAccount,
    SyncCatalog,
}

impl Purpose {
    const fn aad(self) -> &'static [u8] {
        match self {
            Self::AdminIdentity => b"attached/local-secret/v1/admin-identity",
            Self::SyncAccount => b"attached/local-secret/v1/sync-account",
            Self::SyncCatalog => b"attached/local-secret/v1/sync-catalog",
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::AdminIdentity => "admin_identity",
            Self::SyncAccount => "sync_account",
            Self::SyncCatalog => "sync_catalog",
        }
    }
}

pub(crate) fn is_envelope(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub(crate) fn has_envelope_shape(bytes: &[u8]) -> bool {
    is_envelope(bytes) || bytes.len() >= HEADER_BYTES + TAG_BYTES
}

pub(crate) fn seal(
    key: &[u8; 32],
    purpose: Purpose,
    plaintext: &[u8],
    plaintext_limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        plaintext.len() <= plaintext_limit,
        "local secret plaintext exceeds configured limit"
    );
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce_bytes).context("operating-system randomness is unavailable")?;
    let cipher = ChaCha20Poly1305::new(key.into());
    let aad = associated_data(purpose);
    let nonce = Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("could not construct local secret nonce"))?;
    let mut ciphertext = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_BYTES));
    ciphertext.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place(&nonce, &aad, &mut *ciphertext)
        .map_err(|_| anyhow::anyhow!("could not encrypt local secret"))?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + ciphertext.len()));
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub(crate) fn open(
    key: &[u8; 32],
    purpose: Purpose,
    envelope: &[u8],
    plaintext_limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let maximum = HEADER_BYTES
        .checked_add(plaintext_limit)
        .and_then(|length| length.checked_add(TAG_BYTES))
        .context("local secret size limit is invalid")?;
    ensure!(
        envelope.len() <= maximum,
        "encrypted local secret exceeds configured limit"
    );
    ensure!(
        envelope.len() >= HEADER_BYTES + TAG_BYTES,
        "encrypted local secret is truncated"
    );
    ensure!(
        envelope.get(..MAGIC.len()) == Some(MAGIC),
        "encrypted local secret has invalid format"
    );
    if envelope[MAGIC.len()] != VERSION {
        bail!("encrypted local secret uses an unsupported version");
    }
    let nonce_start = MAGIC.len() + 1;
    let nonce_end = nonce_start + NONCE_BYTES;
    let cipher = ChaCha20Poly1305::new(key.into());
    let aad = associated_data(purpose);
    let nonce = Nonce::try_from(&envelope[nonce_start..nonce_end])
        .map_err(|_| anyhow::anyhow!("encrypted local secret has invalid nonce"))?;
    let mut plaintext = Zeroizing::new(envelope[nonce_end..].to_vec());
    cipher
        .decrypt_in_place(&nonce, &aad, &mut *plaintext)
        .map_err(|_| anyhow::anyhow!("encrypted local secret authentication failed"))?;
    ensure!(
        plaintext.len() <= plaintext_limit,
        "decrypted local secret exceeds configured limit"
    );
    Ok(plaintext)
}

fn associated_data(purpose: Purpose) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + 1 + purpose.aad().len());
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.extend_from_slice(purpose.aad());
    aad
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        os::unix::fs::PermissionsExt as _,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            mpsc,
        },
    };

    use super::*;

    struct FakePrompt {
        responses: Mutex<VecDeque<Vec<u8>>>,
        prompts: Mutex<Vec<String>>,
    }

    impl FakePrompt {
        fn new(responses: impl IntoIterator<Item = &'static str>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|response| response.as_bytes().to_vec())
                        .collect(),
                ),
                prompts: Mutex::new(Vec::new()),
            }
        }
    }

    impl PasswordPrompt for FakePrompt {
        fn read_password(&self, prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
            self.prompts.lock().unwrap().push(prompt.to_owned());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .map(Zeroizing::new)
                .context("fake password prompt has no response")
        }
    }

    struct FixedPasswordProvider(&'static [u8]);

    impl PasswordProvider for FixedPasswordProvider {
        fn password(&self, _create: bool) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(self.0.to_vec()))
        }
    }

    #[derive(Debug)]
    struct RecordedOpCall {
        arguments: Vec<String>,
    }

    struct FakeOpRunner {
        outputs: Mutex<VecDeque<Result<OpOutput>>>,
        calls: Mutex<Vec<RecordedOpCall>>,
    }

    impl FakeOpRunner {
        fn with_outputs(outputs: impl IntoIterator<Item = OpOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().map(Ok).collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl OpRunner for FakeOpRunner {
        fn run(&self, arguments: &[String]) -> Result<OpOutput> {
            self.calls.lock().unwrap().push(RecordedOpCall {
                arguments: arguments.to_vec(),
            });
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .expect("the fake op runner has a queued response")
        }
    }

    fn successful_op_output(stdout: impl AsRef<[u8]>) -> OpOutput {
        OpOutput {
            success: true,
            stdout: Zeroizing::new(stdout.as_ref().to_vec()),
        }
    }

    #[test]
    fn user_password_creation_prompts_for_confirmation_and_caches_the_result() {
        let provider = UserPasswordProvider {
            prompt: FakePrompt::new([
                "correct horse battery staple",
                "correct horse battery staple",
            ]),
            cached: Mutex::new(None),
        };

        let first = provider.password(true).unwrap();
        let second = provider.password(false).unwrap();

        assert_eq!(first.as_slice(), b"correct horse battery staple");
        assert_eq!(second.as_slice(), first.as_slice());
        assert_eq!(provider.prompt.prompts.lock().unwrap().len(), 2);
    }

    #[test]
    fn mismatched_or_empty_user_passwords_are_rejected_without_caching() {
        let mismatch = UserPasswordProvider {
            prompt: FakePrompt::new(["first password", "different password"]),
            cached: Mutex::new(None),
        };
        let error = mismatch.password(true).unwrap_err().to_string();
        assert!(error.contains("do not match"), "{error}");
        assert!(mismatch.cached.lock().unwrap().is_none());

        let empty = UserPasswordProvider {
            prompt: FakePrompt::new([""]),
            cached: Mutex::new(None),
        };
        let error = empty.password(false).unwrap_err().to_string();
        assert!(error.contains("cannot be empty"), "{error}");
    }

    #[test]
    fn password_stdin_reader_accepts_one_bounded_line() {
        assert_eq!(
            read_password_line(&mut &b"correct horse battery staple\n"[..])
                .unwrap()
                .as_slice(),
            b"correct horse battery staple"
        );
        assert_eq!(
            read_password_line(&mut &b"windows line\r\n"[..])
                .unwrap()
                .as_slice(),
            b"windows line"
        );
        assert!(read_password_line(&mut &b"\n"[..]).is_err());
        assert!(read_password_line(&mut vec![b'x'; MAX_PASSWORD_BYTES + 1].as_slice()).is_err());
    }

    #[test]
    fn production_kdf_parameters_remain_memory_hard() {
        assert_eq!(PRODUCTION_KDF_MEMORY_KIB, 19 * 1024);
        assert_eq!(PRODUCTION_KDF_ITERATIONS, 2);
        assert_eq!(KDF_PARALLELISM, 1);
    }

    #[test]
    fn password_kdf_is_deterministic_and_bound_to_password_and_salt() {
        let password = b"correct horse battery staple";
        let salt = [0x41; KDF_SALT_BYTES];
        let first = derive_master_key(password, &salt).unwrap();
        let second = derive_master_key(password, &salt).unwrap();
        let other_password = derive_master_key(b"different password", &salt).unwrap();
        let other_salt = derive_master_key(password, &[0x42; KDF_SALT_BYTES]).unwrap();

        assert_eq!(first, second);
        assert_ne!(first, other_password);
        assert_ne!(first, other_salt);
    }

    #[test]
    fn password_store_creates_and_reuses_an_owner_only_local_salt() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        crate::secure_state::prepare_private_dir(&state).unwrap();
        let directory = crate::secure_state::StateDir::open(&state).unwrap();
        let store = PasswordMasterKeyStore {
            passwords: FixedPasswordProvider(b"correct horse battery staple"),
        };

        let first = store.load_or_create(&directory, true).unwrap();
        let second = store.load_or_create(&directory, false).unwrap();

        assert_eq!(first, second);
        let stored_salt = std::fs::read(state.join(KDF_SALT_FILE)).unwrap();
        assert_eq!(stored_salt.len(), KDF_SALT_BYTES);
        assert!(!stored_salt.windows(8).any(|window| window == b"correct "));
        assert_eq!(
            std::fs::metadata(state.join(KDF_SALT_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn one_password_provider_reads_and_caches_the_concealed_password() {
        let item_id = "abcdefghijklmnopqrstuvwx12";
        let vault_id = "abcdefghijklmnopqrstuvwx34";
        let password = "generated-1Password-secret";
        let listed = serde_json::json!([{
            "id": item_id,
            "title": ONE_PASSWORD_ITEM_TITLE,
            "vault": { "id": vault_id },
        }]);
        let runner = FakeOpRunner::with_outputs([
            successful_op_output(serde_json::to_vec(&listed).unwrap()),
            successful_op_output(format!("{password}\n")),
        ]);
        let provider = OnePasswordProvider {
            runner,
            cached: Mutex::new(None),
        };

        assert_eq!(
            provider.password(false).unwrap().as_slice(),
            password.as_bytes()
        );
        assert_eq!(
            provider.password(false).unwrap().as_slice(),
            password.as_bytes()
        );

        let calls = provider.runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(
            calls[0]
                .arguments
                .iter()
                .any(|argument| { argument == &format!("--tags={ONE_PASSWORD_ITEM_TAG}") })
        );
        assert!(
            calls[1]
                .arguments
                .iter()
                .any(|argument| argument == item_id)
        );
        assert!(
            calls[1]
                .arguments
                .iter()
                .any(|argument| argument == &format!("--vault={vault_id}"))
        );
        assert!(calls.iter().all(|call| {
            call.arguments
                .iter()
                .all(|argument| !argument.contains(password))
        }));
    }

    #[test]
    fn one_password_provider_requests_an_auto_generated_password() {
        let item_id = "abcdefghijklmnopqrstuvwx12";
        let vault_id = "abcdefghijklmnopqrstuvwx34";
        let listed = serde_json::json!([{
            "id": item_id,
            "title": ONE_PASSWORD_ITEM_TITLE,
            "vault": { "id": vault_id },
        }]);
        let provider = OnePasswordProvider {
            runner: FakeOpRunner::with_outputs([
                successful_op_output(b"[]"),
                successful_op_output(b""),
                successful_op_output(serde_json::to_vec(&listed).unwrap()),
                successful_op_output(b"generated-password\n"),
            ]),
            cached: Mutex::new(None),
        };

        assert_eq!(
            provider.password(true).unwrap().as_slice(),
            b"generated-password"
        );

        let calls = provider.runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        let create = &calls[1].arguments;
        assert!(create.iter().any(|argument| argument == "create"));
        assert!(
            create
                .iter()
                .any(|argument| { argument == "--generate-password=letters,digits,symbols,64" })
        );
    }

    #[test]
    fn one_password_provider_reports_unavailable_cli_without_backend_details() {
        let provider = OnePasswordProvider {
            runner: FakeOpRunner::with_outputs([OpOutput {
                success: false,
                stdout: Zeroizing::new(b"synthetic sensitive backend detail".to_vec()),
            }]),
            cached: Mutex::new(None),
        };

        let error = provider.password(false).unwrap_err().to_string();

        assert!(error.contains("unlock or sign in"), "{error}");
        assert!(!error.contains("synthetic sensitive"), "{error}");
    }

    #[test]
    fn one_password_provider_rejects_duplicate_managed_items() {
        let listed = serde_json::json!([
            {
                "id": "abcdefghijklmnopqrstuvwx12",
                "title": ONE_PASSWORD_ITEM_TITLE,
                "vault": { "id": "abcdefghijklmnopqrstuvwx34" },
            },
            {
                "id": "abcdefghijklmnopqrstuvwx13",
                "title": ONE_PASSWORD_ITEM_TITLE,
                "vault": { "id": "abcdefghijklmnopqrstuvwx34" },
            },
        ]);
        let provider = OnePasswordProvider {
            runner: FakeOpRunner::with_outputs([successful_op_output(
                serde_json::to_vec(&listed).unwrap(),
            )]),
            cached: Mutex::new(None),
        };

        let error = provider.password(false).unwrap_err().to_string();

        assert!(
            error.contains("multiple Attached encryption password items"),
            "{error}"
        );
    }

    #[test]
    fn coordination_namespace_is_independent_of_home() {
        assert_eq!(
            coordination_dir_for_home(Path::new("/home/first")),
            coordination_dir_for_home(Path::new("/different/home"))
        );
        assert!(coordination_dir_for_home(Path::new("relative-home")).is_absolute());
    }

    #[test]
    fn key_removal_waits_for_in_flight_key_use() {
        struct RemovableStore {
            removed: mpsc::Sender<()>,
        }
        impl MasterKeyStore for RemovableStore {
            fn load_or_create(
                &self,
                _directory: &crate::secure_state::StateDir,
                _create: bool,
            ) -> Result<Zeroizing<[u8; 32]>> {
                Ok(Zeroizing::new([0x42; 32]))
            }
            fn remove(&self) -> Result<()> {
                self.removed.send(()).unwrap();
                Ok(())
            }
        }

        let root = crate::test_support::canonical_tempdir();
        let coordination = root.path().join("coordination");
        let state = root.path().join("state");
        crate::secure_state::prepare_private_dir(&state).unwrap();
        let directory = crate::secure_state::StateDir::open(&state).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (removed_tx, removed_rx) = mpsc::channel();
        let store = Arc::new(RemovableStore {
            removed: removed_tx,
        });

        let user = {
            let store = Arc::clone(&store);
            let coordination = coordination.clone();
            std::thread::spawn(move || {
                with_master_key_store_at(&directory, &coordination, store.as_ref(), false, |_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
            })
        };
        entered_rx.recv().unwrap();
        let remover = {
            let store = Arc::clone(&store);
            let coordination = coordination.clone();
            std::thread::spawn(move || remove_master_key_at(&coordination, store.as_ref()).unwrap())
        };
        assert!(
            removed_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        release_tx.send(()).unwrap();
        user.join().unwrap();
        remover.join().unwrap();
        removed_rx.recv().unwrap();
    }

    #[test]
    fn encrypted_envelope_roundtrips_without_plaintext_at_rest() {
        let key = [0x11; 32];
        let plaintext = b"recognizable-private-material";

        let envelope = seal(&key, Purpose::AdminIdentity, plaintext, 1024).unwrap();

        assert!(
            !envelope
                .windows(plaintext.len())
                .any(|bytes| bytes == plaintext)
        );
        assert_eq!(
            open(&key, Purpose::AdminIdentity, &envelope, 1024)
                .unwrap()
                .as_slice(),
            plaintext
        );
    }

    #[test]
    fn cross_directory_first_use_is_serialized_in_a_global_namespace() {
        let root = crate::test_support::canonical_tempdir();
        let coordination = root.path().join("coordination");
        let first_state = root.path().join("first-state");
        let second_state = root.path().join("second-state");
        crate::secure_state::prepare_private_dir(&first_state).unwrap();
        crate::secure_state::prepare_private_dir(&second_state).unwrap();

        struct ControlledStore {
            calls: AtomicUsize,
            entered: mpsc::Sender<()>,
            release_first: Mutex<mpsc::Receiver<()>>,
        }
        impl MasterKeyStore for ControlledStore {
            fn load_or_create(
                &self,
                _directory: &crate::secure_state::StateDir,
                _create: bool,
            ) -> Result<Zeroizing<[u8; 32]>> {
                let call = self.calls.fetch_add(1, AtomicOrdering::SeqCst);
                self.entered.send(()).unwrap();
                if call == 0 {
                    self.release_first.lock().unwrap().recv().unwrap();
                }
                Ok(Zeroizing::new([0x42; 32]))
            }
        }
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let store = Arc::new(ControlledStore {
            calls: AtomicUsize::new(0),
            entered: entered_tx,
            release_first: Mutex::new(release_rx),
        });
        let spawn = |state: std::path::PathBuf| {
            let coordination = coordination.clone();
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                let directory = crate::secure_state::StateDir::open(&state).unwrap();
                with_master_key_store_at(&directory, &coordination, store.as_ref(), true, |key| {
                    Ok(*key)
                })
                .unwrap()
            })
        };
        let first_worker = spawn(first_state);
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let second_worker = spawn(second_state);
        assert!(
            entered_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        release_tx.send(()).unwrap();
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let first = first_worker.join().unwrap();
        let second = second_worker.join().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn envelope_rejects_wrong_key_tampering_truncation_oversize_version_and_aad_swap() {
        let key = [0x23; 32];
        let plaintext = b"do-not-leak-this-secret";
        let envelope = seal(&key, Purpose::AdminIdentity, plaintext, 128).unwrap();

        assert!(open(&[0x24; 32], Purpose::AdminIdentity, &envelope, 128).is_err());
        assert!(open(&key, Purpose::SyncAccount, &envelope, 128).is_err());

        for offset in [MAGIC.len() + 1, HEADER_BYTES] {
            let mut tampered = envelope.to_vec();
            tampered[offset] ^= 1;
            assert!(open(&key, Purpose::AdminIdentity, &tampered, 128).is_err());
        }

        let truncated = &envelope[..HEADER_BYTES + TAG_BYTES - 1];
        assert!(open(&key, Purpose::AdminIdentity, truncated, 128).is_err());

        let mut oversized = envelope.to_vec();
        oversized.extend_from_slice(&[0; 129]);
        assert!(open(&key, Purpose::AdminIdentity, &oversized, 128).is_err());

        let mut future = envelope.to_vec();
        future[MAGIC.len()] = VERSION + 1;
        let error = open(&key, Purpose::AdminIdentity, &future, 128)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unsupported version"), "{error}");

        for error in [
            open(&[0x24; 32], Purpose::AdminIdentity, &envelope, 128).unwrap_err(),
            open(&key, Purpose::SyncCatalog, &envelope, 128).unwrap_err(),
        ] {
            let diagnostic = format!("{error:?} {error}");
            assert!(!diagnostic.contains("do-not-leak-this-secret"));
            assert!(!diagnostic.contains("35, 35, 35"));
        }
    }

    #[test]
    fn independent_seals_use_distinct_random_nonces() {
        let key = [0x31; 32];
        let first = seal(&key, Purpose::SyncCatalog, b"same", 4).unwrap();
        let second = seal(&key, Purpose::SyncCatalog, b"same", 4).unwrap();
        assert_ne!(first, second);
    }
}
