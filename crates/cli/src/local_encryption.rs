use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce, aead::AeadInOut as _};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ATSECR01";
const VERSION: u8 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = MAGIC.len() + 1 + NONCE_BYTES;
#[cfg(not(test))]
const KEYRING_SERVICE: &str = "com.pvalletbo.attached";
#[cfg(not(test))]
const KEYRING_ACCOUNT: &str = "local-state-master-key-v1";
const COORDINATION_DIRECTORY: &str = "attached-keyring";
const MASTER_KEY_LOCK: &str = "local-master-key.lock";

pub(crate) trait MasterKeyStore: Send + Sync {
    fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>>;
    fn store(&self, key: &[u8; 32]) -> Result<()>;
    fn remove(&self) -> Result<()> {
        bail!("OS credential store is unavailable")
    }
}

#[cfg(not(test))]
struct OsKeyringStore;

#[cfg(not(test))]
impl MasterKeyStore for OsKeyringStore {
    fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .map_err(|_| anyhow::anyhow!("OS credential store is unavailable"))?;
        let bytes = match entry.get_secret() {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(_) => bail!("OS credential store is unavailable"),
        };
        ensure!(
            bytes.len() == 32,
            "OS credential store contains an invalid local encryption key"
        );
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Ok(Some(key))
    }

    fn store(&self, key: &[u8; 32]) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .map_err(|_| anyhow::anyhow!("OS credential store is unavailable"))?;
        entry
            .set_secret(key)
            .map_err(|_| anyhow::anyhow!("OS credential store is unavailable"))
    }

    fn remove(&self) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .map_err(|_| anyhow::anyhow!("OS credential store is unavailable"))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => bail!("OS credential store is unavailable"),
        }
    }
}

// Uninstall deliberately preserves this shared key today because custom state
// directories are undiscoverable. Keep the safe removal primitive for any
// future explicit key-reset operation.
#[allow(dead_code)]
pub(crate) fn remove_master_key(store: &dyn MasterKeyStore) -> Result<()> {
    remove_master_key_at(&coordination_dir()?, store)
}

fn remove_master_key_at(coordination: &Path, store: &dyn MasterKeyStore) -> Result<()> {
    crate::secure_state::with_exclusive_lock(coordination, MASTER_KEY_LOCK, |_| {
        store
            .remove()
            .map_err(|_| anyhow::anyhow!("OS credential store cleanup failed; rerun uninstall"))?;
        tracing::info!(
            event = "local_master_key_removed",
            "removed managed OS credential"
        );
        Ok(())
    })
}

pub(crate) fn load_or_create_master_key(
    store: &dyn MasterKeyStore,
    create: bool,
) -> Result<Zeroizing<[u8; 32]>> {
    let existing = store
        .load()
        .map_err(|_| anyhow::anyhow!("OS credential store is unavailable"))?;
    if let Some(existing) = existing {
        return Ok(existing);
    }
    ensure!(
        create,
        "local encryption key is missing from the OS credential store"
    );
    let mut candidate = Zeroizing::new([0u8; 32]);
    getrandom::fill(candidate.as_mut()).context(
        "operating-system randomness is unavailable while creating local encryption key",
    )?;
    store
        .store(&candidate)
        .map_err(|_| anyhow::anyhow!("OS credential store is unavailable"))?;
    let persisted = store
        .load()
        .map_err(|_| anyhow::anyhow!("OS credential store is unavailable"))?
        .context("local encryption key readback verification failed")?;
    ensure!(
        *persisted == *candidate,
        "local encryption key readback verification failed"
    );
    tracing::info!(
        event = "local_master_key_created",
        "created machine-local encryption credential"
    );
    Ok(persisted)
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
    _directory: &crate::secure_state::StateDir,
    coordination: &Path,
    store: &dyn MasterKeyStore,
    create: bool,
    operation: impl FnOnce(&[u8; 32]) -> Result<T>,
) -> Result<T> {
    crate::secure_state::with_exclusive_lock(coordination, MASTER_KEY_LOCK, |_| {
        let key = load_or_create_master_key(store, create)?;
        operation(&key)
    })
}

pub(crate) fn coordination_dir() -> Result<PathBuf> {
    Ok(coordination_dir_for_home(Path::new("/ignored")))
}

pub(crate) fn coordination_dir_for_home(_home: &Path) -> PathBuf {
    Path::new("/var/tmp").join(format!(
        "{COORDINATION_DIRECTORY}-{}",
        rustix::process::geteuid().as_raw()
    ))
}

pub(crate) const fn stored_limit(plaintext_limit: usize) -> usize {
    HEADER_BYTES + TAG_BYTES + plaintext_limit
}

#[cfg(not(test))]
pub(crate) fn active_store() -> &'static dyn MasterKeyStore {
    &OsKeyringStore
}

#[cfg(test)]
pub(crate) fn active_store() -> &'static dyn MasterKeyStore {
    struct FixedTestStore;

    impl MasterKeyStore for FixedTestStore {
        fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
            Ok(Some(Zeroizing::new([0x9d; 32])))
        }

        fn store(&self, _key: &[u8; 32]) -> Result<()> {
            unreachable!("the deterministic test key is always present")
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
    use std::sync::{Arc, Mutex, mpsc};

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        key: Mutex<Option<[u8; 32]>>,
        unavailable: bool,
        mismatch_after_store: bool,
    }

    impl MasterKeyStore for MemoryStore {
        fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
            if self.unavailable {
                bail!("synthetic unavailable");
            }
            Ok(self.key.lock().unwrap().map(Zeroizing::new))
        }

        fn store(&self, key: &[u8; 32]) -> Result<()> {
            if self.unavailable {
                bail!("synthetic unavailable");
            }
            let stored = if self.mismatch_after_store {
                [0x77; 32]
            } else {
                *key
            };
            *self.key.lock().unwrap() = Some(stored);
            Ok(())
        }
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
            key: Mutex<Option<[u8; 32]>>,
            removed: mpsc::Sender<()>,
        }
        impl MasterKeyStore for RemovableStore {
            fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
                Ok(self.key.lock().unwrap().map(Zeroizing::new))
            }
            fn store(&self, _: &[u8; 32]) -> Result<()> {
                unreachable!()
            }
            fn remove(&self) -> Result<()> {
                *self.key.lock().unwrap() = None;
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
            key: Mutex::new(Some([0x42; 32])),
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
    fn master_key_creation_requires_matching_keyring_readback() {
        let store = MemoryStore {
            mismatch_after_store: true,
            ..MemoryStore::default()
        };

        let error = load_or_create_master_key(&store, true)
            .unwrap_err()
            .to_string();

        assert!(error.contains("readback verification failed"), "{error}");
        assert!(!error.contains("119"), "error disclosed key bytes: {error}");
    }

    #[test]
    fn unavailable_keyring_is_actionable_and_does_not_disclose_store_error_details() {
        let store = MemoryStore {
            unavailable: true,
            ..MemoryStore::default()
        };

        let error = load_or_create_master_key(&store, true)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("OS credential store is unavailable"),
            "{error}"
        );
        assert!(!error.contains("synthetic unavailable"), "{error}");
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
            key: Mutex<Option<[u8; 32]>>,
            first_store_entered: mpsc::Sender<()>,
            release_first_store: Mutex<mpsc::Receiver<()>>,
            loads_after_first_store: mpsc::Sender<()>,
        }
        impl MasterKeyStore for ControlledStore {
            fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
                let key = *self.key.lock().unwrap();
                if key.is_none() {
                    let _ = self.loads_after_first_store.send(());
                }
                Ok(key.map(Zeroizing::new))
            }
            fn store(&self, key: &[u8; 32]) -> Result<()> {
                self.first_store_entered.send(()).unwrap();
                self.release_first_store.lock().unwrap().recv().unwrap();
                *self.key.lock().unwrap() = Some(*key);
                Ok(())
            }
        }
        let (store_entered_tx, store_entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (load_tx, load_rx) = mpsc::channel();
        let store = Arc::new(ControlledStore {
            key: Mutex::new(None),
            first_store_entered: store_entered_tx,
            release_first_store: Mutex::new(release_rx),
            loads_after_first_store: load_tx,
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
        store_entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        while load_rx.try_recv().is_ok() {}
        let second_worker = spawn(second_state);
        assert!(
            load_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        release_tx.send(()).unwrap();
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
