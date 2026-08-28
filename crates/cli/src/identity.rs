use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use iroh::SecretKey;
use zeroize::Zeroizing;

use crate::{
    local_encryption::{
        MasterKeyStore, Purpose, active_store, is_envelope, open, seal, stored_limit,
        with_master_key_store,
    },
    secure_state::{StateDir, prepare_private_dir, with_exclusive_lock},
};

// Keep the existing filename so upgraded hosts retain their Iroh identity.
const IDENTITY_FILE: &str = "admin-identity.key";
const IDENTITY_BYTES: usize = 32;
const MAX_STORED_IDENTITY_BYTES: usize = stored_limit(IDENTITY_BYTES);
const STATE_DIRECTORY: &str = "attached";

pub fn default_state_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    state_dir_for_home(Path::new(&home))
}

pub(crate) fn state_dir_for_home(home: &Path) -> Result<PathBuf> {
    ensure!(!home.as_os_str().is_empty(), "HOME is empty");
    Ok(home.join(".config").join(STATE_DIRECTORY))
}

pub fn load_or_create(state_dir: &Path) -> Result<SecretKey> {
    load_or_create_with_store(state_dir, active_store())
}

fn load_or_create_with_store(state_dir: &Path, store: &dyn MasterKeyStore) -> Result<SecretKey> {
    prepare_private_dir(state_dir)?;
    let lock_name = format!("{IDENTITY_FILE}.lock");
    with_exclusive_lock(state_dir, &lock_name, |directory| {
        if let Some(bytes) =
            directory.read_secret_optional_bounded(IDENTITY_FILE, MAX_STORED_IDENTITY_BYTES)?
        {
            return load_identity(directory, store, bytes, true);
        }

        let secret = SecretKey::generate();
        let serialized = Zeroizing::new(secret.to_bytes());
        let installed = with_master_key_store(directory, store, true, |key| {
            let encrypted = seal(key, Purpose::AdminIdentity, &serialized[..], IDENTITY_BYTES)?;
            directory.create_noclobber(IDENTITY_FILE, &encrypted)
        })?;
        if installed {
            Ok(secret)
        } else {
            load_identity(
                directory,
                store,
                directory.read_secret_bounded(IDENTITY_FILE, MAX_STORED_IDENTITY_BYTES)?,
                true,
            )
        }
    })
}

fn load_identity(
    directory: &StateDir,
    store: &dyn MasterKeyStore,
    bytes: Zeroizing<Vec<u8>>,
    migrate_legacy: bool,
) -> Result<SecretKey> {
    if bytes.len() != IDENTITY_BYTES && is_envelope(&bytes) {
        let plaintext = with_master_key_store(directory, store, false, |key| {
            open(key, Purpose::AdminIdentity, &bytes, IDENTITY_BYTES)
        })?;
        return load_identity_bytes(&plaintext);
    }
    let identity = load_identity_bytes(&bytes)?;
    if migrate_legacy {
        with_master_key_store(directory, store, true, |key| {
            let encrypted = seal(key, Purpose::AdminIdentity, &bytes, IDENTITY_BYTES)?;
            directory.atomic_replace(IDENTITY_FILE, &encrypted)
        })?;
        tracing::info!(
            event = "local_secret_migrated",
            purpose = Purpose::AdminIdentity.name(),
            "migrated legacy local secret to encrypted storage"
        );
    }
    Ok(identity)
}

fn load_identity_bytes(bytes: &[u8]) -> Result<SecretKey> {
    ensure!(
        bytes.len() == IDENTITY_BYTES,
        "identity file has {} bytes, expected {IDENTITY_BYTES}",
        bytes.len()
    );
    let mut key = Zeroizing::new([0u8; IDENTITY_BYTES]);
    key.copy_from_slice(bytes);
    Ok(SecretKey::from_bytes(&key))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    struct FixedStore([u8; 32]);

    impl crate::local_encryption::MasterKeyStore for FixedStore {
        fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
            Ok(Some(Zeroizing::new(self.0)))
        }

        fn store(&self, _key: &[u8; 32]) -> Result<()> {
            unreachable!("fixed test key already exists")
        }
    }

    struct MissingStore;

    impl crate::local_encryption::MasterKeyStore for MissingStore {
        fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
            Ok(None)
        }

        fn store(&self, _key: &[u8; 32]) -> Result<()> {
            unreachable!("decrypt must not create a missing key")
        }
    }

    struct UnavailableStore;

    impl crate::local_encryption::MasterKeyStore for UnavailableStore {
        fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
            anyhow::bail!("synthetic unavailable")
        }

        fn store(&self, _key: &[u8; 32]) -> Result<()> {
            anyhow::bail!("synthetic unavailable")
        }
    }

    struct PanicStore;

    impl crate::local_encryption::MasterKeyStore for PanicStore {
        fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
            panic!("corrupt legacy input must be rejected before key access")
        }

        fn store(&self, _key: &[u8; 32]) -> Result<()> {
            panic!("corrupt legacy input must not be rewritten")
        }
    }

    #[test]
    fn default_state_always_uses_the_attached_name() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            state_dir_for_home(home.path()).unwrap(),
            home.path().join(".config/attached")
        );

        let legacy = home.path().join(".config/obsolete-attached-state");
        fs::create_dir_all(&legacy).unwrap();
        assert_eq!(
            state_dir_for_home(home.path()).unwrap(),
            home.path().join(".config/attached")
        );
    }

    #[test]
    fn identity_is_reused_and_owner_only() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        let first = load_or_create(&state).unwrap();
        let second = load_or_create(&state).unwrap();
        assert_eq!(first.public(), second.public());
        let stored = fs::read(state.join(IDENTITY_FILE)).unwrap();
        assert!(crate::local_encryption::is_envelope(&stored));
        assert!(!stored.windows(32).any(|bytes| bytes == first.to_bytes()));
        assert_eq!(
            fs::metadata(state.join(IDENTITY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn corrupt_identity_is_rejected_without_replacement() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        fs::write(state.join(IDENTITY_FILE), b"short").unwrap();
        fs::set_permissions(state.join(IDENTITY_FILE), fs::Permissions::from_mode(0o600)).unwrap();

        assert!(load_or_create_with_store(&state, &PanicStore).is_err());
        assert_eq!(fs::read(state.join(IDENTITY_FILE)).unwrap(), b"short");
    }

    #[test]
    fn legacy_plaintext_identity_migrates_and_preserves_public_identity() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let legacy = SecretKey::from_bytes(&[0x5a; IDENTITY_BYTES]);
        fs::write(state.join(IDENTITY_FILE), legacy.to_bytes()).unwrap();
        fs::set_permissions(state.join(IDENTITY_FILE), fs::Permissions::from_mode(0o600)).unwrap();

        let loaded = load_or_create_with_store(&state, &FixedStore([0x33; 32])).unwrap();

        assert_eq!(loaded.public(), legacy.public());
        let migrated = fs::read(state.join(IDENTITY_FILE)).unwrap();
        assert!(crate::local_encryption::is_envelope(&migrated));
        assert_ne!(migrated, legacy.to_bytes());
    }

    #[test]
    fn legacy_identity_whose_prefix_equals_envelope_magic_is_still_migrated() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let mut legacy_bytes = [0x5a; IDENTITY_BYTES];
        legacy_bytes[..8].copy_from_slice(b"ATSECR01");
        let legacy = SecretKey::from_bytes(&legacy_bytes);
        fs::write(state.join(IDENTITY_FILE), legacy_bytes).unwrap();
        fs::set_permissions(state.join(IDENTITY_FILE), fs::Permissions::from_mode(0o600)).unwrap();

        let loaded = load_or_create_with_store(&state, &FixedStore([0x33; 32])).unwrap();

        assert_eq!(loaded.public(), legacy.public());
        assert!(crate::local_encryption::is_envelope(
            &fs::read(state.join(IDENTITY_FILE)).unwrap()
        ));
    }

    #[test]
    fn key_store_and_decrypt_failures_leave_identity_file_byte_exact() {
        let root = crate::test_support::canonical_tempdir();

        let unavailable_state = root.path().join("unavailable");
        prepare_private_dir(&unavailable_state).unwrap();
        let legacy = SecretKey::from_bytes(&[0x61; IDENTITY_BYTES]).to_bytes();
        fs::write(unavailable_state.join(IDENTITY_FILE), legacy).unwrap();
        fs::set_permissions(
            unavailable_state.join(IDENTITY_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(load_or_create_with_store(&unavailable_state, &UnavailableStore).is_err());
        assert_eq!(
            fs::read(unavailable_state.join(IDENTITY_FILE)).unwrap(),
            legacy
        );

        let encrypted_state = root.path().join("encrypted");
        load_or_create_with_store(&encrypted_state, &FixedStore([0x71; 32])).unwrap();
        let envelope = fs::read(encrypted_state.join(IDENTITY_FILE)).unwrap();

        assert!(load_or_create_with_store(&encrypted_state, &MissingStore).is_err());
        assert_eq!(
            fs::read(encrypted_state.join(IDENTITY_FILE)).unwrap(),
            envelope
        );

        assert!(load_or_create_with_store(&encrypted_state, &FixedStore([0x72; 32])).is_err());
        assert_eq!(
            fs::read(encrypted_state.join(IDENTITY_FILE)).unwrap(),
            envelope
        );
    }
}
