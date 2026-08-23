use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use iroh::SecretKey;

use crate::secure_state::{prepare_private_dir, with_exclusive_lock};

// Keep the existing filename so upgraded hosts retain their Iroh identity.
const IDENTITY_FILE: &str = "admin-identity.key";
const IDENTITY_BYTES: usize = 32;
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
    prepare_private_dir(state_dir)?;
    let lock_name = format!("{IDENTITY_FILE}.lock");
    with_exclusive_lock(state_dir, &lock_name, |directory| {
        if let Some(bytes) = directory.read_optional_bounded(IDENTITY_FILE, IDENTITY_BYTES)? {
            return load_identity_bytes(bytes);
        }

        let secret = SecretKey::generate();
        let serialized = secret.to_bytes();
        if directory.create_noclobber(IDENTITY_FILE, &serialized)? {
            Ok(secret)
        } else {
            load_identity_bytes(directory.read_bounded(IDENTITY_FILE, IDENTITY_BYTES)?)
        }
    })
}

fn load_identity_bytes(bytes: Vec<u8>) -> Result<SecretKey> {
    ensure!(
        bytes.len() == IDENTITY_BYTES,
        "identity file has {} bytes, expected {IDENTITY_BYTES}",
        bytes.len()
    );
    let mut key = [0u8; IDENTITY_BYTES];
    key.copy_from_slice(&bytes);
    Ok(SecretKey::from_bytes(&key))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

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

        assert!(load_or_create(&state).is_err());
        assert_eq!(fs::read(state.join(IDENTITY_FILE)).unwrap(), b"short");
    }
}
