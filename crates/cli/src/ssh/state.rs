use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use russh::keys::{PrivateKey, ssh_key::private::Ed25519Keypair};
use zeroize::Zeroizing;

use crate::{
    local_encryption::{self, Purpose},
    secure_state, sync,
};

const HOST_KEY: &str = "ssh-host.key";

/// SSH authorization derived from the publish bundle and effective OS account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Policy {
    pub consumer: [u8; 32],
    pub uid: u32,
    pub username: String,
    pub home: PathBuf,
    pub shell: PathBuf,
}

pub(super) fn authorize(path: &Path, consumer: &[u8; 32]) -> Result<()> {
    let account = sync::state::load_account(path, ApiKeyScope::Publish)?;
    let authorized = account
        .authorized_consumer_identity()
        .context("publish bundle has no consumer identity")?;
    ensure!(
        authorized.as_bytes() == consumer,
        "SSH access belongs to another consumer"
    );
    Ok(())
}

pub(super) fn policy(path: &Path, consumer: &[u8; 32]) -> Result<Policy> {
    authorize(path, consumer)?;
    let user = super::account::lookup(rustix::process::geteuid().as_raw())?;
    Ok(Policy {
        consumer: *consumer,
        uid: user.uid,
        username: user.username,
        home: user.home,
        shell: user.shell,
    })
}

pub(super) fn key_from_seed(seed: &[u8; 32]) -> Result<PrivateKey> {
    Ok(PrivateKey::new(
        Ed25519Keypair::from_seed(seed).into(),
        "attached",
    )?)
}

pub(super) fn ephemeral_key() -> Result<PrivateKey> {
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *seed)?;
    key_from_seed(&seed)
}

pub(super) fn host_key(path: &Path, master: &[u8; 32]) -> Result<PrivateKey> {
    secure_state::with_exclusive_lock_until(
        path,
        "ssh-host.lock",
        std::time::Instant::now() + std::time::Duration::from_secs(5),
        |dir| {
            let seed = match dir
                .read_secret_optional_bounded(HOST_KEY, local_encryption::stored_limit(32))?
            {
                Some(bytes) => local_encryption::open(master, Purpose::SshHost, &bytes, 32)?,
                None => {
                    let mut seed = Zeroizing::new(vec![0; 32]);
                    getrandom::fill(&mut seed)?;
                    dir.atomic_replace(
                        HOST_KEY,
                        &local_encryption::seal(master, Purpose::SshHost, &seed, 32)?,
                    )?;
                    seed
                }
            };
            key_from_seed(
                seed.as_slice()
                    .try_into()
                    .context("invalid SSH host key seed")?,
            )
        },
    )
}

pub(super) fn pin_host(
    path: &Path,
    peer: &iroh::EndpointId,
    username: &str,
    host_key: &str,
    trust_new_host_key: bool,
) -> Result<()> {
    let pin = (username.to_owned(), host_key.to_owned());
    secure_state::with_exclusive_lock(path, "ssh-pins.lock", |dir| {
        let mut pins: BTreeMap<String, (String, String)> =
            match dir.read_secret_optional_bounded("ssh-pins.json", 1024 * 1024)? {
                Some(bytes) => serde_json::from_slice(&bytes)?,
                None => BTreeMap::new(),
            };
        if let Some(previous) = pins.get(&peer.to_string()) {
            ensure!(
                previous == &pin || trust_new_host_key,
                "publisher SSH identity changed; verify the publisher, then deliberately rerun `attached ssh --trust-new-host-key {peer}`"
            );
            if previous == &pin {
                return Ok(());
            }
        }
        pins.insert(peer.to_string(), pin);
        let bytes = serde_json::to_vec(&pins)?;
        ensure!(bytes.len() <= 1024 * 1024, "SSH host pin storage is full");
        dir.atomic_replace("ssh-pins.json", &bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_state::StateDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn host_keys_are_encrypted_private_persistent_and_fail_closed() {
        let root = crate::test_support::canonical_tempdir();
        secure_state::prepare_private_dir(root.path()).unwrap();
        let master = [8; 32];
        let first = host_key(root.path(), &master).unwrap();
        assert_eq!(
            first.public_key(),
            host_key(root.path(), &master).unwrap().public_key()
        );
        let bytes = std::fs::read(root.path().join(HOST_KEY)).unwrap();
        assert!(local_encryption::is_envelope(&bytes));
        assert_eq!(
            std::fs::metadata(root.path().join(HOST_KEY))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(host_key(root.path(), &[7; 32]).is_err());
        assert_eq!(std::fs::read(root.path().join(HOST_KEY)).unwrap(), bytes);
        StateDir::open(root.path())
            .unwrap()
            .atomic_replace(HOST_KEY, b"corrupt")
            .unwrap();
        assert!(host_key(root.path(), &master).is_err());
        assert_eq!(
            std::fs::read(root.path().join(HOST_KEY)).unwrap(),
            b"corrupt"
        );
    }

    #[test]
    fn host_pins_require_explicit_rotation_and_are_scoped_to_stable_identity() {
        let root = crate::test_support::canonical_tempdir();
        secure_state::prepare_private_dir(root.path()).unwrap();
        let first = iroh::SecretKey::generate().public();
        let second = iroh::SecretKey::generate().public();
        pin_host(root.path(), &first, "account", "key-one", false).unwrap();
        pin_host(root.path(), &first, "account", "key-one", false).unwrap();
        assert!(pin_host(root.path(), &first, "account", "key-two", false).is_err());
        assert!(pin_host(root.path(), &first, "root", "key-one", false).is_err());
        pin_host(root.path(), &second, "account", "key-two", false).unwrap();
        pin_host(root.path(), &first, "account", "key-two", true).unwrap();
        pin_host(root.path(), &first, "account", "key-two", false).unwrap();
    }

    #[test]
    fn ssh_is_automatic_for_the_publish_bundles_consumer_and_effective_account() {
        let root = crate::test_support::canonical_tempdir();
        let creator = root.path().join("creator");
        let publisher = root.path().join("publisher");
        sync::state::test_support::create_account(&creator, "https://sync.example").unwrap();
        let bundle = sync::account::export(&creator, ApiKeyScope::Publish).unwrap();
        sync::state::import_account(&publisher, bundle.as_bytes()).unwrap();
        let consumer = iroh::SecretKey::from_bytes(&[0x43; 32]).public();
        let enabled = policy(&publisher, consumer.as_bytes()).unwrap();
        let user = super::super::account::lookup(rustix::process::geteuid().as_raw()).unwrap();
        assert_eq!(enabled.uid, user.uid);
        assert_eq!(enabled.username, user.username);
        assert_eq!(enabled.home, user.home);
        assert_eq!(enabled.shell, user.shell);
        assert_eq!(enabled, policy(&publisher, consumer.as_bytes()).unwrap());
        assert!(!publisher.join("ssh-access.json").exists());
        assert!(policy(&publisher, &[0; 32]).is_err());
        assert!(policy(&creator, consumer.as_bytes()).is_err());

        let downloader = root.path().join("downloader");
        let bundle = sync::account::export(&creator, ApiKeyScope::Download).unwrap();
        sync::state::import_account(&downloader, bundle.as_bytes()).unwrap();
        assert!(policy(&downloader, consumer.as_bytes()).is_err());

        // Obsolete opt-in state is ignored, including a previously disabled policy.
        let dir = StateDir::open(&publisher).unwrap();
        let disabled = serde_json::to_vec(&serde_json::json!({
            "consumer": consumer.as_bytes(), "uid": enabled.uid,
            "username": enabled.username, "home": enabled.home, "shell": enabled.shell,
            "generation": vec![1; 32], "enabled": false,
        }))
        .unwrap();
        for legacy in [disabled.as_slice(), b"corrupt"] {
            dir.atomic_replace("ssh-access.json", legacy).unwrap();
            assert_eq!(enabled, policy(&publisher, consumer.as_bytes()).unwrap());
        }
        dir.atomic_replace("sync-account.bundle", b"corrupt")
            .unwrap();
        assert!(policy(&publisher, consumer.as_bytes()).is_err());
        std::fs::remove_file(publisher.join("sync-account.bundle")).unwrap();
        assert!(policy(&publisher, consumer.as_bytes()).is_err());
    }
}
