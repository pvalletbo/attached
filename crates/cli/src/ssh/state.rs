use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use russh::keys::{PrivateKey, ssh_key::private::Ed25519Keypair};
use serde::{Deserialize, Serialize};
use uzers::os::unix::UserExt;
use zeroize::Zeroizing;

use crate::{
    local_encryption::{self, Purpose},
    secure_state::{self, StateDir},
    sync,
};

const POLICY: &str = "ssh-access.json";
const HOST_KEY: &str = "ssh-host.key";

/// Account-level consent, never inferred from an ordinary tunnel capability.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    pub consumer: [u8; 32],
    pub uid: u32,
    pub username: String,
    pub home: PathBuf,
    pub shell: PathBuf,
    pub generation: [u8; 32],
    pub enabled: bool,
}

pub(super) fn policy(path: &Path, consumer: &[u8; 32]) -> Result<Policy> {
    let bytes = StateDir::open(path)?
        .read_secret_bounded(POLICY, 8192)
        .context("SSH access is disabled; run `attached ssh-access enable` on the publisher")?;
    let policy: Policy = serde_json::from_slice(&bytes)?;
    ensure!(
        policy.enabled
            && &policy.consumer == consumer
            && policy.uid == rustix::process::geteuid().as_raw(),
        "SSH access is disabled or belongs to another consumer/account"
    );
    Ok(policy)
}

pub(crate) fn set_access(path: &Path, enabled: bool) -> Result<()> {
    let account = sync::state::load_account(path, ApiKeyScope::Publish)?;
    let consumer = *account
        .authorized_consumer_identity()
        .context("publish bundle has no consumer identity")?
        .as_bytes();
    let user = uzers::get_user_by_uid(rustix::process::geteuid().as_raw())
        .context("could not resolve publisher OS account")?;
    let username = user
        .name()
        .to_str()
        .context("OS username is not UTF-8")?
        .to_owned();
    ensure!(
        !username.is_empty()
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
        "unsupported OS username"
    );
    let mut generation = [0; 32];
    getrandom::fill(&mut generation)?;
    let policy = Policy {
        consumer,
        uid: user.uid(),
        username,
        home: user.home_dir().to_owned(),
        shell: user.shell().to_owned(),
        generation,
        enabled,
    };
    ensure!(
        policy.shell.is_absolute() && policy.home.is_absolute(),
        "account shell and home must be absolute paths"
    );
    secure_state::with_exclusive_lock(path, "ssh-access.lock", |dir| {
        dir.atomic_replace(POLICY, &serde_json::to_vec(&policy)?)
    })?;
    if enabled {
        eprintln!(
            "SSH enabled: the configured consumer may execute arbitrary commands as {} (uid {}). Permission persists until `attached ssh-access disable`. Existing sessions are cancelled when permission changes.",
            policy.username, policy.uid
        );
    } else {
        eprintln!(
            "SSH disabled. Active sessions will be cancelled within one second; deliberately detached processes cannot be recalled."
        );
    }
    Ok(())
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
    fn publisher_consent_is_explicit_persistent_and_revocable() {
        let root = crate::test_support::canonical_tempdir();
        let creator = root.path().join("creator");
        let publisher = root.path().join("publisher");
        sync::state::test_support::create_account(&creator, "https://sync.example").unwrap();
        let bundle = sync::account::export(&creator, ApiKeyScope::Publish).unwrap();
        sync::state::import_account(&publisher, bundle.as_bytes()).unwrap();
        let consumer = iroh::SecretKey::from_bytes(&[0x43; 32]).public();
        assert!(policy(&publisher, consumer.as_bytes()).is_err());
        set_access(&publisher, true).unwrap();
        let enabled = policy(&publisher, consumer.as_bytes()).unwrap();
        assert_eq!(enabled.uid, rustix::process::geteuid().as_raw());
        assert_eq!(enabled, policy(&publisher, consumer.as_bytes()).unwrap());
        assert!(policy(&publisher, &[0; 32]).is_err());
        set_access(&publisher, false).unwrap();
        assert!(policy(&publisher, consumer.as_bytes()).is_err());
        set_access(&publisher, true).unwrap();
        assert_ne!(
            enabled.generation,
            policy(&publisher, consumer.as_bytes()).unwrap().generation
        );
    }
}
