use std::{
    fs::File,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use fs4::{FileExt, TryLockError};
use rustix::process::geteuid;

use crate::secure_state::StateDir;

pub struct ActiveEndpoint {
    file: File,
}

impl Drop for ActiveEndpoint {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub fn default_dir() -> Result<PathBuf> {
    let temp_root = std::fs::canonicalize(std::env::temp_dir())
        .context("could not canonicalize the temporary directory")?;
    dir_for_temp_root(&temp_root, geteuid().as_raw())
}

fn dir_for_temp_root(temp_root: &Path, effective_uid: u32) -> Result<PathBuf> {
    ensure!(
        temp_root.is_absolute(),
        "temporary directory must be absolute"
    );
    ensure!(
        temp_root.components().all(|component| matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )),
        "temporary directory is not canonical"
    );
    ensure!(
        temp_root
            .components()
            .any(|component| matches!(component, std::path::Component::Normal(_))),
        "temporary directory must not be the filesystem root"
    );
    Ok(temp_root
        .join(format!("attached-{effective_uid}"))
        .join("live-endpoints"))
}

pub fn register(registry_dir: &Path, endpoint_identity: [u8; 32]) -> Result<ActiveEndpoint> {
    let directory = open_registry_dir(registry_dir)?;
    let name = marker_name(endpoint_identity);
    let file = directory
        .open_private_lock_file(&name, true)?
        .expect("creation requested");
    FileExt::try_lock(&file)
        .map_err(|error| anyhow::anyhow!("endpoint is already registered: {error}"))?;
    directory.verify_locked_file(registry_dir, &name, &file)?;
    Ok(ActiveEndpoint { file })
}

pub fn is_active(registry_dir: &Path, endpoint_identity: [u8; 32]) -> Result<bool> {
    let directory = open_registry_dir(registry_dir)?;
    let name = marker_name(endpoint_identity);
    let Some(file) = directory.open_private_lock_file(&name, false)? else {
        return Ok(false);
    };
    match FileExt::try_lock(&file) {
        Err(TryLockError::WouldBlock) => {
            directory.verify_locked_file(registry_dir, &name, &file)?;
            Ok(true)
        }
        Err(TryLockError::Error(error)) => Err(error).context("failed to probe endpoint marker"),
        Ok(()) => {
            directory.verify_locked_file(registry_dir, &name, &file)?;
            FileExt::unlock(&file).context("failed to unlock endpoint marker")?;
            Ok(false)
        }
    }
}

fn open_registry_dir(registry_dir: &Path) -> Result<StateDir> {
    let user_root = registry_dir
        .parent()
        .context("endpoint registry has no private user root")?;
    // Validate the predictable per-user component before creating or trusting a
    // child below it. In a shared sticky temporary directory, another user can
    // precreate this pathname but cannot satisfy owner-only StateDir validation.
    let _root =
        StateDir::open(user_root).context("local endpoint registry user root is not private")?;
    StateDir::open(registry_dir).context("local endpoint registry is not private")
}

fn marker_name(endpoint_identity: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut name = String::with_capacity(64 + ".lock".len());
    for byte in endpoint_identity {
        write!(&mut name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    name.push_str(".lock");
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_path_is_home_independent_and_scoped_by_effective_user() {
        let temp = Path::new("/private/runtime/tmp");

        let first = dir_for_temp_root(temp, 1001).unwrap();
        let second = dir_for_temp_root(temp, 1002).unwrap();

        assert_eq!(first, temp.join("attached-1001/live-endpoints"));
        assert_ne!(first, second);
        assert!(dir_for_temp_root(Path::new("relative"), 1001).is_err());
        assert!(dir_for_temp_root(Path::new("/tmp/../unsafe"), 1001).is_err());
    }

    #[test]
    fn registry_creation_never_shadows_default_or_custom_state() {
        let root = crate::test_support::canonical_tempdir();
        let temp_root = root.path().join("runtime");
        std::fs::create_dir(&temp_root).unwrap();
        let registry = dir_for_temp_root(&temp_root, 1001).unwrap();

        let fresh_home = root.path().join("fresh-home");
        std::fs::create_dir(&fresh_home).unwrap();
        let default_state = crate::identity::state_dir_for_home(&fresh_home).unwrap();
        let custom_state = root.path().join("custom-account-state");
        assert_ne!(registry, default_state);
        assert_ne!(registry, custom_state);
        let guard = register(&registry, [0x83; 32]).unwrap();
        assert_eq!(
            crate::identity::state_dir_for_home(&fresh_home).unwrap(),
            default_state
        );
        drop(guard);

        let legacy_home = root.path().join("legacy-home");
        let ignored_legacy_state = legacy_home.join(".config/obsolete-attached-state");
        std::fs::create_dir_all(&ignored_legacy_state).unwrap();
        let default_state = legacy_home.join(".config/attached");
        assert_eq!(
            crate::identity::state_dir_for_home(&legacy_home).unwrap(),
            default_state
        );
        let _guard = register(&registry, [0x84; 32]).unwrap();
        assert_eq!(
            crate::identity::state_dir_for_home(&legacy_home).unwrap(),
            default_state
        );
        assert!(!default_state.exists());
    }

    #[test]
    fn attacker_precreated_user_registry_root_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::test_support::canonical_tempdir();
        let user_root = root.path().join("attached-1001");
        let registry = user_root.join("live-endpoints");
        std::fs::create_dir(&user_root).unwrap();
        std::fs::set_permissions(&user_root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = match register(&registry, [0x91; 32]) {
            Ok(_) => panic!("unsafe parent was accepted"),
            Err(error) => format!("{error:#}"),
        };

        assert!(error.contains("expected 0700"), "{error}");
        assert!(!registry.exists(), "unsafe parent gained a registry child");
    }

    #[test]
    fn active_exact_endpoint_is_detected() {
        let root = crate::test_support::canonical_tempdir();
        let registry = root.path().join("attached-1001/live-endpoints");
        let identity = [0x5a; 32];

        let _guard = register(&registry, identity).unwrap();

        assert!(is_active(&registry, identity).unwrap());
    }

    #[test]
    fn dropped_guard_leaves_an_inactive_stale_marker() {
        let root = crate::test_support::canonical_tempdir();
        let registry = root.path().join("attached-1001/live-endpoints");
        let identity = [0xa5; 32];
        let guard = register(&registry, identity).unwrap();
        assert!(is_active(&registry, identity).unwrap());

        drop(guard);

        assert!(!is_active(&registry, identity).unwrap());
        let marker = marker_name(identity);
        assert!(
            registry.join(marker).is_file(),
            "marker pathname was deleted"
        );
    }

    #[test]
    fn registry_and_canonical_marker_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::test_support::canonical_tempdir();
        let registry = root.path().join("attached-1001/live-endpoints");
        let identity = [0x0f; 32];
        let _guard = register(&registry, identity).unwrap();
        let expected = format!("{}.lock", "0f".repeat(32));
        let names = std::fs::read_dir(&registry)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();

        assert_eq!(names, [std::ffi::OsString::from(expected)]);
        assert_eq!(
            std::fs::metadata(&registry).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(registry.join(marker_name(identity)))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}
