use std::{fs::File, path::Path};

use anyhow::{Context, Result, ensure};
use fs4::{FileExt, TryLockError};
use sha2::{Digest, Sha256};

use crate::secure_state::StateDir;

fn marker(endpoint: [u8; 32], session: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"attached/interactive-session/v1\0");
    digest.update(endpoint);
    digest.update(session.as_bytes());
    let hash: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("interactive-{hash}.lock")
}

pub struct Guard(File);

impl Drop for Guard {
    fn drop(&mut self) {
        // Explicit unlock also releases a lock briefly inherited by a concurrently
        // forked child before its exec closes CLOEXEC descriptors.
        let _ = FileExt::unlock(&self.0);
    }
}

// Shared locks allow multiple interactive clients. Kernel-owned locks disappear
// on crash; marker contents contain no credentials or session labels.
pub fn attach(state_dir: &Path, endpoint: [u8; 32], session: &str) -> Result<Guard> {
    let directory = StateDir::open(state_dir)?;
    let name = marker(endpoint, session);
    let file = directory
        .open_private_lock_file(&name, true)?
        .expect("creation requested");
    FileExt::lock_shared(&file).context("could not register interactive attachment")?;
    let guard = Guard(file);
    directory.verify_locked_file(state_dir, &name, &guard.0)?;
    Ok(guard)
}

pub fn is_attached(state_dir: &Path, endpoint: [u8; 32], session: &str) -> Result<bool> {
    let directory = StateDir::open(state_dir)?;
    let name = marker(endpoint, session);
    let Some(file) = directory.open_private_lock_file(&name, false)? else {
        return Ok(false);
    };
    directory.verify_locked_file(state_dir, &name, &file)?;
    match FileExt::try_lock(&file) {
        Ok(()) => {
            FileExt::unlock(&file).context("could not unlock attachment probe")?;
            Ok(false)
        }
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(error)) => {
            Err(error).context("could not inspect interactive attachment")
        }
    }
}

pub fn singleton(state_dir: &Path) -> Result<Guard> {
    let directory = StateDir::open(state_dir)?;
    let name = "notifications-watch.lock";
    let file = directory
        .open_private_lock_file(name, true)?
        .expect("creation requested");
    ensure!(
        FileExt::try_lock(&file).is_ok(),
        "a notification watcher is already running for this state directory"
    );
    let guard = Guard(file);
    directory.verify_locked_file(state_dir, name, &guard.0)?;
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiple_attachments_and_crash_safe_markers() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        let a = attach(&state, [1; 32], "work").unwrap();
        let b = attach(&state, [1; 32], "work").unwrap();
        assert!(is_attached(&state, [1; 32], "work").unwrap());
        assert!(!is_attached(&state, [1; 32], "other").unwrap());
        assert!(!is_attached(&state, [2; 32], "work").unwrap());
        drop(a);
        assert!(is_attached(&state, [1; 32], "work").unwrap());
        drop(b);
        assert!(!is_attached(&state, [1; 32], "work").unwrap());
        let watcher = singleton(&state).unwrap();
        assert!(singleton(&state).is_err());
        drop(watcher);
        assert!(singleton(&state).is_ok());
    }
}
