use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::process::diagnostic;

#[derive(Default, Deserialize, Serialize)]
pub(crate) struct State {
    pub seen: BTreeSet<String>,
    pub pending: BTreeMap<String, String>,
}

impl State {
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .context("invalid discovery state; refusing to overwrite it"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).context("could not read discovery state"),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path.parent().context("state path has no parent")?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(file.as_file_mut(), self)?;
        file.as_file().sync_all()?;
        file.persist(path)
            .context("could not save discovery state")?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct Log {
    directory: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl Log {
    pub fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_owned(),
            lock: Arc::default(),
        }
    }

    pub fn record(&self, message: impl AsRef<str>) {
        let Ok(_guard) = self.lock.lock() else {
            return;
        };
        let _ = (|| -> Result<()> {
            let path = self.directory.join("discovery.log");
            if fs::metadata(&path).is_ok_and(|m| m.len() >= 256 * 1024) {
                fs::rename(&path, self.directory.join("discovery.log.1"))?;
            }
            let mut file = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(path)?;
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            writeln!(file, "{time} {}", diagnostic(message.as_ref()))?;
            Ok(())
        })();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn state_roundtrips_privately_and_corruption_is_not_treated_as_empty() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.json");
        let mut state = State::load(&path).unwrap();
        state.seen.insert("identity".into());
        state.pending.insert("identity".into(), "Office".into());
        state.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap().pending["identity"], "Office");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::write(&path, "invalid").unwrap();
        assert!(State::load(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "invalid");
    }

    #[test]
    fn logs_are_bounded_and_strip_terminal_controls() {
        let temp = tempfile::tempdir().unwrap();
        let log = Log::new(temp.path());
        for _ in 0..300 {
            log.record(format!("\x1b{}", "x".repeat(4000)));
        }
        for name in ["discovery.log", "discovery.log.1"] {
            let bytes = fs::read(temp.path().join(name)).unwrap();
            assert!(bytes.len() < 260 * 1024);
            assert!(!bytes.contains(&0x1b));
        }
    }
}
