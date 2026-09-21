//! Installation, singleton ownership, and Attached exporter lifecycle.
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use fs4::FileExt;
use tokio::{io::AsyncReadExt, process::Command};

use crate::{
    INTERVAL,
    attached::{CliAttached, DiscoverySource},
    discovery::Reconciler,
    herdr::Herdr,
    process::ChildGroup,
    state::Log,
};

pub(crate) fn executable(root: &Path) -> PathBuf {
    root.join("../../target/release/attached-herdr-plugin")
}

pub(crate) fn identity(path: &Path) -> Result<(u64, u64)> {
    let metadata = path.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

fn try_lock(path: &Path) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    match FileExt::try_lock(&file) {
        Ok(()) => Ok(Some(file)),
        Err(fs4::TryLockError::WouldBlock) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn exporter_running(home: &Path) -> Result<bool> {
    let path = home.join(".ssh/attached/broker.lock");
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    match FileExt::try_lock(&file) {
        Ok(()) => Ok(false),
        Err(fs4::TryLockError::WouldBlock) => Ok(true),
        Err(error) => Err(error.into()),
    }
}

#[derive(Default)]
struct Exporter {
    child: Option<ChildGroup>,
    reader: Option<tokio::task::JoinHandle<()>>,
}

impl Exporter {
    async fn ensure(&mut self, home: &Path, attached: &CliAttached, log: &Log) -> Result<()> {
        if let Some(child) = &mut self.child {
            if child.child.try_wait()?.is_none() {
                return Ok(());
            }
            self.stop().await;
        }
        // Attached's own lock also protects the race between this check/spawn.
        // Never terminate or take ownership of a user's existing exporter.
        if exporter_running(home)? {
            return Ok(());
        }
        let mut command = Command::new(&attached.binary);
        command
            .arg("export-ssh-config")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = ChildGroup::spawn(&mut command)?;
        let mut stderr = child
            .child
            .stderr
            .take()
            .context("missing exporter stderr")?;
        let log = log.clone();
        self.reader = Some(tokio::spawn(async move {
            let mut buffer = [0; 4096];
            while let Ok(count) = stderr.read(&mut buffer).await {
                if count == 0 {
                    break;
                }
                log.record(format!(
                    "SSH exporter: {}",
                    String::from_utf8_lossy(&buffer[..count])
                ));
            }
        }));
        self.child = Some(child);
        Ok(())
    }

    async fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.stop().await;
        }
        if let Some(reader) = self.reader.take() {
            reader.abort();
            let _ = reader.await;
        }
    }
}

pub(crate) fn launch(args: &[String]) -> Result<()> {
    // Spawn returns only after the OS has opened the executable. Install may now
    // move the checkout without racing an interpreter opening its script later.
    std::process::Command::new(std::env::current_exe()?)
        .args(args)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}

pub(crate) async fn await_registration(herdr: &Herdr, expected: (u64, u64), deadline: Duration) {
    // Builds have no runtime plugin context. Wait for the new checkout to be
    // committed (not an older install), then ask a running session for context.
    let _ = tokio::time::timeout(deadline, async {
        loop {
            let result = async {
                let Some(plugin) = herdr.plugin().await? else {
                    return Ok(false);
                };
                if !plugin.enabled
                    || !plugin.warnings.is_empty()
                    || identity(&executable(&plugin.plugin_root))? != expected
                {
                    return Ok(false);
                }
                for session in herdr.sessions().await? {
                    if session.running {
                        herdr.ensure_in_session(&session.name).await?;
                        return Ok(true);
                    }
                }
                // No server now: the manifest startup hook handles its next start.
                Ok::<_, anyhow::Error>(true)
            }
            .await;
            if matches!(result, Ok(true)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
}

pub(crate) async fn worker() -> Result<()> {
    let directory = PathBuf::from(
        std::env::var_os("HERDR_PLUGIN_STATE_DIR")
            .context("Herdr did not provide HERDR_PLUGIN_STATE_DIR")?,
    );
    std::fs::create_dir_all(&directory)?;
    let Some(lock) = try_lock(&directory.join("discovery.lock"))? else {
        return Ok(());
    };
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    let original = identity(&std::env::current_exe()?)?;
    let log = Log::new(&directory);
    let herdr = Herdr::default();
    let attached = CliAttached::default();
    let mut reconciler = Reconciler::new(&directory, log.clone());
    let mut exporter = Exporter::default();
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    log.record("Automatic Attached discovery started");
    let run = async {
        loop {
            let result = async {
                let Some(plugin) = herdr.plugin().await? else {
                    return Ok(Some(None));
                };
                if !plugin.warnings.is_empty() {
                    bail!("plugin manifest is unavailable: {:?}", plugin.warnings);
                }
                let next = executable(&plugin.plugin_root);
                if identity(&next)? != original {
                    return Ok(Some(Some(next)));
                }
                if plugin.enabled {
                    let hosts = attached.hosts().await?;
                    exporter.ensure(&home, &attached, &log).await?;
                    reconciler.poll(&hosts, &attached, &herdr).await?;
                } else {
                    // Keep a dormant worker so re-enable resumes without an action.
                    exporter.stop().await;
                }
                Ok::<_, anyhow::Error>(None)
            }
            .await;
            match result {
                Ok(Some(next)) => break next,
                Ok(None) => {}
                Err(error) => log.record(format!("Discovery will retry: {error:#}")),
            }
            tokio::time::sleep(INTERVAL).await;
        }
    };
    let replacement = tokio::select! {
        next = run => next,
        _ = interrupt.recv() => None,
        _ = terminate.recv() => None,
        _ = hangup.recv() => None,
    };
    exporter.stop().await;
    log.record("Automatic Attached discovery stopped");
    drop(lock);
    if let Some(next) = replacement {
        // A reinstall replaced the binary. Never keep executing the old checkout.
        std::process::Command::new(next)
            .arg("ensure")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_and_external_exporter_locks_do_not_rely_on_stale_pids() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("discovery.lock");
        let first = try_lock(&path).unwrap().unwrap();
        assert!(try_lock(&path).unwrap().is_none());
        drop(first);
        assert!(try_lock(&path).unwrap().is_some());
        assert!(!exporter_running(home.path()).unwrap());
        let ssh = home.path().join(".ssh/attached");
        std::fs::create_dir_all(&ssh).unwrap();
        let owner = try_lock(&ssh.join("broker.lock")).unwrap().unwrap();
        assert!(exporter_running(home.path()).unwrap());
        drop(owner);
        assert!(!exporter_running(home.path()).unwrap());
    }

    #[test]
    fn manifest_starts_at_install_and_startup_and_builds_only_the_rust_plugin() {
        let manifest: toml::Value =
            toml::from_str(include_str!("../../../plugins/herdr/herdr-plugin.toml")).unwrap();
        assert_eq!(manifest["id"].as_str(), Some(crate::PLUGIN_ID));
        let build = manifest["build"].as_array().unwrap();
        assert_eq!(build.len(), 2);
        assert_eq!(build[0]["command"][0].as_str(), Some("cargo"));
        assert_eq!(build[1]["command"][1].as_str(), Some("install"));
        assert_eq!(
            manifest["startup"][0]["command"][1].as_str(),
            Some("ensure")
        );
        assert_eq!(manifest["actions"][0]["id"].as_str(), Some("ensure"));
    }
}
