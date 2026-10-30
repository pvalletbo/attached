//! A leased, singleton worker for the desktop mod. No legacy Herdr socket,
//! plugin registry or credentials are needed by the mod's JavaScript runtime.
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    INTERVAL,
    attached::CliAttached,
    core::Core,
    discovery::Reconciler,
    lifecycle::{self, Exporter},
    state::{Log, State, save_json},
};

const LEASE_SECONDS: u64 = 90;

#[derive(Deserialize, Serialize)]
struct Lease {
    checked_at: u64,
    enabled: bool,
    install_core: bool,
}

impl Lease {
    fn active(&self, now: u64) -> bool {
        self.enabled
            && now
                .checked_sub(self.checked_at)
                .is_some_and(|age| age <= LEASE_SECONDS)
    }
}

#[derive(Default, Deserialize, Serialize)]
struct Status {
    running: bool,
    checked_at: Option<u64>,
    managed: usize,
    error: Option<String>,
    notices: Vec<Notice>,
}

#[derive(Deserialize, Serialize)]
struct Notice {
    id: String,
    label: String,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn load<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path)?).with_context(|| format!("invalid {}", path.display()))
}

fn status(directory: &Path) -> Result<Status> {
    let path = directory.join("status.json");
    if path.exists() {
        load(&path)
    } else {
        Ok(Status::default())
    }
}

pub(crate) fn heartbeat(directory: &Path, enabled: bool, install_core: bool) -> Result<()> {
    ensure!(
        directory.is_absolute(),
        "app state directory must be absolute"
    );
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    let mut current = status(directory)?;
    save_json(
        &directory.join("lease.json"),
        &Lease {
            checked_at: now()?,
            enabled,
            install_core,
        },
    )?;
    // An OS lock, not a PID, decides ownership. Races between windows may spawn
    // two candidates; only one can hold the lock and touch the registry/exporter.
    if let Some(lock) = lifecycle::try_lock(&directory.join("discovery.lock"))? {
        current.running = false;
        drop(lock);
        if enabled {
            lifecycle::launch(&["app-run".into(), directory.to_string_lossy().into_owned()])?;
        }
    } else {
        current.running = true;
    }
    println!("{}", serde_json::to_string(&current)?);
    Ok(())
}

async fn until_inactive(directory: &Path) {
    loop {
        if !load::<Lease>(&directory.join("lease.json"))
            .and_then(|lease| Ok(lease.active(now()?)))
            .unwrap_or(false)
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub(crate) async fn worker(directory: &Path) -> Result<()> {
    let Some(_lock) = lifecycle::try_lock(&directory.join("discovery.lock"))? else {
        return Ok(());
    };
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    let log = Log::new(directory);
    let attached = CliAttached::default();
    let mut exporter = Exporter::default();
    let mut reconciler = Reconciler::new(directory, log.clone());
    let mut current = status(directory)?;
    // A previous worker's status must not be mistaken for this worker's check.
    current.running = true;
    current.checked_at = None;
    save_json(&directory.join("status.json"), &current)?;
    log.record("Herdr app discovery started");
    let run = async {
        loop {
            let lease: Lease = load(&directory.join("lease.json"))?;
            if !lease.active(now()?) {
                break;
            }
            let core = Core::new(lease.install_core);
            let result = async {
                exporter.ensure(&home, &attached, &log).await?;
                let discovery = attached.hosts()?;
                reconciler.check(&discovery, &attached, &core).await
            }
            .await;
            current.checked_at = Some(now()?);
            current.error = match result {
                Ok(()) => core.error.into_inner(),
                Err(error) => {
                    reconciler.reset_absences();
                    Some(format!("{error:#}"))
                }
            };
            if let Some(error) = &current.error {
                log.record(error);
            }
            current.managed = State::load(&directory.join("discovery-state.json"))?
                .managed
                .len();
            for (index, label) in core.notices.into_inner().into_iter().enumerate() {
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
                current.notices.push(Notice {
                    id: format!("{timestamp}-{index}"),
                    label,
                });
            }
            if current.notices.len() > 32 {
                current.notices.drain(..current.notices.len() - 32);
            }
            save_json(&directory.join("status.json"), &current)?;
            tokio::time::sleep(INTERVAL).await;
        }
        Ok::<_, anyhow::Error>(())
    };
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let result = tokio::select! {
        result = run => result,
        _ = until_inactive(directory) => Ok(()),
        _ = interrupt.recv() => Ok(()),
        _ = terminate.recv() => Ok(()),
        _ = hangup.recv() => Ok(()),
    };
    // Cancelling an in-flight registry call kills only its own process group.
    // Stop only the exporter this worker owns, never the TUI's/user's exporter.
    exporter.stop().await;
    let mut current = status(directory)?;
    current.running = false;
    if let Err(error) = &result {
        current.error = Some(format!("{error:#}"));
    }
    save_json(&directory.join("status.json"), &current)?;
    log.record("Herdr app discovery stopped (paused, unloaded or lease expired)");
    result
}

pub(crate) fn install(home: &Path) -> Result<()> {
    ensure!(home.is_absolute(), "app home must be absolute");
    let mods = home.join("mods");
    fs::create_dir_all(&mods)?;
    let destination = mods.join("attached-discovery");
    ensure!(
        !destination.exists(),
        "{} already exists; refusing to overwrite a personal mod",
        destination.display()
    );
    let staging = tempfile::Builder::new()
        .prefix(".attached-discovery-")
        .tempdir_in(&mods)?;
    fs::write(
        staging.path().join("main.js"),
        include_str!("../../../plugins/herdr-app/mods/attached-discovery/main.js"),
    )?;
    fs::write(
        staging.path().join("mod.json"),
        include_str!("../../../plugins/herdr-app/mods/attached-discovery/mod.json"),
    )?;
    fs::copy(std::env::current_exe()?, staging.path().join("worker"))?;
    fs::rename(staging.path(), &destination)?;
    println!(
        "Installed {}\nMount attached-discovery in a PERSONAL layout or mod pane to start discovery.\nFor startup discovery, keep its block in the layout you open the app with.\nClone shipped layouts before adding a block; no layouts were modified.\nIt executes hc/ssh/attached and reads ~/.ssh/attached/discovery.json.\nCore installation/upgrades are off until explicitly enabled in the panel.\nOwnership and logs: {}/data/attached-discovery\nValidate: herdr-app check {}",
        destination.display(),
        home.display(),
        destination.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_expire_and_fail_closed_for_pause_and_clock_changes() {
        let mut lease = Lease {
            checked_at: 100,
            enabled: true,
            install_core: false,
        };
        assert!(lease.active(100));
        assert!(lease.active(190));
        assert!(!lease.active(191));
        assert!(!lease.active(99));
        lease.enabled = false;
        assert!(!lease.active(100));
    }
}
