use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::process::Command;

use crate::{PLUGIN_ID, process};

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Machine {
    pub target: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Plugin {
    pub plugin_id: String,
    pub enabled: bool,
    pub plugin_root: PathBuf,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Session {
    pub name: String,
    pub running: bool,
    pub socket_path: PathBuf,
}

pub(crate) trait MachineRegistry {
    async fn machines(&self) -> Result<Vec<Machine>>;
    async fn add(&self, target: &str, label: &str) -> Result<()>;
    /// False means no running Herdr session accepted the toast yet.
    async fn notify(&self, label: &str) -> Result<bool>;
}

pub(crate) struct Herdr {
    binary: PathBuf,
}

impl Default for Herdr {
    fn default() -> Self {
        Self {
            binary: std::env::var_os("HERDR_BIN_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| "herdr".into()),
        }
    }
}

impl Herdr {
    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command.args(args);
        command
    }

    pub async fn plugin(&self) -> Result<Option<Plugin>> {
        #[derive(Deserialize)]
        struct Response {
            result: Plugins,
        }
        #[derive(Deserialize)]
        struct Plugins {
            plugins: Vec<Plugin>,
        }
        let output = process::output(
            self.command(&["plugin", "list", "--json"]),
            Duration::from_secs(10),
        )
        .await?;
        let response: Response =
            serde_json::from_str(&output).context("invalid Herdr plugin list")?;
        Ok(response
            .result
            .plugins
            .into_iter()
            .find(|p| p.plugin_id == PLUGIN_ID))
    }

    pub async fn sessions(&self) -> Result<Vec<Session>> {
        #[derive(Deserialize)]
        struct Response {
            sessions: Vec<Session>,
        }
        let output = process::output(
            self.command(&["session", "list", "--json"]),
            Duration::from_secs(10),
        )
        .await?;
        let response: Response =
            serde_json::from_str(&output).context("invalid Herdr session list")?;
        Ok(response.sessions)
    }

    pub async fn ensure_in_session(&self, name: &str) -> Result<()> {
        process::output(
            self.command(&[
                "--session",
                name,
                "plugin",
                "action",
                "invoke",
                "attached.discovery.ensure",
            ]),
            Duration::from_secs(10),
        )
        .await?;
        Ok(())
    }
}

impl MachineRegistry for Herdr {
    async fn machines(&self) -> Result<Vec<Machine>> {
        let output = process::output(
            self.command(&["machine", "list", "--json"]),
            Duration::from_secs(10),
        )
        .await?;
        serde_json::from_str(&output).context("invalid Herdr machine list")
    }

    async fn add(&self, target: &str, label: &str) -> Result<()> {
        // Herdr saves only after successful remote preparation. Null stdin makes
        // missing/incompatible remote installs fail, never auto-approve upgrades.
        process::output(
            self.command(&["machine", "add", target, "--label", label]),
            Duration::from_secs(60),
        )
        .await?;
        Ok(())
    }

    async fn notify(&self, label: &str) -> Result<bool> {
        let mut sockets = self
            .sessions()
            .await?
            .into_iter()
            .filter(|s| s.running)
            .map(|s| s.socket_path)
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(socket) = std::env::var_os("HERDR_SOCKET_PATH") {
            sockets.insert(socket.into());
        }
        let mut delivered = false;
        for socket in sockets {
            let mut command = self.command(&[
                "notification",
                "show",
                "Attached machine added",
                "--body",
                &format!("{label} is now available in Machines."),
                "--sound",
                "none",
            ]);
            command
                .env("HERDR_SOCKET_PATH", socket)
                .env_remove("HERDR_CLIENT_SOCKET_PATH");
            // One stale session socket must not prevent notification of others.
            delivered |= process::output(command, Duration::from_secs(5))
                .await
                .is_ok();
        }
        Ok(delivered)
    }
}
