use std::{
    os::unix::{fs::FileTypeExt, process::ExitStatusExt as _},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use tokio::process::Command;

use crate::bounded_process;

const SESSION_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SESSION_DISCOVERY_BYTES: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    name: String,
    tui_socket: PathBuf,
}

impl Session {
    pub fn new(name: String, tui_socket: PathBuf) -> Self {
        Self { name, tui_socket }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn validate(&self) -> Result<()> {
        validate_socket("TUI", &self.tui_socket)
    }

    pub fn validated_tui_socket(&self) -> Result<&Path> {
        validate_socket("TUI", &self.tui_socket).with_context(|| {
            format!("Herdr session `{}` cannot accept a TUI stream", self.name())
        })?;
        Ok(&self.tui_socket)
    }

    pub async fn attach_local(&self, herdr_bin: &Path) -> Result<i32> {
        self.validate()?;
        let status = Command::new(herdr_bin)
            .env_remove("HERDR_SOCKET_PATH")
            .env("HERDR_CLIENT_SOCKET_PATH", &self.tui_socket)
            .env_remove("HERDR_REMOTE_KEYBINDINGS")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .status()
            .await
            .with_context(|| {
                format!("failed to launch Herdr executable {}", herdr_bin.display())
            })?;
        Ok(exit_code(status))
    }
}

#[derive(Deserialize)]
struct HerdrSessionList {
    sessions: Vec<HerdrSession>,
}

#[derive(Deserialize)]
struct HerdrSession {
    name: String,
    running: bool,
    session_dir: PathBuf,
}

fn sessions_from_json(output: &[u8]) -> Result<Vec<Session>> {
    let list: HerdrSessionList = serde_json::from_slice(output)
        .context("failed to parse `herdr session list --json` output")?;
    Ok(list
        .sessions
        .into_iter()
        .filter(|session| session.running)
        .map(|session| Session::new(session.name, session.session_dir.join("herdr-client.sock")))
        .collect())
}

pub struct SessionManager {
    herdr_bin: PathBuf,
}

impl SessionManager {
    pub fn new(herdr_bin: PathBuf) -> Self {
        Self { herdr_bin }
    }

    pub fn active_sessions(&self) -> Result<Vec<Session>> {
        let output = bounded_process::run(
            &self.herdr_bin,
            ["session", "list", "--json"]
                .map(std::ffi::OsStr::new)
                .as_slice(),
            SESSION_DISCOVERY_TIMEOUT,
            MAX_SESSION_DISCOVERY_BYTES,
        )?;
        if !output.status.success() {
            bail!(
                "`{:?} session list --json` failed with {}: {}",
                self.herdr_bin,
                output.status,
                bounded_process::diagnostic(&output.stderr).trim()
            );
        }
        sessions_from_json(&output.stdout)
    }
}

pub async fn discover_active(herdr_bin: PathBuf) -> Result<Vec<Session>> {
    tokio::task::spawn_blocking(move || SessionManager::new(herdr_bin).active_sessions())
        .await
        .context("Herdr session discovery worker failed")?
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

fn validate_socket(label: &str, path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("{label} socket {} is not available", path.display()))?;
    ensure!(
        metadata.file_type().is_socket(),
        "{label} path {} is not a Unix socket",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };

    fn fake_herdr(body: &[u8]) -> tempfile::TempPath {
        let path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let mut script = b"#!/bin/sh\n".to_vec();
        script.extend_from_slice(body);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[tokio::test]
    async fn local_attach_uses_only_the_selected_tui_socket() {
        let root = tempfile::tempdir().unwrap();
        let tui_socket = root.path().join("tui.sock");
        let _tui_listener = std::os::unix::net::UnixListener::bind(&tui_socket).unwrap();
        let herdr = fake_herdr(
            br#"
test -z "$HERDR_SOCKET_PATH" || exit 11
test -S "$HERDR_CLIENT_SOCKET_PATH" || exit 12
test -z "$HERDR_REMOTE_KEYBINDINGS" || exit 13
test "$#" -eq 0 || exit 14
exit 7
"#,
        );
        let session = Session::new("local-work".to_owned(), tui_socket);

        let code = session.attach_local(&herdr).await.unwrap();

        assert_eq!(code, 7);
    }

    #[test]
    fn parses_only_running_sessions_and_tolerates_unknown_fields() {
        let sessions = sessions_from_json(
            br#"{
                "unknown": true,
                "sessions": [
                    {
                        "name": "active",
                        "running": true,
                        "session_dir": "/tmp/herdr/active",
                        "socket_path": "/tmp/herdr/active/api.sock",
                        "future_field": 1
                    },
                    {
                        "name": "stopped",
                        "running": false,
                        "session_dir": "/tmp/herdr/stopped",
                        "socket_path": "/tmp/herdr/stopped/api.sock"
                    }
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].name(), "active");
        assert_eq!(
            sessions[0].tui_socket,
            Path::new("/tmp/herdr/active/herdr-client.sock")
        );
    }

    #[test]
    fn active_session_discovery_times_out_and_reaps_hanging_process_group() {
        let hanging = fake_herdr(b"(sleep 60) &\nsleep 3\nprintf '{\"sessions\":[]}'\n");
        let manager = SessionManager::new(hanging.to_path_buf());
        let started = Instant::now();
        let error = manager.active_sessions().unwrap_err().to_string();
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn active_session_discovery_rejects_excessive_output() {
        let excessive =
            fake_herdr(b"dd if=/dev/zero bs=8192 count=1 2>/dev/null\nprintf diagnostic >&2\n");
        let manager = SessionManager::new(excessive.to_path_buf());
        let error = manager.active_sessions().unwrap_err().to_string();
        assert!(error.contains("more than"), "{error}");
    }

    #[test]
    fn validates_unix_sockets() {
        let root = tempfile::tempdir().unwrap();
        let socket_path = root.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        assert!(validate_socket("TUI", &socket_path).is_ok());

        let file_path = root.path().join("file");
        std::fs::write(&file_path, b"not a socket").unwrap();
        assert!(validate_socket("TUI", &file_path).is_err());
    }
}
