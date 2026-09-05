use std::{
    os::unix::process::CommandExt as _,
    os::unix::{fs::FileTypeExt, process::ExitStatusExt as _},
    path::{Path, PathBuf},
    process::{Child, Command as StdCommand, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use tokio::process::Command;
use tracing::{info, warn};

use crate::{bounded_process, secure_state};

const SESSION_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SESSION_DISCOVERY_BYTES: u64 = 4096;
const DEFAULT_SESSION_START_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SESSION_POLL_INTERVAL: Duration = Duration::from_millis(25);
const DEFAULT_SESSION_BOOTSTRAP_LOCK: &str = "herdr-bootstrap.lock";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    name: String,
    tui_socket: PathBuf,
    api_socket: PathBuf,
}

impl Session {
    pub fn new(name: String, tui_socket: PathBuf) -> Self {
        let api_socket = tui_socket.with_file_name("herdr.sock");
        Self {
            name,
            tui_socket,
            api_socket,
        }
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

    pub fn validated_api_socket(&self) -> Result<&Path> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&self.api_socket)
            .context("Herdr API socket is unavailable")?;
        ensure!(
            metadata.file_type().is_socket(),
            "Herdr API path is not a Unix socket"
        );
        ensure!(
            metadata.uid() == rustix::process::geteuid().as_raw(),
            "Herdr API socket has a different owner"
        );
        ensure!(
            metadata.mode() & 0o077 == 0,
            "Herdr API socket must be owner-only"
        );
        Ok(&self.api_socket)
    }

    #[tracing::instrument(name = "attach_local_session", level = "debug", skip_all)]
    pub async fn attach_local(&self, herdr_bin: &Path) -> Result<i32> {
        self.validate()?;
        let status = Command::new(herdr_bin)
            // The selected server is already running and its TUI socket was validated.
            // Skip bare Herdr's unrelated default-API-server compatibility probe.
            .arg("client")
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
    #[serde(default)]
    socket_path: Option<PathBuf>,
}

fn sessions_from_json(output: &[u8]) -> Result<Vec<Session>> {
    let list: HerdrSessionList = serde_json::from_slice(output)
        .context("failed to parse `herdr session list --json` output")?;
    Ok(list
        .sessions
        .into_iter()
        .filter(|session| session.running)
        .map(|session| {
            let mut discovered =
                Session::new(session.name, session.session_dir.join("herdr-client.sock"));
            if let Some(path) = session.socket_path {
                discovered.api_socket = path;
            }
            discovered
        })
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
        self.active_sessions_with_timeout(SESSION_DISCOVERY_TIMEOUT)
    }

    #[tracing::instrument(name = "discover_local_sessions_blocking", level = "debug", skip_all)]
    fn active_sessions_with_timeout(&self, timeout: Duration) -> Result<Vec<Session>> {
        ensure!(!timeout.is_zero(), "Herdr session discovery timed out");
        let output = bounded_process::run(
            &self.herdr_bin,
            ["session", "list", "--json"]
                .map(std::ffi::OsStr::new)
                .as_slice(),
            timeout.min(SESSION_DISCOVERY_TIMEOUT),
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

struct StartingDefaultServer {
    child: Option<Child>,
    reaper: Option<DetachedChildReaper>,
}

struct DetachedChildReaper {
    child: mpsc::SyncSender<Child>,
}

impl DetachedChildReaper {
    fn start() -> Result<Self> {
        let (child, receiver) = mpsc::sync_channel::<Child>(1);
        thread::Builder::new()
            .name("attached-herdr-reaper".to_owned())
            .spawn(move || {
                let Ok(mut child) = receiver.recv() else {
                    return;
                };
                let pid = child.id();
                match child.wait() {
                    Ok(status) => {
                        warn!(pid, %status, "detached default Herdr session exited");
                    }
                    Err(error) => {
                        warn!(pid, %error, "failed to reap detached default Herdr session");
                    }
                }
            })
            .context("failed to start the default Herdr session reaper")?;
        Ok(Self { child })
    }
}

impl StartingDefaultServer {
    fn command(herdr_bin: &Path) -> StdCommand {
        let mut command = StdCommand::new(herdr_bin);
        command
            .arg("server")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("HERDR_SOCKET_PATH")
            .env_remove("HERDR_CLIENT_SOCKET_PATH")
            .env_remove("HERDR_REMOTE_KEYBINDINGS")
            .process_group(0);
        command
    }

    fn spawn(herdr_bin: &Path) -> Result<Self> {
        Self::spawn_with_reaper(herdr_bin, DetachedChildReaper::start)
    }

    fn spawn_with_reaper(
        herdr_bin: &Path,
        start_reaper: impl FnOnce() -> Result<DetachedChildReaper>,
    ) -> Result<Self> {
        let reaper = start_reaper()?;
        let child = Self::command(herdr_bin).spawn().with_context(|| {
            format!(
                "failed to start the default Herdr session with {} server",
                herdr_bin.display()
            )
        })?;
        Ok(Self {
            child: Some(child),
            reaper: Some(reaper),
        })
    }

    fn exited(&mut self) -> Result<Option<ExitStatus>> {
        let child = self
            .child
            .as_mut()
            .expect("default server child is present while starting");
        let process_group = child.id();
        let status = child
            .try_wait()
            .context("failed to inspect the starting default Herdr session")?;
        if status.is_some() {
            bounded_process::terminate_process_group(process_group);
            self.child.take();
        }
        Ok(status)
    }

    fn detach(mut self) -> Result<()> {
        let child = self
            .child
            .take()
            .expect("default server child is present before detaching");
        let reaper = self
            .reaper
            .take()
            .expect("default server reaper is present before detaching");
        match reaper.child.send(child) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.child = Some(error.0);
                bail!("default Herdr session reaper stopped before accepting the child")
            }
        }
    }
}

impl Drop for StartingDefaultServer {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        bounded_process::terminate_process_group(child.id());
        let _ = child.wait();
    }
}

fn ensure_active_blocking(bootstrap_lock_dir: PathBuf, herdr_bin: PathBuf) -> Result<Vec<Session>> {
    let manager = SessionManager::new(herdr_bin.clone());
    let deadline = std::time::Instant::now() + DEFAULT_SESSION_START_TIMEOUT;
    let sessions = manager.active_sessions_with_timeout(
        deadline.saturating_duration_since(std::time::Instant::now()),
    )?;
    if !sessions.is_empty() {
        return Ok(sessions);
    }

    secure_state::with_exclusive_lock_until(
        &bootstrap_lock_dir,
        DEFAULT_SESSION_BOOTSTRAP_LOCK,
        deadline,
        |_| {
            let sessions = manager.active_sessions_with_timeout(
                deadline.saturating_duration_since(std::time::Instant::now()),
            )?;
            if !sessions.is_empty() {
                return Ok(sessions);
            }

            info!("no active Herdr sessions found; starting the default session headlessly");
            let mut server = StartingDefaultServer::spawn(&herdr_bin)?;
            let mut last_discovery_error;
            loop {
                match manager.active_sessions_with_timeout(
                    deadline.saturating_duration_since(std::time::Instant::now()),
                ) {
                    Ok(sessions) if !sessions.is_empty() => {
                        info!(
                            session_count = sessions.len(),
                            "default Herdr session is ready"
                        );
                        server.detach()?;
                        return Ok(sessions);
                    }
                    Ok(_) => last_discovery_error = None,
                    Err(error) => last_discovery_error = Some(error),
                }

                if let Some(status) = server.exited()? {
                    bail!(
                        "`herdr server` exited with {status} before the default session became active"
                    );
                }
                if std::time::Instant::now() >= deadline {
                    if let Some(error) = last_discovery_error {
                        return Err(error).context(
                            "the default Herdr session did not become discoverable before startup timed out",
                        );
                    }
                    bail!(
                        "the default Herdr session did not become discoverable within {} seconds",
                        DEFAULT_SESSION_START_TIMEOUT.as_secs()
                    );
                }
                thread::sleep(
                    DEFAULT_SESSION_POLL_INTERVAL
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                );
            }
        },
    )
}

pub async fn ensure_active(
    bootstrap_lock_dir: PathBuf,
    herdr_bin: PathBuf,
) -> Result<Vec<Session>> {
    tokio::task::spawn_blocking(move || ensure_active_blocking(bootstrap_lock_dir, herdr_bin))
        .await
        .context("default Herdr session startup worker failed")?
}

#[tracing::instrument(name = "discover_local_sessions", level = "debug", skip_all)]
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
        process::Child as TestChild,
        time::{Duration, Instant},
    };

    #[test]
    fn notification_api_socket_uses_discovery_and_rejects_unsafe_paths() {
        use std::os::unix::net::UnixListener;
        let root = crate::test_support::canonical_tempdir();
        let api = root.path().join("custom-api.sock");
        let _socket = UnixListener::bind(&api).unwrap();
        fs::set_permissions(&api, fs::Permissions::from_mode(0o600)).unwrap();
        let sessions = sessions_from_json(&serde_json::to_vec(&serde_json::json!({
            "sessions":[{"name":"test", "running":true, "session_dir":root.path(), "socket_path":api}]
        })).unwrap()).unwrap();
        assert_eq!(sessions[0].validated_api_socket().unwrap(), api);
        fs::set_permissions(&api, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(sessions[0].validated_api_socket().is_err());
        fs::remove_file(&api).unwrap();
        fs::write(&api, "not a socket").unwrap();
        assert!(sessions[0].validated_api_socket().is_err());
        fs::remove_file(&api).unwrap();
        std::os::unix::fs::symlink(root.path().join("elsewhere"), &api).unwrap();
        assert!(sessions[0].validated_api_socket().is_err());
    }

    fn wait_for_process_exit(pid: u32, timeout: Duration) -> bool {
        let process = PathBuf::from(format!("/proc/{pid}"));
        let deadline = Instant::now() + timeout;
        while process.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        !process.exists()
    }

    fn stop_fake_server(pid_file: &Path, stop_file: &Path) {
        let pid: u32 = fs::read_to_string(pid_file).unwrap().parse().unwrap();
        fs::write(stop_file, b"stop").unwrap();
        assert!(
            wait_for_process_exit(pid, Duration::from_secs(1)),
            "fake server {pid} was not reaped"
        );
    }

    fn process_group_of(pid: u32) -> Option<u32> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields = stat
            .rsplit_once(") ")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        fields.get(2)?.parse().ok()
    }

    struct TestProcess {
        child: Option<TestChild>,
    }

    impl TestProcess {
        fn spawn(command: &mut StdCommand) -> Self {
            command.process_group(0);
            Self {
                child: Some(command.spawn().unwrap()),
            }
        }

        fn wait(mut self) -> ExitStatus {
            let status = self.child.as_mut().unwrap().wait().unwrap();
            self.child.take();
            status
        }
    }

    impl Drop for TestProcess {
        fn drop(&mut self) {
            if let Some(child) = self.child.as_mut() {
                bounded_process::terminate_process_group(child.id());
                let _ = child.wait();
            }
        }
    }

    fn fake_herdr(body: &[u8]) -> tempfile::TempPath {
        let path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let mut script = b"#!/bin/sh\n".to_vec();
        script.extend_from_slice(body);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[tokio::test]
    async fn local_attach_uses_direct_client_mode_for_the_selected_tui_socket() {
        let root = tempfile::tempdir().unwrap();
        let tui_socket = root.path().join("tui.sock");
        let _tui_listener = std::os::unix::net::UnixListener::bind(&tui_socket).unwrap();
        let herdr = fake_herdr(
            br#"
test -z "$HERDR_SOCKET_PATH" || exit 11
test -S "$HERDR_CLIENT_SOCKET_PATH" || exit 12
test -z "$HERDR_REMOTE_KEYBINDINGS" || exit 13
test "$#" -eq 1 || exit 14
test "$1" = client || exit 15
exit 7
"#,
        );
        let session = Session::new("local-work".to_owned(), tui_socket);

        let code = session.attach_local(&herdr).await.unwrap();

        assert_eq!(code, 7);
    }

    #[test]
    fn starts_headless_default_server_when_no_session_is_active() {
        let root = crate::test_support::canonical_tempdir();
        let ready = root.path().join("ready");
        let pid_file = root.path().join("pid");
        let stop = root.path().join("stop");
        let session_dir = root.path().join("default");
        let herdr = fake_herdr(
            format!(
                r#"
if [ "$1" = session ] && [ "$2" = list ] && [ "$3" = --json ]; then
    if [ -f '{ready}' ]; then
        printf '{{"sessions":[{{"name":"default","running":true,"session_dir":"{session_dir}"}}]}}'
    else
        printf '{{"sessions":[]}}'
    fi
    exit 0
fi
if [ "$1" = server ]; then
    printf '%s' "$$" > '{pid_file}'
    : > '{ready}'
    while [ ! -f '{stop}' ]; do sleep 0.01; done
fi
exit 9
"#,
                ready = ready.display(),
                pid_file = pid_file.display(),
                stop = stop.display(),
                session_dir = session_dir.display(),
            )
            .as_bytes(),
        );

        let sessions =
            ensure_active_blocking(root.path().join("state"), herdr.to_path_buf()).unwrap();
        let session_count = sessions.len();
        let session_name = sessions[0].name().to_owned();
        stop_fake_server(&pid_file, &stop);

        assert_eq!(session_count, 1);
        assert_eq!(session_name, "default");
    }

    #[test]
    fn detached_default_server_does_not_inherit_session_routing_overrides() {
        let command = StartingDefaultServer::command(Path::new("herdr"));
        for name in [
            "HERDR_SOCKET_PATH",
            "HERDR_CLIENT_SOCKET_PATH",
            "HERDR_REMOTE_KEYBINDINGS",
        ] {
            assert!(
                command
                    .get_envs()
                    .any(|(key, value)| key == std::ffi::OsStr::new(name) && value.is_none()),
                "{name} was not removed from the detached server environment"
            );
        }

        let root = crate::test_support::canonical_tempdir();
        let ready = root.path().join("ready");
        let pid_file = root.path().join("pid");
        let stop = root.path().join("stop");
        let environment_file = root.path().join("environment");
        let session_dir = root.path().join("default");
        let herdr = fake_herdr(
                format!(
                    r#"
if [ "$1" = session ] && [ "$2" = list ] && [ "$3" = --json ]; then
    if [ -f '{ready}' ]; then
        printf '{{"sessions":[{{"name":"default","running":true,"session_dir":"{session_dir}"}}]}}'
    else
        printf '{{"sessions":[]}}'
    fi
    exit 0
fi
if [ "$1" = server ]; then
    printf '%s\n%s\n%s\n' "$HERDR_SOCKET_PATH" "$HERDR_CLIENT_SOCKET_PATH" "$HERDR_REMOTE_KEYBINDINGS" > '{environment_file}'
    printf '%s' "$$" > '{pid_file}'
    : > '{ready}'
    while [ ! -f '{stop}' ]; do sleep 0.01; done
fi
exit 9
"#,
                    ready = ready.display(),
                    pid_file = pid_file.display(),
                    stop = stop.display(),
                    environment_file = environment_file.display(),
                    session_dir = session_dir.display(),
                )
                .as_bytes(),
            );

        ensure_active_blocking(root.path().join("state"), herdr.to_path_buf()).unwrap();
        let inherited = fs::read_to_string(&environment_file).unwrap();
        stop_fake_server(&pid_file, &stop);

        assert_eq!(inherited, "\n\n\n");
    }

    #[tokio::test]
    async fn existing_active_session_does_not_start_another_server() {
        let root = tempfile::tempdir().unwrap();
        let started = root.path().join("started");
        let session_dir = root.path().join("work");
        let herdr = fake_herdr(
            format!(
                r#"
if [ "$1" = session ] && [ "$2" = list ] && [ "$3" = --json ]; then
    printf '{{"sessions":[{{"name":"work","running":true,"session_dir":"{session_dir}"}}]}}'
    exit 0
fi
if [ "$1" = server ]; then
    : > '{started}'
    exit 0
fi
exit 9
"#,
                started = started.display(),
                session_dir = session_dir.display(),
            )
            .as_bytes(),
        );

        let sessions = ensure_active(root.path().join("state"), herdr.to_path_buf())
            .await
            .unwrap();
        assert_eq!(sessions[0].name(), "work");
        assert!(!started.exists());
    }

    #[test]
    fn bootstrap_process_helper() {
        let Ok(herdr) = std::env::var("ATTACHED_TEST_BOOTSTRAP_HERDR") else {
            return;
        };
        let state = std::env::var("ATTACHED_TEST_BOOTSTRAP_STATE").unwrap();
        ensure_active_blocking(PathBuf::from(state), PathBuf::from(herdr)).unwrap();
    }

    #[test]
    fn concurrent_serve_processes_launch_only_one_default_server() {
        let root = crate::test_support::canonical_tempdir();
        let first_discovery = root.path().join("first-discovery");
        let second_discovery = root.path().join("second-discovery");
        let launched = root.path().join("launched");
        let duplicate = root.path().join("duplicate");
        let ready = root.path().join("ready");
        let server_pid = root.path().join("server-pid");
        let stop = root.path().join("stop");
        let session_dir = root.path().join("default");
        let herdr = fake_herdr(
            format!(
                r#"
if [ "$1" = session ] && [ "$2" = list ] && [ "$3" = --json ]; then
    if [ -f '{ready}' ]; then
        printf '{{"sessions":[{{"name":"default","running":true,"session_dir":"{session_dir}"}}]}}'
        exit 0
    fi
    if mkdir '{first_discovery}' 2>/dev/null; then
        while [ ! -d '{second_discovery}' ]; do sleep 0.01; done
    else
        mkdir '{second_discovery}' 2>/dev/null || true
    fi
    printf '{{"sessions":[]}}'
    exit 0
fi
if [ "$1" = server ]; then
    if mkdir '{launched}' 2>/dev/null; then
        printf '%s' "$$" > '{server_pid}'
        sleep 0.2
        : > '{ready}'
        while [ ! -f '{stop}' ]; do sleep 0.01; done
    fi
    : > '{duplicate}'
    exit 41
fi
exit 9
"#,
                first_discovery = first_discovery.display(),
                second_discovery = second_discovery.display(),
                launched = launched.display(),
                duplicate = duplicate.display(),
                ready = ready.display(),
                server_pid = server_pid.display(),
                stop = stop.display(),
                session_dir = session_dir.display(),
            )
            .as_bytes(),
        );

        let test_binary = std::env::current_exe().unwrap();
        let command = || {
            let mut command = StdCommand::new(&test_binary);
            command
                .args(["--exact", "session::tests::bootstrap_process_helper"])
                .env("ATTACHED_TEST_BOOTSTRAP_HERDR", &herdr)
                .env("ATTACHED_TEST_BOOTSTRAP_STATE", root.path().join("state"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        };
        let first = TestProcess::spawn(&mut command());
        let second = TestProcess::spawn(&mut command());

        let first_status = first.wait();
        let second_status = second.wait();
        let launched_once = launched.exists();
        let launched_duplicate = duplicate.exists();
        stop_fake_server(&server_pid, &stop);

        assert!(first_status.success());
        assert!(second_status.success());
        assert!(launched_once);
        assert!(!launched_duplicate, "a second default server was launched");
    }

    #[tokio::test]
    async fn reports_default_server_exit_before_session_is_ready() {
        let root = crate::test_support::canonical_tempdir();
        let herdr = fake_herdr(
            br#"
if [ "$1" = session ] && [ "$2" = list ] && [ "$3" = --json ]; then
    printf '{"sessions":[]}'
    exit 0
fi
if [ "$1" = server ]; then
    exit 23
fi
exit 9
"#,
        );

        let started = Instant::now();
        let error = ensure_active(root.path().join("state"), herdr.to_path_buf())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("exited with exit status: 23"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn early_server_exit_kills_its_surviving_process_group() {
        let root = crate::test_support::canonical_tempdir();
        let server_pid = root.path().join("server-pid");
        let descendant_pid = root.path().join("descendant-pid");
        let herdr = fake_herdr(
            format!(
                r#"
if [ "$1" = session ] && [ "$2" = list ] && [ "$3" = --json ]; then
    printf '{{"sessions":[]}}'
    exit 0
fi
if [ "$1" = server ]; then
    printf '%s' "$$" > '{server_pid}'
    sleep 60 &
    printf '%s' "$!" > '{descendant_pid}'
    exit 23
fi
exit 9
"#,
                server_pid = server_pid.display(),
                descendant_pid = descendant_pid.display(),
            )
            .as_bytes(),
        );

        let error = ensure_active_blocking(root.path().join("state"), herdr.to_path_buf())
            .unwrap_err()
            .to_string();
        let process_group: u32 = fs::read_to_string(&server_pid).unwrap().parse().unwrap();
        let descendant: u32 = fs::read_to_string(&descendant_pid)
            .unwrap()
            .parse()
            .unwrap();
        let descendant_exited = wait_for_process_exit(descendant, Duration::from_millis(250));
        if !descendant_exited && process_group_of(descendant) == Some(process_group) {
            bounded_process::terminate_process_group(process_group);
            let _ = wait_for_process_exit(descendant, Duration::from_secs(1));
        }

        assert!(error.contains("exited with exit status: 23"), "{error}");
        assert!(
            descendant_exited,
            "server descendant {descendant} survived the early-exit error"
        );
    }

    #[test]
    fn reaper_setup_failure_happens_before_default_server_spawn() {
        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("server-pid");
        let herdr = fake_herdr(
            format!(
                "if [ \"$1\" = server ]; then printf '%s' \"$$\" > '{}'; while :; do sleep 1; done; fi\nexit 9\n",
                pid_file.display()
            )
            .as_bytes(),
        );

        let error = StartingDefaultServer::spawn_with_reaper(&herdr, || {
            anyhow::bail!("synthetic reaper setup failure")
        })
        .err()
        .unwrap();

        assert!(error.to_string().contains("synthetic reaper setup failure"));
        assert!(!pid_file.exists(), "server was spawned without a reaper");
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
    fn default_session_deadline_bounds_final_discovery_and_reaps_every_process_group() {
        let root = crate::test_support::canonical_tempdir();
        let first_discovery = root.path().join("first-discovery");
        let discovery_pid = root.path().join("discovery-pid");
        let discovery_child_pid = root.path().join("discovery-child-pid");
        let herdr = fake_herdr(
            format!(
                r#"
if [ "$1" = session ] && [ "$2" = list ] && [ "$3" = --json ]; then
    if mkdir '{first_discovery}' 2>/dev/null; then
        printf '{{"sessions":[]}}'
        exit 0
    fi
    printf '%s' "$$" > '{discovery_pid}'
    sleep 60 &
    printf '%s' "$!" > '{discovery_child_pid}'
    wait
fi
if [ "$1" = server ]; then
    while :; do sleep 1; done
fi
exit 9
"#,
                first_discovery = first_discovery.display(),
                discovery_pid = discovery_pid.display(),
                discovery_child_pid = discovery_child_pid.display(),
            )
            .as_bytes(),
        );

        let started = Instant::now();
        let error =
            ensure_active_blocking(root.path().join("state"), herdr.to_path_buf()).unwrap_err();
        let elapsed = started.elapsed();

        assert!(error.to_string().contains("timed out"), "{error:#}");
        assert!(
            elapsed < DEFAULT_SESSION_START_TIMEOUT + Duration::from_millis(500),
            "whole startup bound was exceeded: {elapsed:?}"
        );
        for pid_file in [&discovery_pid, &discovery_child_pid] {
            let pid = fs::read_to_string(pid_file).unwrap();
            let pid = pid.trim().parse().unwrap();
            assert!(
                wait_for_process_exit(pid, Duration::from_secs(1)),
                "process {pid} was not reaped"
            );
        }
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
