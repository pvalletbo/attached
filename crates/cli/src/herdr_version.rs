use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
pub use attached_tunnel_protocol::HerdrVersion;
use serde::Deserialize;

use crate::bounded_process;

pub fn parse_version_output(output: &[u8]) -> Result<HerdrVersion> {
    let output = output.strip_suffix(b"\n").unwrap_or(output);
    let output = output.strip_suffix(b"\r").unwrap_or(output);
    let Some(version) = output.strip_prefix(b"herdr ") else {
        bail!("expected `herdr X.Y.Z`");
    };
    let mut components = version.split(|byte| *byte == b'.');
    let parse_component = |component: Option<&[u8]>| -> Result<u32> {
        let Some(component) = component else {
            bail!("expected three numeric version components");
        };
        if component.is_empty() || !component.iter().all(u8::is_ascii_digit) {
            bail!("version component is not an unsigned integer");
        }
        let component = std::str::from_utf8(component)
            .expect("an ASCII digit sequence is valid UTF-8")
            .parse()?;
        Ok(component)
    };
    let parsed = HerdrVersion::new(
        parse_component(components.next())?,
        parse_component(components.next())?,
        parse_component(components.next())?,
    );
    if components.next().is_some() {
        bail!("expected three numeric version components");
    }
    Ok(parsed)
}

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const QUERY_CAPTURE_LIMIT: u64 = 4096;
// Herdr's asset fetch alone is bounded at 120 seconds; leave time for manifest selection,
// verification, and its atomic replacement of the staged copy.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(150);
// Herdr itself allows up to 240 seconds for a live-handoff request. Waiting slightly longer keeps
// Attached from racing a still-running handoff with rollback.
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(250);
const UPDATE_CAPTURE_LIMIT: u64 = 64 * 1024;
const HERDR_ROUTING_ENVIRONMENT: [&str; 5] = [
    "HERDR_ENV",
    "HERDR_SOCKET_PATH",
    "HERDR_CLIENT_SOCKET_PATH",
    "HERDR_SESSION",
    "HERDR_REMOTE_KEYBINDINGS",
];

#[tracing::instrument(name = "herdr_version_query", level = "debug", skip_all)]
pub fn query(executable: &Path) -> Result<HerdrVersion> {
    query_with_limits(executable, QUERY_TIMEOUT, QUERY_CAPTURE_LIMIT)
}

fn query_with_limits(
    executable: &Path,
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<HerdrVersion> {
    let output = bounded_process::run(
        executable,
        [std::ffi::OsStr::new("--version")].as_slice(),
        runtime_limit,
        capture_limit,
    )?;
    ensure!(
        output.status.success(),
        "Herdr executable {} --version exited with status {}: {}",
        executable.display(),
        output.status,
        bounded_process::diagnostic(&output.stderr)
    );

    parse_version_output(&output.stdout).with_context(|| {
        format!(
            "could not parse {} --version output as `herdr X.Y.Z`: {}",
            executable.display(),
            bounded_process::diagnostic(&output.stdout)
        )
    })
}

#[derive(Deserialize)]
struct ServerStatus {
    running: bool,
    version: Option<String>,
}

#[derive(Deserialize)]
struct SessionList {
    sessions: Vec<ListedSession>,
}

#[derive(Deserialize)]
struct ListedSession {
    name: String,
    running: bool,
}

fn isolated_command(executable: &Path) -> Command {
    let mut command = Command::new(executable);
    command.stdin(Stdio::null());
    for variable in HERDR_ROUTING_ENVIRONMENT {
        command.env_remove(variable);
    }
    command
}

fn update_command(executable: &Path) -> Command {
    // Herdr is one host-wide installation and Attached publishes one version for every session.
    // With routing overrides removed, Herdr's native updater hands off all running sessions rather
    // than whichever session happened to launch `attached serve`.
    let mut command = isolated_command(executable);
    command.args(["update", "--handoff"]);
    command
}

fn session_list_command(executable: &Path) -> Command {
    let mut command = isolated_command(executable);
    command.args(["session", "list", "--json"]);
    command
}

fn session_status_command(executable: &Path, session: &str) -> Command {
    let mut command = isolated_command(executable);
    command.args(["--session", session, "status", "server", "--json"]);
    command
}

fn session_handoff_command(
    executable: &Path,
    import_executable: &Path,
    session: &str,
    requested_version: HerdrVersion,
) -> Command {
    let mut command = isolated_command(executable);
    command
        .args(["--session", session, "server", "live-handoff"])
        .arg("--import-exe")
        .arg(import_executable)
        .arg("--expected-version")
        .arg(requested_version.to_string());
    command
}

#[cfg(test)]
fn invoke_update_with_limits(
    executable: &Path,
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<()> {
    invoke_update_command_with_limits(update_command(executable), runtime_limit, capture_limit)
}

fn invoke_update_command_with_limits(
    command: Command,
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<()> {
    let output = bounded_process::run_command(command, runtime_limit, capture_limit)?;
    ensure!(
        output.status.success(),
        "remote `herdr update --handoff` exited with status {}: {}",
        output.status,
        bounded_process::diagnostic(&output.stderr)
    );
    Ok(())
}

fn query_session_with_limits(
    executable: &Path,
    session: &str,
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<HerdrVersion> {
    let output = bounded_process::run_command(
        session_status_command(executable, session),
        runtime_limit,
        capture_limit,
    )?;
    ensure!(
        output.status.success(),
        "could not query running Herdr session `{session}`: {}",
        bounded_process::diagnostic(&output.stderr)
    );
    let status: ServerStatus = serde_json::from_slice(&output.stdout)
        .context("Herdr session status was not valid JSON")?;
    ensure!(status.running, "Herdr session `{session}` is not running");
    let version = status
        .version
        .with_context(|| format!("Herdr session `{session}` did not report its version"))?;
    parse_version_output(format!("herdr {version}").as_bytes())
        .with_context(|| format!("Herdr session `{session}` reported invalid version metadata"))
}

fn query_session(executable: &Path, session: &str) -> Result<HerdrVersion> {
    query_session_with_limits(executable, session, QUERY_TIMEOUT, QUERY_CAPTURE_LIMIT)
}

fn running_sessions(executable: &Path) -> Result<Vec<String>> {
    let output = bounded_process::run_command(
        session_list_command(executable),
        QUERY_TIMEOUT,
        QUERY_CAPTURE_LIMIT,
    )?;
    ensure!(
        output.status.success(),
        "could not list running Herdr sessions: {}",
        bounded_process::diagnostic(&output.stderr)
    );
    let sessions: SessionList =
        serde_json::from_slice(&output.stdout).context("Herdr session list was not valid JSON")?;
    let mut running = sessions
        .sessions
        .into_iter()
        .filter(|session| session.running)
        .map(|session| session.name)
        .collect::<Vec<_>>();
    running.sort();
    ensure!(
        !running.windows(2).any(|pair| pair[0] == pair[1]),
        "Herdr session list contained duplicate names"
    );
    Ok(running)
}

pub fn query_running_sessions(executable: &Path) -> Result<HerdrVersion> {
    let sessions = running_sessions(executable)?;
    let first = sessions
        .first()
        .context("Herdr did not report any running sessions")?;
    let version = query_session(executable, first)?;
    for session in &sessions[1..] {
        let observed = query_session(executable, session)?;
        ensure!(
            observed == version,
            "running Herdr sessions use mixed versions {version} and {observed}"
        );
    }
    Ok(version)
}

fn resolve_executable(executable: &Path) -> Result<PathBuf> {
    if executable.components().count() != 1 {
        return std::fs::canonicalize(executable).with_context(|| {
            format!(
                "could not resolve configured Herdr executable {}",
                executable.display()
            )
        });
    }
    let path = std::env::var_os("PATH").context("PATH is unavailable for resolving Herdr")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(executable);
        if candidate.is_file() {
            return std::fs::canonicalize(&candidate).with_context(|| {
                format!("could not resolve Herdr executable {}", candidate.display())
            });
        }
    }
    bail!(
        "configured Herdr executable {} was not found on PATH",
        executable.display()
    )
}

fn configured_herdr_config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("HERDR_CONFIG_PATH") {
        return Some(PathBuf::from(path));
    }
    if let Some(root) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(root).join("herdr/config.toml"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/herdr/config.toml"))
}

struct UpdateSandbox {
    _root: tempfile::TempDir,
    config_path: PathBuf,
    config_home: PathBuf,
    state_home: PathBuf,
}

impl UpdateSandbox {
    fn prepare(config_source: Option<&Path>) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("attached-herdr-update-")
            .tempdir()
            .context("could not create an isolated Herdr update directory")?;
        let config_home = root.path().join("config");
        let state_home = root.path().join("state");
        std::fs::create_dir(&config_home)?;
        std::fs::create_dir(&state_home)?;
        let config_path = root.path().join("config.toml");
        if let Some(source) = config_source {
            match std::fs::copy(source, &config_path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "could not stage Herdr configuration from {}",
                            source.display()
                        )
                    });
                }
            }
        }
        Ok(Self {
            _root: root,
            config_path,
            config_home,
            state_home,
        })
    }

    fn update_command(&self, executable: &Path) -> Command {
        let mut command = update_command(executable);
        // Isolating Herdr's config and state directories prevents its updater from handing off
        // live sessions itself. Attached stages the binary first, then performs and verifies each
        // handoff before committing the installation.
        command
            .env("HERDR_CONFIG_PATH", &self.config_path)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state_home);
        command
    }
}

fn duplicate_executable(
    executable: &Path,
    parent: &Path,
    prefix: &str,
) -> Result<tempfile::TempPath> {
    let duplicate = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)
        .with_context(|| format!("could not stage Herdr beside {}", executable.display()))?;
    std::fs::copy(executable, duplicate.path())
        .with_context(|| format!("could not copy Herdr executable {}", executable.display()))?;
    let permissions = std::fs::metadata(executable)?.permissions();
    std::fs::set_permissions(duplicate.path(), permissions)?;
    duplicate.as_file().sync_all()?;
    Ok(duplicate.into_temp_path())
}

fn replace_executable(source: &Path, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .context("configured Herdr executable has no parent directory")?;
    let replacement = duplicate_executable(source, parent, ".attached-herdr-install-")?;
    replacement.persist(destination).map_err(|error| {
        anyhow::anyhow!(
            "could not atomically replace Herdr executable {}: {}",
            destination.display(),
            error.error
        )
    })?;
    Ok(())
}

fn package_managed_executable(executable: &Path) -> bool {
    if executable.starts_with("/nix/store") {
        return true;
    }
    if executable.file_name() != Some(std::ffi::OsStr::new("herdr")) {
        return false;
    }
    let Some(bin) = executable
        .parent()
        .filter(|path| path.file_name() == Some(std::ffi::OsStr::new("bin")))
    else {
        return false;
    };
    let Some(version) = bin.parent() else {
        return false;
    };
    let Some(tool) = version
        .parent()
        .filter(|path| path.file_name() == Some(std::ffi::OsStr::new("herdr")))
    else {
        return false;
    };
    if tool
        .parent()
        .is_some_and(|path| path.file_name() == Some(std::ffi::OsStr::new("Cellar")))
    {
        return true;
    }
    let Some(installs) = tool.parent() else {
        return false;
    };
    installs.file_name() == Some(std::ffi::OsStr::new("installs"))
        || std::env::var_os("MISE_INSTALLS_DIR")
            .is_some_and(|configured| installs.as_os_str() == configured)
}

struct ExecutableTransaction {
    destination: PathBuf,
    original: tempfile::TempPath,
    candidate: tempfile::TempPath,
}

impl ExecutableTransaction {
    fn prepare(executable: &Path) -> Result<Self> {
        let destination = resolve_executable(executable)?;
        let parent = destination
            .parent()
            .context("configured Herdr executable has no parent directory")?;
        let original = duplicate_executable(&destination, parent, ".attached-herdr-original-")?;
        let candidate = duplicate_executable(&destination, parent, ".attached-herdr-candidate-")?;
        Ok(Self {
            destination,
            original,
            candidate,
        })
    }

    fn install_candidate(&self) -> Result<()> {
        replace_executable(self.candidate.as_ref(), &self.destination)
    }

    fn restore_original(&self) -> Result<()> {
        replace_executable(self.original.as_ref(), &self.destination)
    }
}

#[derive(Debug)]
struct UpdateRolledBack {
    source: anyhow::Error,
}

impl std::fmt::Display for UpdateRolledBack {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("remote Herdr update failed and was rolled back")
    }
}

impl std::error::Error for UpdateRolledBack {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug)]
struct PackageManagedUpdate;

impl std::fmt::Display for PackageManagedUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("remote Herdr is package-managed")
    }
}

impl std::error::Error for PackageManagedUpdate {}

pub(crate) fn is_rolled_back(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UpdateRolledBack>().is_some()
}

pub(crate) fn is_package_managed(error: &anyhow::Error) -> bool {
    error.downcast_ref::<PackageManagedUpdate>().is_some()
}

fn invoke_session_handoff_with_limits(
    command_executable: &Path,
    import_executable: &Path,
    session: &str,
    requested_version: HerdrVersion,
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<()> {
    let output = bounded_process::run_command(
        session_handoff_command(
            command_executable,
            import_executable,
            session,
            requested_version,
        ),
        runtime_limit,
        capture_limit,
    )?;
    ensure!(
        output.status.success(),
        "Herdr session `{session}` live handoff exited with status {}: {}",
        output.status,
        bounded_process::diagnostic(&output.stderr)
    );
    Ok(())
}

fn verify_live_sessions(
    command_executable: &Path,
    selected_session: &str,
    expected_version: HerdrVersion,
) -> Result<()> {
    let sessions = running_sessions(command_executable)?;
    ensure!(
        sessions.iter().any(|running| running == selected_session),
        "selected Herdr session `{selected_session}` is not running"
    );
    for session in sessions {
        let running = query_session(command_executable, &session)?;
        ensure!(
            running == expected_version,
            "Herdr session `{session}` is running {running}, expected {expected_version}"
        );
    }
    Ok(())
}

fn reconcile_live_sessions(
    command_executable: &Path,
    import_executable: &Path,
    selected_session: &str,
    expected_version: HerdrVersion,
    reject_newer: bool,
) -> Result<()> {
    // Re-list after each pass so a session started concurrently is either handed off too or makes
    // verification fail. The updater semaphore serializes Attached requests, but not local Herdr
    // launches on the serving host.
    for _ in 0..3 {
        let sessions = running_sessions(command_executable)?;
        ensure!(
            sessions.iter().any(|running| running == selected_session),
            "selected Herdr session `{selected_session}` stopped during live handoff"
        );
        let mut changed = false;
        for session in sessions {
            match query_session(command_executable, &session) {
                Ok(running) if running == expected_version => continue,
                Ok(running) if reject_newer && running > expected_version => {
                    bail!(
                        "Herdr session `{session}` is newer at {running}; expected {expected_version}"
                    );
                }
                Ok(_) | Err(_) => {}
            }
            invoke_session_handoff_with_limits(
                command_executable,
                import_executable,
                &session,
                expected_version,
                HANDOFF_TIMEOUT,
                UPDATE_CAPTURE_LIMIT,
            )?;
            let running = query_session(command_executable, &session)
                .context("could not verify a Herdr session after live handoff")?;
            ensure!(
                running == expected_version,
                "Herdr session `{session}` is still running {running}, expected {expected_version}"
            );
            changed = true;
        }
        if !changed {
            return verify_live_sessions(command_executable, selected_session, expected_version);
        }
    }
    verify_live_sessions(command_executable, selected_session, expected_version)
}

fn rollback_transaction(
    transaction: &ExecutableTransaction,
    selected_session: &str,
    original_version: HerdrVersion,
    handoff_attempted: bool,
    candidate_installed: bool,
) -> Result<()> {
    if candidate_installed {
        transaction.restore_original()?;
    }
    let restored = query(&transaction.destination)?;
    ensure!(
        restored == original_version,
        "restored Herdr binary is {restored}, expected {original_version}"
    );
    if handoff_attempted
        && reconcile_live_sessions(
            transaction.candidate.as_ref(),
            &transaction.destination,
            selected_session,
            original_version,
            false,
        )
        .is_err()
    {
        reconcile_live_sessions(
            &transaction.destination,
            &transaction.destination,
            selected_session,
            original_version,
            false,
        )?;
    }
    verify_live_sessions(&transaction.destination, selected_session, original_version)
}

fn roll_forward_transaction(
    transaction: &ExecutableTransaction,
    selected_session: &str,
    original_version: HerdrVersion,
    requested_version: HerdrVersion,
) -> Result<()> {
    ensure!(
        query(transaction.candidate.as_ref())? == requested_version,
        "staged Herdr candidate is not the requested version"
    );
    let installed = query(&transaction.destination)?;
    ensure!(
        installed == original_version || installed == requested_version,
        "Herdr installation changed concurrently to {installed}"
    );
    transaction.install_candidate()?;
    reconcile_live_sessions(
        transaction.candidate.as_ref(),
        &transaction.destination,
        selected_session,
        requested_version,
        true,
    )?;
    verify_live_sessions(
        &transaction.destination,
        selected_session,
        requested_version,
    )
}

pub fn update_session(
    executable: &Path,
    session: &str,
    requested_version: HerdrVersion,
) -> Result<HerdrVersion> {
    let config_path = configured_herdr_config_path();
    update_session_with_config(
        executable,
        session,
        requested_version,
        config_path.as_deref(),
    )
}

pub(crate) fn update_session_with_config(
    executable: &Path,
    session: &str,
    requested_version: HerdrVersion,
    config_source: Option<&Path>,
) -> Result<HerdrVersion> {
    let installed_before = query(executable)?;
    ensure!(
        installed_before <= requested_version,
        "remote Herdr binary is newer at {installed_before}; expected {requested_version}"
    );
    let executable = resolve_executable(executable)?;

    if installed_before == requested_version {
        reconcile_live_sessions(&executable, &executable, session, requested_version, true)?;
        return Ok(requested_version);
    }

    // Refuse to start a new transaction from an already inconsistent host. A previous transaction
    // whose binary reached the requested version is repaired by the branch above.
    verify_live_sessions(&executable, session, installed_before)?;
    if package_managed_executable(&executable) {
        return Err(anyhow::Error::new(PackageManagedUpdate));
    }
    let transaction = ExecutableTransaction::prepare(&executable)?;
    let sandbox = UpdateSandbox::prepare(config_source)?;
    let mut handoff_attempted = false;
    let mut candidate_installed = false;
    let forward_result = (|| -> Result<()> {
        let update_result = invoke_update_command_with_limits(
            sandbox.update_command(transaction.candidate.as_ref()),
            UPDATE_TIMEOUT,
            UPDATE_CAPTURE_LIMIT,
        );
        let candidate_version = query(transaction.candidate.as_ref())
            .context("could not query the staged Herdr candidate")?;
        ensure!(
            candidate_version == requested_version,
            "remote channel staged Herdr {candidate_version}, expected {requested_version}"
        );
        if update_result.is_err() {
            tracing::warn!(
                "staged Herdr updater did not complete; continuing from its verified candidate"
            );
        }

        ensure!(
            query(&transaction.destination)? == installed_before,
            "Herdr installation changed while the update was staged"
        );
        transaction.install_candidate()?;
        candidate_installed = true;
        ensure!(
            query(&transaction.destination)? == requested_version,
            "installed Herdr binary did not match the staged candidate"
        );
        handoff_attempted = true;
        reconcile_live_sessions(
            transaction.candidate.as_ref(),
            &transaction.destination,
            session,
            requested_version,
            true,
        )?;
        verify_live_sessions(&transaction.destination, session, requested_version)
    })();

    if forward_result.is_ok() {
        return Ok(requested_version);
    }
    if rollback_transaction(
        &transaction,
        session,
        installed_before,
        handoff_attempted,
        candidate_installed,
    )
    .is_ok()
    {
        return Err(anyhow::Error::new(UpdateRolledBack {
            source: forward_result.expect_err("successful update returned through rollback"),
        }));
    }
    if roll_forward_transaction(&transaction, session, installed_before, requested_version).is_ok()
    {
        return Ok(requested_version);
    }
    bail!("remote Herdr update and rollback could not establish a consistent live version")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, sync::Mutex, time::Instant};

    const FIXTURE_RUNTIME_LIMIT: Duration = Duration::from_secs(10);
    const OVER_32_BYTES: &[u8] = b"printf '0123456789abcdef0123456789abcdefX'\n";
    static PROCESS_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn lock_process_fixtures() -> std::sync::MutexGuard<'static, ()> {
        PROCESS_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn fake_herdr(body: &[u8]) -> tempfile::TempPath {
        let path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let mut script = b"#!/bin/sh\n".to_vec();
        script.extend_from_slice(body);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn stateful_herdr(
        root: &Path,
        binary_version: &str,
        session_version: &str,
    ) -> std::path::PathBuf {
        let executable = root.join("herdr");
        let running = root.join("running-version");
        let invocations = root.join("invocations");
        fs::write(&running, session_version).unwrap();
        fs::write(
            &executable,
            format!(
                r#"#!/bin/sh
VERSION={binary_version}
set -eu
printf '%s\n' "$*" >> '{invocations}'
if [ "${{1-}}" = --version ]; then
    printf 'herdr %s\n' "$VERSION"
    exit 0
fi
if [ "${{1-}}" = update ]; then
    sed 's/^VERSION=.*/VERSION=4.5.6/' "$0" > "$0.next"
    chmod 700 "$0.next"
    mv "$0.next" "$0"
    if [ -f '{fail_update}' ]; then
        printf 'private updater diagnostic' >&2
        exit 7
    fi
    exit 0
fi
if [ "${{1-}}" = session ] && [ "${{2-}}" = list ]; then
    printf '{{"sessions":[{{"name":"work","running":true}}]}}\n'
    exit 0
fi
if [ "${{1-}}" = --session ] && [ "${{3-}}" = status ]; then
    if [ -f '{fail_committed_status}' ] && [ "$(basename "$0")" = herdr ] && [ "$(cat '{running}')" = 4.5.6 ]; then
        exit 7
    fi
    printf '{{"running":true,"version":"%s"}}\n' "$(cat '{running}')"
    exit 0
fi
if [ "${{1-}}" = --session ] && [ "${{3-}}" = server ] && [ "${{4-}}" = live-handoff ]; then
    if [ -f '{fail_handoff}' ]; then
        printf 'private handoff diagnostic' >&2
        exit 8
    fi
    printf '%s' "${{8-}}" > '{running}'
    exit 0
fi
exit 9
"#,
                binary_version = binary_version,
                invocations = invocations.display(),
                running = running.display(),
                fail_update = root.join("fail-update").display(),
                fail_committed_status = root.join("fail-committed-status").display(),
                fail_handoff = root.join("fail-handoff").display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        executable
    }

    #[test]
    fn refuses_package_managed_executables_before_staging() {
        assert!(package_managed_executable(Path::new(
            "/opt/homebrew/Cellar/herdr/0.8.2/bin/herdr"
        )));
        assert!(package_managed_executable(Path::new(
            "/home/me/.local/share/mise/installs/herdr/0.8.2/bin/herdr"
        )));
        assert!(package_managed_executable(Path::new(
            "/nix/store/hash-herdr/bin/herdr"
        )));
        assert!(!package_managed_executable(Path::new(
            "/home/me/.local/bin/herdr"
        )));
    }

    #[test]
    fn parses_documented_version_output() {
        assert_eq!(
            parse_version_output(b"herdr 1.2.3\n").unwrap(),
            HerdrVersion::new(1, 2, 3)
        );
    }

    #[test]
    fn rejects_prerelease_malformed_and_non_utf8_output() {
        for output in [
            b"herdr 1.2.3-alpha".as_slice(),
            b"herdr 1.2".as_slice(),
            b"other 1.2.3".as_slice(),
            b"herdr 1.2.3\xff".as_slice(),
        ] {
            assert!(parse_version_output(output).is_err(), "accepted {output:?}");
        }
    }

    #[test]
    fn queries_configured_executable_and_handles_failures() {
        // These process-heavy cases and the update cases would otherwise run in
        // parallel and can exhaust constrained CI runners during a full suite.
        let _fixture_guard = lock_process_fixtures();
        let valid = fake_herdr(b"printf 'herdr 4.5.6\\n'\n");
        assert_eq!(
            query_with_limits(&valid, FIXTURE_RUNTIME_LIMIT, QUERY_CAPTURE_LIMIT).unwrap(),
            HerdrVersion::new(4, 5, 6)
        );

        let non_zero = fake_herdr(b"printf 'broken' >&2\nexit 7\n");
        let error = query_with_limits(&non_zero, FIXTURE_RUNTIME_LIMIT, QUERY_CAPTURE_LIMIT)
            .unwrap_err()
            .to_string();
        assert!(error.contains("status"), "{error}");
        assert!(error.contains('7'), "{error}");

        let non_utf8 = fake_herdr(b"printf 'herdr 1.2.3\\377'\n");
        assert!(query_with_limits(&non_utf8, FIXTURE_RUNTIME_LIMIT, QUERY_CAPTURE_LIMIT).is_err());

        let hanging = fake_herdr(b"sleep 60\n");
        let started = Instant::now();
        let error = query_with_limits(&hanging, Duration::from_millis(20), QUERY_CAPTURE_LIMIT)
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(4));

        let excessive = fake_herdr(OVER_32_BYTES);
        let error = query_with_limits(&excessive, FIXTURE_RUNTIME_LIMIT, 32)
            .unwrap_err()
            .to_string();
        assert!(error.contains("more than"), "{error}");
    }

    #[test]
    fn update_uses_a_fixed_isolated_noninteractive_operation() {
        let command = update_command(Path::new("/opt/herdr"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["update", "--handoff"]
        );
        for variable in HERDR_ROUTING_ENVIRONMENT {
            assert!(
                command
                    .get_envs()
                    .any(|(name, value)| name == variable && value.is_none()),
                "{variable} was inherited by the updater"
            );
        }

        let _fixture_guard = lock_process_fixtures();
        let root = tempfile::tempdir().unwrap();
        let source_config = root.path().join("config.toml");
        fs::write(&source_config, b"[update]\nchannel = 'preview'\n").unwrap();
        let sandbox = UpdateSandbox::prepare(Some(&source_config)).unwrap();
        assert_eq!(
            fs::read(&sandbox.config_path).unwrap(),
            b"[update]\nchannel = 'preview'\n"
        );
        let staged_command = sandbox.update_command(Path::new("/opt/herdr"));
        for variable in ["HERDR_CONFIG_PATH", "XDG_CONFIG_HOME", "XDG_STATE_HOME"] {
            assert!(
                staged_command
                    .get_envs()
                    .any(|(name, value)| name == variable && value.is_some()),
                "{variable} was not isolated"
            );
        }

        let argv = root.path().join("argv");
        let updated = fake_herdr(
            format!(
                "if [ \"$1\" = update ]; then printf '%s\\n' \"$@\" > '{}'; exit 0; fi\nexit 9\n",
                argv.display()
            )
            .as_bytes(),
        );
        invoke_update_with_limits(&updated, FIXTURE_RUNTIME_LIMIT, 1024).unwrap();
        assert_eq!(fs::read_to_string(argv).unwrap(), "update\n--handoff\n");

        let failed = fake_herdr(b"printf 'updater failed' >&2\nexit 7\n");
        assert!(
            invoke_update_with_limits(&failed, FIXTURE_RUNTIME_LIMIT, 1024)
                .unwrap_err()
                .to_string()
                .contains("updater failed")
        );
        let hanging = fake_herdr(b"sleep 60\n");
        assert!(
            invoke_update_with_limits(&hanging, Duration::from_millis(20), 1024)
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        let excessive = fake_herdr(OVER_32_BYTES);
        assert!(
            invoke_update_with_limits(&excessive, FIXTURE_RUNTIME_LIMIT, 32)
                .unwrap_err()
                .to_string()
                .contains("more than")
        );
    }

    #[test]
    fn remote_update_verifies_and_repairs_live_sessions_offline() {
        let _fixture_guard = lock_process_fixtures();
        let requested = HerdrVersion::new(4, 5, 6);

        let updated = tempfile::tempdir().unwrap();
        let executable = stateful_herdr(updated.path(), "1.2.3", "1.2.3");
        assert_eq!(
            update_session_with_config(&executable, "work", requested, None)
                .unwrap_or_else(|error| panic!("{error:#}")),
            requested
        );
        assert_eq!(
            fs::read_to_string(updated.path().join("running-version")).unwrap(),
            "4.5.6"
        );
        assert_eq!(query(&executable).unwrap(), requested);

        let stale = tempfile::tempdir().unwrap();
        let executable = stateful_herdr(stale.path(), "4.5.6", "1.2.3");
        assert_eq!(
            update_session_with_config(&executable, "work", requested, None).unwrap(),
            requested
        );
        let invocations = fs::read_to_string(stale.path().join("invocations")).unwrap();
        assert!(!invocations.lines().any(|line| line == "update --handoff"));
        assert!(
            invocations.lines().any(|line| {
                line.starts_with("--session work server live-handoff --import-exe ")
                    && line.ends_with("--expected-version 4.5.6")
            }),
            "{invocations}"
        );

        let recovered = tempfile::tempdir().unwrap();
        let executable = stateful_herdr(recovered.path(), "1.2.3", "1.2.3");
        fs::write(recovered.path().join("fail-update"), b"").unwrap();
        assert_eq!(
            update_session_with_config(&executable, "work", requested, None).unwrap(),
            requested
        );
        assert_eq!(
            fs::read_to_string(recovered.path().join("running-version")).unwrap(),
            "4.5.6"
        );

        let failed = tempfile::tempdir().unwrap();
        let executable = stateful_herdr(failed.path(), "1.2.3", "1.2.3");
        fs::write(failed.path().join("fail-handoff"), b"").unwrap();
        let error = update_session_with_config(&executable, "work", requested, None).unwrap_err();
        assert!(is_rolled_back(&error), "{error:#}");
        assert_eq!(query(&executable).unwrap(), HerdrVersion::new(1, 2, 3));
        assert_eq!(
            fs::read_to_string(failed.path().join("running-version")).unwrap(),
            "1.2.3"
        );

        let post_commit_failure = tempfile::tempdir().unwrap();
        let executable = stateful_herdr(post_commit_failure.path(), "1.2.3", "1.2.3");
        fs::write(
            post_commit_failure.path().join("fail-committed-status"),
            b"",
        )
        .unwrap();
        let error = update_session_with_config(&executable, "work", requested, None).unwrap_err();
        assert!(is_rolled_back(&error), "{error:#}");
        assert_eq!(query(&executable).unwrap(), HerdrVersion::new(1, 2, 3));
        assert_eq!(
            fs::read_to_string(post_commit_failure.path().join("running-version")).unwrap(),
            "1.2.3"
        );
    }
}
