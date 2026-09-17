//! Black-box lifecycle tests, with no user credentials, SSH, or Herdr state.
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use fs4::FileExt;
use serde_json::json;

const WAIT: Duration = Duration::from_secs(45);

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let fixture = Self { root };
        for path in [
            "bin",
            "home/.ssh/attached",
            "state",
            "plugins/herdr",
            "target/release",
        ] {
            fs::create_dir_all(fixture.path(path)).unwrap();
        }
        fs::copy(
            env!("CARGO_BIN_EXE_attached-herdr-plugin"),
            fixture.binary(),
        )
        .unwrap();
        fixture.plugin(true);
        fixture.hosts(&[1]);
        fs::write(fixture.path("machines.json"), "[]").unwrap();
        fixture.script("herdr", r#"
case "$*" in
  'plugin list --json') cat "$FIXTURE/plugin.json";;
  'machine list --json') cat "$FIXTURE/machines.json";;
  'session list --json') printf '%s\n' '{"sessions":[{"name":"work","running":true,"socket_path":"/fixture/herdr.sock"}]}' ;;
  '--session work plugin action invoke attached.discovery.ensure') printf 'ensure\n' >> "$FIXTURE/events";;
  *)
    if [ "$1 $2" = 'machine add' ]; then
      [ "$4" = '--label' ] && [ "$#" = 5 ] || exit 81
      # The worker must not supply stdin or permit SSH askpass.
      if read -r input; then exit 82; fi
      [ "$SSH_ASKPASS_REQUIRE" = 'never' ] || exit 83
      printf 'add %s %s\n' "$3" "$5" >> "$FIXTURE/events"
    elif [ "$1 $2" = 'notification show' ]; then
      [ "$HERDR_SOCKET_PATH" = '/fixture/herdr.sock' ] || exit 84
      printf 'toast %s\n' "$5" >> "$FIXTURE/events"
    else
      printf 'unexpected Herdr args: %s\n' "$*" >&2; exit 90
    fi;;
esac
"#);
        fixture.script(
            "attached",
            r#"
case "$*" in
  'sessions list --json') cat "$FIXTURE/hosts.json";;
  'export-ssh-config')
    printf 'exporter-start\n' >> "$FIXTURE/events"
    trap 'printf "exporter-stop\n" >> "$FIXTURE/events"; exit 0' TERM INT HUP
    while :; do sleep 1; done;;
  *) exit 91;;
esac
"#,
        );
        fixture.script("ssh", r#"
[ "$1" = '-G' ] && [ "$#" = 2 ] || exit 92
printf 'hostname %s\nproxycommand /attached __ssh-local-proxy /fixture/socket\nbatchmode yes\nstricthostkeychecking true\n' "$2"
"#);
        fixture
    }
    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }
    fn binary(&self) -> PathBuf {
        self.path("target/release/attached-herdr-plugin")
    }
    fn script(&self, name: &str, script: &str) {
        let path = self.path(&format!("bin/{name}"));
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{script}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn plugin(&self, enabled: bool) {
        self.json(
            "plugin.json",
            json!({"result":{"plugins":[{
                "plugin_id":"attached.discovery", "enabled":enabled,
                "plugin_root":self.path("plugins/herdr"), "warnings":[]
            }]}}),
        );
    }
    fn hosts(&self, ids: &[u8]) {
        self.json(
            "hosts.json",
            json!(ids.iter().map(|id| {
            let id = format!("{id:02x}").repeat(32);
            json!({"host":"office", "endpoint_id":id,"ssh_target":format!("attached-{id}")})
        }).collect::<Vec<_>>()),
        );
    }
    fn json(&self, name: &str, value: serde_json::Value) {
        let path = self.path(name);
        let temporary = path.with_extension("new");
        fs::write(&temporary, value.to_string()).unwrap();
        fs::rename(temporary, path).unwrap();
    }
    fn command(&self) -> Command {
        let mut command = Command::new(self.binary());
        command
            .env_clear()
            .env("HOME", self.path("home"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("FIXTURE", self.root.path())
            .env("HERDR_BIN_PATH", self.path("bin/herdr"))
            .env("HERDR_PLUGIN_STATE_DIR", self.path("state"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
    fn start(&self) -> Running {
        Running(self.command().arg("run").spawn().unwrap())
    }
    fn events(&self) -> String {
        fs::read_to_string(self.path("events")).unwrap_or_default()
    }
    fn until(&self, condition: impl Fn(&str) -> bool) {
        let start = Instant::now();
        loop {
            let events = self.events();
            if condition(&events) {
                break;
            }
            assert!(
                start.elapsed() < WAIT,
                "events: {events}\nlog: {}",
                fs::read_to_string(self.path("state/discovery.log")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

struct Running(Child);
impl Running {
    fn signal(&self, signal: rustix::process::Signal) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
            let _ = rustix::process::kill_process(pid, signal);
        }
    }
    fn wait(&mut self) {
        let start = Instant::now();
        while self.0.try_wait().unwrap().is_none() {
            assert!(start.elapsed() < WAIT, "worker did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn stop(&mut self) {
        self.signal(rustix::process::Signal::TERM);
        self.wait();
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.stop();
        }
    }
}

#[test]
fn worker_polls_new_publishers_without_interaction_and_survives_restart_without_duplicates() {
    let fixture = Fixture::new();
    let mut worker = fixture.start();
    fixture.until(|events| events.contains("toast"));
    // Simultaneous startup/focus hooks may not create another discovery loop.
    let mut duplicate = fixture.start();
    duplicate.wait();
    fixture.hosts(&[1, 2]);
    fixture.until(|events| {
        events
            .lines()
            .filter(|line| line.starts_with("toast"))
            .count()
            == 2
    });
    worker.stop();
    fixture.until(|events| events.contains("exporter-stop"));
    let mut restarted = fixture.start();
    fixture.until(|events| {
        events
            .lines()
            .filter(|line| *line == "exporter-start")
            .count()
            == 2
    });
    restarted.stop();
    let events = fixture.events();
    assert_eq!(
        events
            .lines()
            .filter(|line| line.starts_with("add "))
            .count(),
        2,
        "{events}"
    );
    assert_eq!(
        events
            .lines()
            .filter(|line| line.starts_with("toast "))
            .count(),
        2,
        "{events}"
    );
}

#[test]
fn disabling_and_uninstalling_stop_only_the_owned_exporter() {
    let fixture = Fixture::new();
    let mut worker = fixture.start();
    fixture.until(|events| events.contains("toast"));
    fixture.plugin(false);
    fixture.until(|events| events.contains("exporter-stop"));
    assert!(worker.0.try_wait().unwrap().is_none()); // Dormant until re-enabled.
    fixture.plugin(true);
    fixture.until(|events| {
        events
            .lines()
            .filter(|line| *line == "exporter-start")
            .count()
            == 2
    });
    fixture.json("plugin.json", json!({"result":{"plugins":[]}}));
    worker.wait();
    assert_eq!(
        fixture
            .events()
            .lines()
            .filter(|line| *line == "exporter-stop")
            .count(),
        2
    );
}

#[test]
fn external_exporter_is_reused_and_never_terminated() {
    let fixture = Fixture::new();
    let file = fs::File::create(fixture.path("home/.ssh/attached/broker.lock")).unwrap();
    FileExt::lock(&file).unwrap();
    let mut worker = fixture.start();
    fixture.until(|events| events.contains("toast"));
    worker.stop();
    assert!(!fixture.events().contains("exporter-"));
}

#[test]
fn installation_waits_for_committed_checkout_before_activating_a_running_named_session() {
    let fixture = Fixture::new();
    let metadata = fixture.binary().metadata().unwrap();
    // An existing registration pointing to an older binary must not be started.
    let previous = fixture.path("previous/plugins/herdr");
    fs::create_dir_all(&previous).unwrap();
    fixture.json(
        "plugin.json",
        json!({"result":{"plugins":[{
            "plugin_id":"attached.discovery", "enabled":true,"plugin_root":previous,"warnings":[]
        }]}}),
    );
    let mut waiter = Running(
        fixture
            .command()
            .args([
                "__install-wait",
                &metadata.dev().to_string(),
                &metadata.ino().to_string(),
            ])
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(400));
    assert!(!fixture.events().contains("ensure"));
    fixture.plugin(true);
    fixture.until(|events| events.contains("ensure"));
    waiter.wait();
}

#[test]
fn install_hook_exits_immediately_and_no_server_defers_to_startup() {
    let fixture = Fixture::new();
    fixture.script(
        "herdr",
        r#"
case "$*" in
  'plugin list --json') cat "$FIXTURE/plugin.json";;
  'session list --json') printf '{"sessions":[]}'; printf 'no-server\n' >> "$FIXTURE/events";;
  *) exit 99;;
esac
"#,
    );
    let start = Instant::now();
    let output = fixture
        .command()
        .arg("install")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(start.elapsed() < Duration::from_secs(3)); // No inherited capture pipes.
    fixture.until(|events| events.contains("no-server"));
    assert!(!fixture.events().contains("ensure"));
}

#[test]
fn malformed_discovery_never_runs_machine_add_or_starts_an_exporter() {
    let fixture = Fixture::new();
    fs::write(fixture.path("hosts.json"), "not JSON").unwrap();
    let mut worker = fixture.start();
    let start = Instant::now();
    while !fs::read_to_string(fixture.path("state/discovery.log"))
        .unwrap_or_default()
        .contains("invalid Attached JSON")
    {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(20));
    }
    worker.stop();
    assert!(fixture.events().is_empty());
    assert!(!Path::new(&fixture.path("state/discovery-state.json")).exists());
}
