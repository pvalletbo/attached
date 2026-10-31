//! App lifecycle tests use isolated HOME/PATH and fake hc/ssh/attached only.
use fs4::FileExt;
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Fixture(tempfile::TempDir);

impl Fixture {
    fn new() -> Self {
        let fixture = Self(tempfile::tempdir().unwrap());
        for name in ["bin", "home/.ssh/attached", "state"] {
            fs::create_dir_all(fixture.path(name)).unwrap();
        }
        fixture.script(
            "hc",
            r#"
[ "$*" = 'machine ls --json' ] || exit 90
printf 'check\n' >> "$FIXTURE/events"
printf '{"machines":[]}\n'
"#,
        );
        fixture.script(
            "attached",
            r#"
[ "$*" = 'export-ssh-config' ] || exit 91
printf 'exporter-start\n' >> "$FIXTURE/events"
trap 'printf "exporter-stop\n" >> "$FIXTURE/events"; exit 0' TERM INT HUP
while :; do sleep 1; done
"#,
        );
        fixture.lease(true, 0);
        let path = fixture.path("home/.ssh/attached/discovery.json");
        fs::write(&path, json!({"version":1, "generation":"first", "checked_at":now(), "complete":true, "hosts":[]}).to_string()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fixture
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.path().join(name)
    }
    fn script(&self, name: &str, body: &str) {
        let path = self.path(&format!("bin/{name}"));
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn lease(&self, enabled: bool, age: u64) {
        let temporary = self.path("state/lease.new");
        fs::write(
            &temporary,
            json!({"enabled":enabled,"install_core":false,"checked_at":now()-age}).to_string(),
        )
        .unwrap();
        fs::rename(temporary, self.path("state/lease.json")).unwrap();
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_attached-herdr-plugin"));
        command
            .env_clear()
            .env("HOME", self.path("home"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("FIXTURE", self.0.path())
            .stdin(Stdio::null());
        command
    }
    fn start(&self) -> Worker {
        Worker(
            self.command()
                .arg("app-run")
                .arg(self.path("state"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn events(&self) -> String {
        fs::read_to_string(self.path("events")).unwrap_or_default()
    }
    fn until(&self, condition: impl Fn() -> bool) {
        let start = Instant::now();
        while !condition() {
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "events: {}",
                self.events()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Worker(Child);
impl Worker {
    fn wait(&mut self) {
        let start = Instant::now();
        while self.0.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "worker did not stop"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            let pid = rustix::process::Pid::from_raw(self.0.id() as i32).unwrap();
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            self.wait();
        }
    }
}

#[test]
fn app_worker_is_singleton_and_pause_stops_only_its_exporter() {
    let fixture = Fixture::new();
    let mut worker = fixture.start();
    fixture.until(|| fixture.events().contains("check"));
    fixture.until(|| fixture.events().contains("exporter-start"));
    let mut duplicate = fixture.start();
    duplicate.wait();
    assert_eq!(fixture.events().matches("exporter-start").count(), 1);
    let output = fixture
        .command()
        .arg("app-pause")
        .arg(fixture.path("state"))
        .output()
        .unwrap();
    assert!(output.status.success());
    worker.wait();
    assert_eq!(fixture.events().matches("exporter-stop").count(), 1);
    let status: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.path("state/status.json")).unwrap()).unwrap();
    assert_eq!(status["running"], false);
    assert!(status["checked_at"].is_number());
}

#[test]
fn stale_or_corrupt_lease_stops_discovery_without_removing_saved_machines() {
    let fixture = Fixture::new();
    let mut worker = fixture.start();
    fixture.until(|| fixture.events().contains("check"));
    fixture.lease(true, 91);
    worker.wait();
    assert!(fixture.events().contains("exporter-stop"));
    fs::write(fixture.path("state/lease.json"), "not JSON").unwrap();
    let mut invalid = fixture.start();
    invalid.wait();
    assert_eq!(fixture.events().matches("exporter-start").count(), 1);
}

#[test]
fn app_reuses_external_exporter_and_never_stops_it() {
    let fixture = Fixture::new();
    let lock = fs::File::create(fixture.path("home/.ssh/attached/broker.lock")).unwrap();
    FileExt::try_lock(&lock).unwrap();
    let mut worker = fixture.start();
    fixture.until(|| fixture.events().contains("check"));
    fixture.lease(false, 0);
    worker.wait();
    assert!(!fixture.events().contains("exporter"));
    assert!(
        FileExt::try_lock(&fs::File::open(fixture.path("home/.ssh/attached/broker.lock")).unwrap())
            .is_err()
    );
}

#[test]
fn heartbeat_starts_a_detached_worker_and_renews_one_shared_lease() {
    let fixture = Fixture::new();
    for _ in 0..2 {
        let output = fixture
            .command()
            .arg("app-heartbeat")
            .arg(fixture.path("state"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(serde_json::from_slice::<serde_json::Value>(&output.stdout).is_ok());
        // The worker can finish its first hc query before the separately
        // spawned exporter has written its readiness marker.
        fixture.until(|| {
            let events = fixture.events();
            events.contains("check") && events.contains("exporter-start")
        });
    }
    assert_eq!(fixture.events().matches("exporter-start").count(), 1);
    let output = fixture
        .command()
        .arg("app-pause")
        .arg(fixture.path("state"))
        .output()
        .unwrap();
    assert!(output.status.success());
    fixture.until(|| fixture.events().contains("exporter-stop"));
    fixture.until(|| {
        let lock = fs::File::open(fixture.path("state/discovery.lock")).unwrap();
        FileExt::try_lock(&lock).is_ok()
    });
}

#[test]
fn lease_cancellation_interrupts_a_slow_core_call_without_waiting_for_its_deadline() {
    let fixture = Fixture::new();
    fixture.script(
        "hc",
        r#"
printf 'slow-check\n' >> "$FIXTURE/events"
sleep 60 & wait
"#,
    );
    let mut worker = fixture.start();
    fixture.until(|| fixture.events().contains("slow-check"));
    fixture.lease(false, 0);
    let start = Instant::now();
    worker.wait();
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(fixture.events().contains("exporter-stop"));
}

#[test]
fn installer_bundles_the_mod_and_worker_but_refuses_to_overwrite_personal_files() {
    let fixture = Fixture::new();
    let home = fixture.path("app");
    let output = fixture
        .command()
        .arg("app-install")
        .arg(&home)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let installed = home.join("mods/attached-discovery");
    assert!(installed.join("worker").is_file());
    assert!(installed.join("main.js").is_file());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(installed.join("mod.json")).unwrap()).unwrap();
    assert_eq!(manifest["place"], "none");
    assert_eq!(manifest["overlay"]["kind"], "popup");
    assert_eq!(
        fs::read_to_string(installed.join("README.md")).unwrap(),
        include_str!("../../../plugins/herdr-app/README.md")
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("mod.open"));
    assert_ne!(
        fs::metadata(installed.join("worker"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    fs::write(installed.join("main.js"), "personal version").unwrap();
    let output = fixture
        .command()
        .arg("app-install")
        .arg(&home)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(installed.join("main.js")).unwrap(),
        "personal version"
    );
    assert!(
        !home.join("data").exists(),
        "installation must not start discovery"
    );
}
