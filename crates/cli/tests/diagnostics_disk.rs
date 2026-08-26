#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    process::{Command, Stdio},
};

fn log_paths(log_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(log_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name == "attached.log" || name.starts_with("attached.log."))
        })
        .collect()
}

#[test]
fn process_creates_private_bounded_disk_diagnostics() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_attached"))
        .env("HOME", home.path())
        .args([
            "account",
            "export",
            "--type",
            "download",
            "--output",
            "unused.bundle",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());

    let log_dir = home.path().join(".config/attached/logs");
    let metadata = fs::metadata(&log_dir).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);

    let logs = log_paths(&log_dir);
    assert!(!logs.is_empty(), "startup did not create a disk log");
    let mut contents = String::new();
    for log in &logs {
        contents.push_str(&fs::read_to_string(log).unwrap());
    }
    assert!(
        contents.contains("diagnostics initialized"),
        "orderly process exit did not flush its startup event: {contents:?}"
    );
    assert!(
        !contents.contains("unused.bundle"),
        "argument leaked: {contents:?}"
    );
    assert!(
        logs.len() <= 5,
        "disk log retention was not bounded: {logs:?}"
    );
    for log in logs {
        let metadata = fs::metadata(&log).unwrap();
        assert!(metadata.is_file(), "unexpected log entry: {log:?}");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert!(metadata.len() <= 1024 * 1024, "oversized log: {log:?}");
    }
    let lock = fs::metadata(log_dir.join(".attached.log.lock")).unwrap();
    assert_eq!(lock.permissions().mode() & 0o7777, 0o600);
}

#[test]
fn restrictive_umask_does_not_prevent_private_disk_diagnostics() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new("sh")
        .args([
            "-c",
            "umask 0777; exec \"$1\" account export --type download --output unused.bundle",
            "sh",
        ])
        .arg(env!("CARGO_BIN_EXE_attached"))
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("failed to prepare private diagnostics directory"),
        "{stderr}"
    );

    let log_dir = home.path().join(".config/attached/logs");
    let logs = log_paths(&log_dir);
    assert!(!logs.is_empty(), "no disk diagnostics were created");
    let contents = logs
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect::<String>();
    assert!(contents.contains("diagnostics initialized"), "{contents}");
    assert_eq!(
        fs::metadata(log_dir).unwrap().permissions().mode() & 0o7777,
        0o700
    );
}

#[test]
fn concurrent_processes_rotate_without_losing_or_interleaving_startup_events() {
    let home = tempfile::tempdir().unwrap();
    let log_dir = home.path().join(".config/attached/logs");
    fs::create_dir_all(&log_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(
        home.path().join(".config/attached"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let current = log_dir.join("attached.log");
    fs::write(&current, vec![b' '; 1024 * 1024 - 128]).unwrap();
    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();

    let mut children = (0..8)
        .map(|index| {
            Command::new(env!("CARGO_BIN_EXE_attached"))
                .args([
                    "account",
                    "export",
                    "--type",
                    "download",
                    "--output",
                    &format!("unused-{index}.bundle"),
                ])
                .env("HOME", home.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    for child in &mut children {
        assert!(!child.wait().unwrap().success());
    }

    let logs = log_paths(&log_dir);
    assert!(!logs.is_empty());
    assert!(logs.len() <= 5, "too many retained logs: {logs:?}");
    let mut startup_events = 0;
    for log in logs {
        let metadata = fs::metadata(&log).unwrap();
        assert!(metadata.len() <= 1024 * 1024, "oversized log: {log:?}");
        let contents = fs::read_to_string(&log).unwrap();
        for line in contents
            .lines()
            .filter(|line| line.contains("diagnostics initialized"))
        {
            assert!(line.contains("log_retention_files=5"), "{line}");
            assert!(line.contains("log_file_limit_bytes=1048576"), "{line}");
            startup_events += 1;
        }
    }
    assert_eq!(startup_events, 8);
}
