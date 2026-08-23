use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail, ensure};
pub use attached_tunnel_protocol::HerdrVersion;

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

pub fn update(executable: &Path) -> Result<HerdrVersion> {
    update_with_limits(executable, Duration::from_secs(120), 64 * 1024)
}

fn update_with_limits(
    executable: &Path,
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<HerdrVersion> {
    let output = bounded_process::run(
        executable,
        [
            std::ffi::OsStr::new("update"),
            std::ffi::OsStr::new("--handoff"),
        ]
        .as_slice(),
        runtime_limit,
        capture_limit,
    )?;
    ensure!(
        output.status.success(),
        "remote `herdr update` exited with status {}: {}",
        output.status,
        bounded_process::diagnostic(&output.stderr)
    );
    query(executable).context("remote Herdr version query failed after update")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, sync::Mutex, time::Instant};

    const FIXTURE_RUNTIME_LIMIT: Duration = Duration::from_secs(10);
    const OVER_32_BYTES: &[u8] = b"printf '0123456789abcdef0123456789abcdefX'\n";
    static PROCESS_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fake_herdr(body: &[u8]) -> tempfile::TempPath {
        let path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
        let mut script = b"#!/bin/sh\n".to_vec();
        script.extend_from_slice(body);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
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
        let _fixture_guard = PROCESS_FIXTURE_LOCK.lock().unwrap();
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
    fn update_uses_fixed_operation_and_verifies_exact_installed_version() {
        let _fixture_guard = PROCESS_FIXTURE_LOCK.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let argv = root.path().join("argv");
        let updated = fake_herdr(
            format!(
                "if [ \"$1\" = update ]; then printf '%s\\n' \"$@\" > '{}'; exit 0; fi\nif [ \"$1\" = --version ]; then printf 'herdr 4.5.6\\n'; exit 0; fi\nexit 9\n",
                argv.display()
            )
            .as_bytes(),
        );
        assert_eq!(
            update_with_limits(&updated, FIXTURE_RUNTIME_LIMIT, 1024).unwrap(),
            HerdrVersion::new(4, 5, 6)
        );
        assert_eq!(fs::read_to_string(argv).unwrap(), "update\n--handoff\n");

        let failed = fake_herdr(b"printf 'updater failed' >&2\nexit 7\n");
        assert!(
            update_with_limits(&failed, FIXTURE_RUNTIME_LIMIT, 1024)
                .unwrap_err()
                .to_string()
                .contains("updater failed")
        );
        let hanging = fake_herdr(b"sleep 60\n");
        assert!(
            update_with_limits(&hanging, Duration::from_millis(20), 1024)
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        let excessive = fake_herdr(OVER_32_BYTES);
        assert!(
            update_with_limits(&excessive, FIXTURE_RUNTIME_LIMIT, 32)
                .unwrap_err()
                .to_string()
                .contains("more than")
        );
    }
}
