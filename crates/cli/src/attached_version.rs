use std::{ffi::OsStr, path::Path, time::Duration};

use anyhow::{Context, Result, bail, ensure};
pub use attached_tunnel_protocol::AttachedVersion;

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const QUERY_OUTPUT_LIMIT: u64 = 4 * 1024;

pub const fn current() -> AttachedVersion {
    AttachedVersion::new(
        parse_compile_time_component(env!("CARGO_PKG_VERSION_MAJOR")),
        parse_compile_time_component(env!("CARGO_PKG_VERSION_MINOR")),
        parse_compile_time_component(env!("CARGO_PKG_VERSION_PATCH")),
    )
}

const fn parse_compile_time_component(value: &str) -> u32 {
    let bytes = value.as_bytes();
    let mut parsed = 0_u32;
    let mut index = 0;
    while index < bytes.len() {
        let digit = bytes[index] - b'0';
        parsed = parsed * 10 + digit as u32;
        index += 1;
    }
    parsed
}

pub fn query(executable: &Path) -> Result<AttachedVersion> {
    let output = crate::bounded_process::run(
        executable,
        [OsStr::new("--version")].as_slice(),
        QUERY_TIMEOUT,
        QUERY_OUTPUT_LIMIT,
    )?;
    ensure!(
        output.status.success(),
        "Attached executable {} --version exited with status {}: {}",
        executable.display(),
        output.status,
        crate::bounded_process::diagnostic(&output.stderr)
    );
    parse_version_output(&output.stdout).with_context(|| {
        format!(
            "could not parse {} --version output as `attached X.Y.Z`: {}",
            executable.display(),
            crate::bounded_process::diagnostic(&output.stdout)
        )
    })
}

pub fn parse_version_output(output: &[u8]) -> Result<AttachedVersion> {
    let output = output.strip_suffix(b"\n").unwrap_or(output);
    let version = output
        .strip_prefix(b"attached ")
        .context("expected the `attached ` prefix")?;
    let mut components = version.split(|byte| *byte == b'.');
    let mut component = || -> Result<u32> {
        let bytes = components
            .next()
            .context("expected three numeric version components")?;
        ensure!(!bytes.is_empty(), "version component is empty");
        let text = std::str::from_utf8(bytes).context("version component is not UTF-8")?;
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("version component is not an unsigned integer");
        }
        text.parse().context("version component is too large")
    };
    let parsed = AttachedVersion::new(component()?, component()?, component()?);
    ensure!(
        components.next().is_none(),
        "expected three numeric version components"
    );
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stable_attached_version_output() {
        assert_eq!(
            parse_version_output(b"attached 1.2.3\n").unwrap(),
            AttachedVersion::new(1, 2, 3)
        );
        for invalid in [
            b"attached 1.2".as_slice(),
            b"attached 1.2.3.4",
            b"attached 1.2.x",
            b"attached 1.2.3 extra",
            b"other 1.2.3",
        ] {
            assert!(
                parse_version_output(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn compile_time_version_matches_the_package() {
        assert_eq!(current().to_string(), env!("CARGO_PKG_VERSION"));
    }
}
