//! Official Linux release installation. Downloads and extraction never execute an installer.
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::process::{run, strings};

pub(crate) fn validate_version(version: &str) -> Result<String> {
    let parts: Vec<_> = version.split('.').collect();
    ensure!(
        version.len() < 64
            && parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())),
        "release must be a stable version such as 0.3.5"
    );
    Ok(version.to_owned())
}

fn asset(version: &str, architecture: &str) -> Result<String> {
    validate_version(version)?;
    ensure!(
        matches!(architecture, "aarch64" | "x86_64"),
        "unsupported Linux architecture"
    );
    Ok(format!(
        "https://github.com/pvalletbo/attached/releases/download/v{version}/attached-{architecture}-unknown-linux-gnu.tar.xz"
    ))
}

async fn download(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(60))
        .build()?;
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 128 * 1024 * 1024,
            "release download exceeded its bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) async fn executable(archive: &[u8], checksum: &str, member: &str) -> Result<Vec<u8>> {
    let expected = checksum
        .split_whitespace()
        .next()
        .context("missing release checksum")?;
    ensure!(
        digest(archive) == expected,
        "release archive checksum mismatch"
    );
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("archive.tar.xz");
    std::fs::write(&path, archive)?;
    // Extract just this member to stdout, never arbitrary archive paths or links
    // into a filesystem. An absent/link/non-Linux payload fails the ELF check.
    let result = run(
        "tar",
        &strings(&["-xJOf", &path.to_string_lossy(), member]),
        None,
        false,
        Duration::from_secs(30),
    )
    .await?;
    ensure!(
        result.code == 0 && result.stdout.starts_with(b"\x7fELF"),
        "release archive has no Linux executable at the expected path"
    );
    Ok(result.stdout)
}

pub(crate) async fn install(version: &str) -> Result<()> {
    let url = asset(version, std::env::consts::ARCH)?;
    let name = url.rsplit('/').next().context("missing asset name")?;
    let member = format!("{}/attached", name.trim_end_matches(".tar.xz"));
    let binary = executable(
        &download(&url).await?,
        &String::from_utf8(download(&format!("{url}.sha256")).await?)?,
        &member,
    )
    .await?;
    let destination = Path::new("/usr/local/bin/attached");
    std::fs::write(destination, binary)?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_version_and_architecture_are_pinned_not_interpolated_unsafely() {
        for architecture in ["aarch64", "x86_64"] {
            assert_eq!(
                asset("0.3.5", architecture).unwrap(),
                format!(
                    "https://github.com/pvalletbo/attached/releases/download/v0.3.5/attached-{architecture}-unknown-linux-gnu.tar.xz"
                )
            );
        }
        for invalid in [
            "latest",
            "v0.3.5",
            "0.3.5;echo bad",
            "../foo",
            "0.3",
            "0..5",
        ] {
            assert!(asset(invalid, "x86_64").is_err());
        }
        assert!(asset("0.3.5", "unknown").is_err());
    }

    #[tokio::test]
    async fn checksum_is_verified_before_archive_extraction() {
        assert!(
            executable(b"bad archive", "", "member")
                .await
                .unwrap_err()
                .to_string()
                .contains("missing release checksum")
        );
        assert!(
            executable(b"bad archive", &"0".repeat(64), "member")
                .await
                .unwrap_err()
                .to_string()
                .contains("checksum mismatch")
        );
    }

    #[tokio::test]
    async fn extracts_only_expected_linux_payload() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package");
        std::fs::create_dir(&package).unwrap();
        std::fs::write(package.join("attached"), b"\x7fELFbinary").unwrap();
        let output = run(
            "tar",
            &strings(&["-cJf", "-", "-C", &dir.path().to_string_lossy(), "package"]),
            None,
            false,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(output.code, 0);
        let checksum = format!("{}  archive.tar.xz\n", digest(&output.stdout));
        assert_eq!(
            executable(&output.stdout, &checksum, "package/attached")
                .await
                .unwrap(),
            b"\x7fELFbinary"
        );
        assert!(
            executable(&output.stdout, &checksum, "wrong/attached")
                .await
                .is_err()
        );
    }
}
