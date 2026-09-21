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

pub(crate) async fn candidate_context(archive: &Path, runtime_image: &str) -> Result<Vec<u8>> {
    let name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid archive filename")?;
    let package = name
        .strip_suffix(".tar.xz")
        .context("candidate must be a .tar.xz archive")?;
    let checksum = archive.with_file_name(format!("{name}.sha256"));
    let binary = executable(
        &std::fs::read(archive)?,
        &std::fs::read_to_string(checksum)?,
        &format!("{package}/attached"),
    )
    .await?;
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("Dockerfile"),
        format!("FROM {runtime_image}\nCOPY attached /usr/local/bin/attached\n"),
    )?;
    let path = directory.path().join("attached");
    std::fs::write(&path, binary)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    // These temporary files contain only the public candidate binary, never
    // credentials. USTAR without xattrs avoids leaking host metadata and macOS
    // AppleDouble/provenance records unsupported by the Linux Docker daemon.
    let context = run(
        "tar",
        &strings(&[
            "--format=ustar",
            "--no-xattrs",
            "-cf",
            "-",
            "-C",
            &directory.path().to_string_lossy(),
            "Dockerfile",
            "attached",
        ]),
        None,
        false,
        Duration::from_secs(30),
    )
    .await?;
    ensure!(
        context.code == 0,
        "could not prepare candidate Docker context"
    );
    Ok(context.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn candidate_uses_verified_archive_not_source_build_or_download() {
        use crate::{
            docker::tests::Fake,
            smoke::{Options, Smoke},
        };
        let directory = tempfile::tempdir().unwrap();
        let package = "attached-x86_64-unknown-linux-gnu";
        std::fs::create_dir(directory.path().join(package)).unwrap();
        std::fs::write(
            directory.path().join(package).join("attached"),
            b"\x7fELFbinary",
        )
        .unwrap();
        let packed = run(
            "tar",
            &strings(&[
                "-cJf",
                "-",
                "-C",
                &directory.path().to_string_lossy(),
                package,
            ]),
            None,
            false,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(packed.code, 0);
        let archive = directory.path().join(format!("{package}.tar.xz"));
        let checksum = directory.path().join(format!("{package}.tar.xz.sha256"));
        std::fs::write(&archive, &packed.stdout).unwrap();
        std::fs::write(&checksum, digest(&packed.stdout)).unwrap();
        let mut test = Smoke::new(
            Fake::default(),
            Options {
                service: String::new(),
                release: None,
                archive: Some(archive),
            },
        )
        .unwrap();
        test.build().await.unwrap();
        {
            let calls = test.executor.calls.lock().unwrap();
            assert!(calls[0].args.contains(&"runtime".into()));
            assert!(calls.iter().all(|s| {
                !s.args
                    .iter()
                    .any(|arg| arg.starts_with("ATTACHED_VERSION="))
            }));
            assert!(
                calls
                    .last()
                    .unwrap()
                    .args
                    .iter()
                    .any(|arg| arg.ends_with("Dockerfile.backend"))
            );
        }
        let context = test.executor.calls.lock().unwrap()[1]
            .input
            .clone()
            .unwrap();
        // First record must be the regular Dockerfile, not a PAX/xattr header
        // importing macOS provenance metadata unsupported by the Linux daemon.
        assert_eq!(&context[..10], b"Dockerfile");
        assert_eq!(context[156], b'0');
        let tar = directory.path().join("context.tar");
        std::fs::write(&tar, context).unwrap();
        let listed = run(
            "tar",
            &strings(&["-tf", &tar.to_string_lossy()]),
            None,
            false,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(
            String::from_utf8(listed.stdout).unwrap(),
            "Dockerfile\nattached\n"
        );
        let executable = run(
            "tar",
            &strings(&["-xOf", &tar.to_string_lossy(), "attached"]),
            None,
            false,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(executable.stdout, b"\x7fELFbinary");
        test.executor.calls.lock().unwrap().clear();
        std::fs::write(checksum, "0".repeat(64)).unwrap();
        assert!(
            test.build()
                .await
                .unwrap_err()
                .to_string()
                .contains("checksum mismatch")
        );
        assert!(test.executor.calls.lock().unwrap().is_empty());
    }

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
