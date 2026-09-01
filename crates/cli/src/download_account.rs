use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result, bail, ensure};
use attached_session_sync_protocol::limits::MAX_BUNDLE_ENCODED_BYTES;
use zeroize::Zeroizing;

use crate::sync;

const MAX_BUNDLE_INPUT_BYTES: usize = MAX_BUNDLE_ENCODED_BYTES + 2;

pub fn install(state_dir: &Path, bundle_file: Option<&Path>, bundle_stdin: bool) -> Result<()> {
    install_with(
        state_dir,
        bundle_file,
        bundle_stdin,
        read_stdin_bundle,
        prompt_for_bundle,
    )
}

fn install_with<ReadStdin, Prompt>(
    state_dir: &Path,
    bundle_file: Option<&Path>,
    bundle_stdin: bool,
    read_stdin: ReadStdin,
    prompt: Prompt,
) -> Result<()>
where
    ReadStdin: FnOnce() -> Result<Zeroizing<String>>,
    Prompt: FnOnce() -> Result<Zeroizing<String>>,
{
    ensure!(
        bundle_file.is_none() || !bundle_stdin,
        "--bundle-file conflicts with --bundle-stdin"
    );

    if let Some(path) = bundle_file {
        let bundle = read_bundle_file(path)?;
        return install_bundle(state_dir, bundle, &format!("file {}", path.display()));
    }

    if bundle_stdin {
        let bundle =
            read_stdin().context("could not read a download bundle from standard input")?;
        return install_bundle(state_dir, bundle, "standard input");
    }

    let bundle = prompt().context(
        "could not read a download bundle interactively; pass --bundle-file or --bundle-stdin",
    )?;
    install_bundle(state_dir, bundle, "interactive input")
}

fn read_bundle_file(path: &Path) -> Result<Zeroizing<String>> {
    let file = File::open(path)
        .with_context(|| format!("could not open download bundle file {}", path.display()))?;
    read_bounded_bundle(file)
        .with_context(|| format!("could not read download bundle file {}", path.display()))
}

fn read_stdin_bundle() -> Result<Zeroizing<String>> {
    let stdin = std::io::stdin();
    read_bounded_bundle(stdin.lock())
}

fn read_bounded_bundle(reader: impl Read) -> Result<Zeroizing<String>> {
    let mut contents = Zeroizing::new(String::new());
    reader
        .take((MAX_BUNDLE_INPUT_BYTES + 1) as u64)
        .read_to_string(&mut contents)
        .context("download bundle input is not valid UTF-8")?;
    if contents.len() > MAX_BUNDLE_INPUT_BYTES {
        bail!("download bundle input is too long");
    }
    Ok(contents)
}

fn prompt_for_bundle() -> Result<Zeroizing<String>> {
    let bundle = rpassword::prompt_password("Enter the download bundle (input hidden): ")
        .context("hidden terminal input failed")?;
    Ok(Zeroizing::new(bundle))
}

fn install_bundle(state_dir: &Path, bundle: Zeroizing<String>, source: &str) -> Result<()> {
    let bundle = normalize_bundle(bundle).map_err(|error| {
        anyhow::anyhow!("invalid download bundle supplied by {source}: {error}")
    })?;
    sync::account::install_download(state_dir, bundle.as_bytes()).map_err(|error| {
        anyhow::anyhow!("could not configure the download account from {source}: {error}")
    })?;
    eprintln!("Download account configured.");
    Ok(())
}

fn normalize_bundle(bundle: Zeroizing<String>) -> Result<Zeroizing<String>> {
    if bundle.len() > MAX_BUNDLE_INPUT_BYTES {
        bail!("download bundle is too long (maximum {MAX_BUNDLE_ENCODED_BYTES} bytes)");
    }
    let trimmed = bundle.trim();
    if trimmed.len() > MAX_BUNDLE_ENCODED_BYTES {
        bail!("download bundle is too long (maximum {MAX_BUNDLE_ENCODED_BYTES} bytes)");
    }
    if trimmed.is_empty() {
        bail!("download bundle is empty");
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use attached_session_sync_protocol::account::{AccountBundle, ApiKeyScope};

    fn fixture_bundle(owner: &Path, scope: ApiKeyScope) -> String {
        sync::state::test_support::create_account(owner, "https://sync.example").unwrap();
        sync::state::export_account(owner, scope).unwrap()
    }

    fn secret(value: impl Into<String>) -> Zeroizing<String> {
        Zeroizing::new(value.into())
    }

    #[test]
    fn download_bundle_file_configures_encrypted_downloader_state() {
        let root = crate::test_support::canonical_tempdir();
        let owner = root.path().join("owner");
        let bundle = fixture_bundle(&owner, ApiKeyScope::Download);
        let publish = sync::state::export_account(&owner, ApiKeyScope::Publish).unwrap();
        let published_identity = match AccountBundle::parse(publish.as_bytes()).unwrap() {
            AccountBundle::Scoped(bundle) => bundle.authorized_consumer_identity().unwrap(),
            AccountBundle::Owner(_) => panic!("export produced an owner bundle"),
        };
        let bundle_file = root.path().join("download.bundle");
        std::fs::write(&bundle_file, format!("{bundle}\n")).unwrap();
        let state = root.path().join("downloader");

        install_with(
            &state,
            Some(&bundle_file),
            false,
            || panic!("standard input must not be read"),
            || panic!("the prompt must not be used"),
        )
        .unwrap();

        assert!(sync::state::has_download_account(&state).unwrap());
        let credentials = sync::state::load_account(&state, ApiKeyScope::Download).unwrap();
        let imported_identity = iroh::SecretKey::from_bytes(
            credentials
                .consumer_identity_secret()
                .expect("download import retained the consumer Iroh private key"),
        );
        assert_eq!(
            imported_identity.public().as_bytes(),
            published_identity.as_bytes(),
            "imported download identity must match the public key in the publish bundle"
        );
        assert!(sync::state::load_account(&state, ApiKeyScope::Publish).is_err());
        assert_eq!(
            sync::state::export_account(&state, ApiKeyScope::Download).unwrap(),
            bundle
        );
        let stored = std::fs::read(state.join("sync-account.bundle")).unwrap();
        assert!(crate::local_encryption::is_envelope(&stored));
        assert_ne!(stored.as_slice(), bundle.as_bytes());
    }

    #[test]
    fn explicit_stdin_import_uses_only_standard_input() {
        let root = crate::test_support::canonical_tempdir();
        let bundle = fixture_bundle(&root.path().join("owner"), ApiKeyScope::Download);
        let state = root.path().join("downloader");

        install_with(
            &state,
            None,
            true,
            || Ok(secret(format!("  {bundle}\r\n"))),
            || panic!("the prompt must not be used"),
        )
        .unwrap();

        assert!(sync::state::has_download_account(&state).unwrap());
    }

    #[test]
    fn interactive_import_uses_hidden_prompt_result() {
        let root = crate::test_support::canonical_tempdir();
        let bundle = fixture_bundle(&root.path().join("owner"), ApiKeyScope::Download);
        let state = root.path().join("downloader");

        install_with(
            &state,
            None,
            false,
            || panic!("standard input must not be read"),
            || Ok(secret(format!("  {bundle}  "))),
        )
        .unwrap();

        assert!(sync::state::has_download_account(&state).unwrap());
    }

    #[test]
    fn publish_bundle_is_rejected_without_poisoning_downloader_state() {
        let root = crate::test_support::canonical_tempdir();
        let publish = fixture_bundle(&root.path().join("owner"), ApiKeyScope::Publish);
        let state = root.path().join("downloader");
        crate::secure_state::prepare_private_dir(&state).unwrap();

        let error = install_bundle(&state, secret(publish), "test input")
            .unwrap_err()
            .to_string();

        assert!(error.contains("download-only"), "{error}");
        assert!(!sync::state::has_download_account(&state).unwrap());
    }

    #[test]
    fn input_sources_are_exclusive() {
        let root = crate::test_support::canonical_tempdir();
        let file = root.path().join("download.bundle");
        let error = install_with(
            &root.path().join("downloader"),
            Some(&file),
            true,
            || panic!("standard input must not be read"),
            || panic!("the prompt must not be used"),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("conflicts"), "{error}");
    }

    #[test]
    fn bundle_inputs_are_trimmed_and_bounded_without_echoing_values() {
        assert_eq!(
            normalize_bundle(secret("  c3ludGhldGlj\r\n"))
                .unwrap()
                .as_str(),
            "c3ludGhldGlj"
        );

        let oversized_value = "x".repeat(MAX_BUNDLE_ENCODED_BYTES + 1);
        let error = normalize_bundle(secret(oversized_value.clone()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("too long"), "{error}");
        assert!(!error.contains(&oversized_value[..32]), "{error}");

        let reader_error =
            read_bounded_bundle(std::io::Cursor::new(vec![b'x'; MAX_BUNDLE_INPUT_BYTES + 1]))
                .unwrap_err()
                .to_string();
        assert!(reader_error.contains("too long"), "{reader_error}");
    }

    #[test]
    fn unavailable_interactive_input_has_automation_guidance() {
        let root = crate::test_support::canonical_tempdir();
        let error = install_with(
            &root.path().join("downloader"),
            None,
            false,
            || panic!("standard input must not be read"),
            || Err(anyhow::anyhow!("synthetic terminal failure")),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("--bundle-file"), "{error}");
        assert!(error.contains("--bundle-stdin"), "{error}");
    }
}
