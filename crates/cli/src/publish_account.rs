use std::{env, ffi::OsString, fs::File, io::Read, path::Path};

use anyhow::{Context, Result, bail};
use attached_session_sync_protocol::{account::ApiKeyScope, limits::MAX_BUNDLE_ENCODED_BYTES};
use zeroize::Zeroizing;

use crate::sync;

pub const PUBLISH_BUNDLE_ENV: &str = "ATTACHED_PUBLISH_BUNDLE";
const MAX_BUNDLE_INPUT_BYTES: usize = MAX_BUNDLE_ENCODED_BYTES + 2;

pub fn ensure_configured(state_dir: &Path, bundle_file: Option<&Path>) -> Result<()> {
    let environment_bundle = read_environment_bundle()?;
    ensure_configured_with(
        state_dir,
        environment_bundle,
        bundle_file,
        prompt_for_bundle,
    )
}

fn ensure_configured_with<Prompt>(
    state_dir: &Path,
    environment_bundle: Option<Zeroizing<String>>,
    bundle_file: Option<&Path>,
    prompt: Prompt,
) -> Result<()>
where
    Prompt: FnOnce() -> Result<Zeroizing<String>>,
{
    if let Some(bundle) = environment_bundle {
        return install_bundle(
            state_dir,
            bundle,
            &format!("environment variable {PUBLISH_BUNDLE_ENV}"),
        );
    }

    if let Some(path) = bundle_file {
        let bundle = read_bundle_file(path)?;
        return install_bundle(state_dir, bundle, &format!("file {}", path.display()));
    }

    if sync::state::load_account_optional(state_dir, ApiKeyScope::Publish)
        .context("could not inspect the configured publish account")?
        .is_some()
    {
        return Ok(());
    }

    let bundle = prompt().with_context(|| {
        format!(
            "could not read a publish bundle interactively; set {PUBLISH_BUNDLE_ENV} or pass --bundle-file"
        )
    })?;
    install_bundle(state_dir, bundle, "interactive input")
}

fn read_environment_bundle() -> Result<Option<Zeroizing<String>>> {
    let Some(value) = env::var_os(PUBLISH_BUNDLE_ENV) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    os_string_into_secret(value).map(Some)
}

fn os_string_into_secret(value: OsString) -> Result<Zeroizing<String>> {
    value
        .into_string()
        .map(Zeroizing::new)
        .map_err(|_| anyhow::anyhow!("{PUBLISH_BUNDLE_ENV} must contain valid UTF-8"))
}

fn read_bundle_file(path: &Path) -> Result<Zeroizing<String>> {
    let file = File::open(path)
        .with_context(|| format!("could not open publish bundle file {}", path.display()))?;
    let mut contents = Zeroizing::new(String::new());
    file.take((MAX_BUNDLE_INPUT_BYTES + 1) as u64)
        .read_to_string(&mut contents)
        .with_context(|| format!("could not read publish bundle file {}", path.display()))?;
    if contents.len() > MAX_BUNDLE_INPUT_BYTES {
        bail!("publish bundle file is too long");
    }
    Ok(contents)
}

fn prompt_for_bundle() -> Result<Zeroizing<String>> {
    let bundle = rpassword::prompt_password(
        "No publish bundle is configured.\nEnter the publish bundle (input hidden): ",
    )
    .context("hidden terminal input failed")?;
    Ok(Zeroizing::new(bundle))
}

fn install_bundle(state_dir: &Path, bundle: Zeroizing<String>, source: &str) -> Result<()> {
    let bundle = normalize_bundle(bundle)
        .map_err(|error| anyhow::anyhow!("invalid publish bundle supplied by {source}: {error}"))?;
    sync::account::install_publish(state_dir, bundle.as_bytes()).map_err(|error| {
        anyhow::anyhow!("could not configure the publish account from {source}: {error}")
    })?;
    eprintln!("Publish account configured.");
    Ok(())
}

fn normalize_bundle(bundle: Zeroizing<String>) -> Result<Zeroizing<String>> {
    if bundle.len() > MAX_BUNDLE_INPUT_BYTES {
        bail!("publish bundle is too long (maximum {MAX_BUNDLE_ENCODED_BYTES} bytes)");
    }
    let trimmed = bundle.trim();
    if trimmed.len() > MAX_BUNDLE_ENCODED_BYTES {
        bail!("publish bundle is too long (maximum {MAX_BUNDLE_ENCODED_BYTES} bytes)");
    }
    if trimmed.is_empty() {
        bail!("publish bundle is empty");
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_publish_bundle(owner: &Path) -> String {
        sync::state::test_support::create_account(owner, "https://sync.example").unwrap();
        sync::state::export_account(owner, ApiKeyScope::Publish).unwrap()
    }

    fn secret(value: impl Into<String>) -> Zeroizing<String> {
        Zeroizing::new(value.into())
    }

    #[test]
    fn environment_bundle_takes_precedence_over_file_and_prompt() {
        let root = crate::test_support::canonical_tempdir();
        let bundle = fixture_publish_bundle(&root.path().join("owner"));
        let state = root.path().join("host");
        let missing_file = root.path().join("missing.bundle");

        ensure_configured_with(&state, Some(secret(bundle)), Some(&missing_file), || {
            panic!("the prompt must not be used")
        })
        .unwrap();

        assert!(
            sync::state::load_account(&state, ApiKeyScope::Publish).is_ok(),
            "the environment bundle should configure publish state"
        );
    }

    #[test]
    fn bundle_file_is_used_when_the_environment_is_absent() {
        let root = crate::test_support::canonical_tempdir();
        let bundle = fixture_publish_bundle(&root.path().join("owner"));
        let bundle_file = root.path().join("publish.bundle");
        std::fs::write(&bundle_file, format!("{bundle}\n")).unwrap();
        let state = root.path().join("host");

        ensure_configured_with(&state, None, Some(&bundle_file), || {
            panic!("the prompt must not be used")
        })
        .unwrap();

        assert!(sync::state::load_account(&state, ApiKeyScope::Publish).is_ok());
    }

    #[test]
    fn configured_publish_state_is_reused_without_prompting() {
        let root = crate::test_support::canonical_tempdir();
        let bundle = fixture_publish_bundle(&root.path().join("owner"));
        let state = root.path().join("host");
        sync::account::install_publish(&state, bundle.as_bytes()).unwrap();

        ensure_configured_with(&state, None, None, || panic!("the prompt must not be used"))
            .unwrap();
    }

    #[test]
    fn interactive_fallback_installs_the_hidden_prompt_result() {
        let root = crate::test_support::canonical_tempdir();
        let bundle = fixture_publish_bundle(&root.path().join("owner"));
        let state = root.path().join("host");
        crate::secure_state::prepare_private_dir(&state).unwrap();

        ensure_configured_with(&state, None, None, || Ok(secret(format!("  {bundle}  ")))).unwrap();

        assert!(sync::state::load_account(&state, ApiKeyScope::Publish).is_ok());
    }

    #[test]
    fn unavailable_interactive_input_has_automation_guidance() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("host");
        crate::secure_state::prepare_private_dir(&state).unwrap();

        let error = ensure_configured_with(&state, None, None, || {
            Err(anyhow::anyhow!("synthetic terminal failure"))
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains(PUBLISH_BUNDLE_ENV), "{error}");
        assert!(error.contains("--bundle-file"), "{error}");
    }

    #[test]
    fn wrong_scope_error_is_actionable_without_verbose_diagnostics() {
        let root = crate::test_support::canonical_tempdir();
        let owner = root.path().join("owner");
        sync::state::test_support::create_account(&owner, "https://sync.example").unwrap();
        let download = sync::state::export_account(&owner, ApiKeyScope::Download).unwrap();
        let state = root.path().join("host");

        let error = ensure_configured_with(&state, Some(secret(download)), None, || {
            panic!("the prompt must not be used")
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains(PUBLISH_BUNDLE_ENV), "{error}");
        assert!(error.contains("publish-only"), "{error}");
    }

    #[test]
    fn bundle_inputs_are_trimmed_and_bounded_without_echoing_values_in_errors() {
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
    }
}
