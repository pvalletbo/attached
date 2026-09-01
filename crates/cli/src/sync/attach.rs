use std::{
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
    str::FromStr as _,
};

use anyhow::{Context as _, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use attached_tunnel_protocol::{CapabilitySecret, HerdrVersion};
use iroh_tickets::endpoint::EndpointTicket;
use tracing::{debug, warn};

use crate::{herdr_version, tunnel};

use super::{state, state_catalog};

pub(super) fn decide_upgrade(
    local: HerdrVersion,
    remote: HerdrVersion,
    explicit: bool,
    interactive: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<bool> {
    if local == remote {
        return Ok(false);
    }
    ensure!(
        (local.major(), local.minor(), local.patch())
            > (remote.major(), remote.minor(), remote.patch()),
        "remote Herdr {remote} is newer than local Herdr {local}; update local Herdr before attaching"
    );
    if explicit {
        return Ok(true);
    }
    ensure!(
        interactive,
        "Herdr version mismatch: local Herdr {local}, remote Herdr {remote}; rerun with `--upgrade-remote` to explicitly request `herdr update --handoff` on the remote host"
    );
    write!(
        output,
        "Herdr version mismatch: local {local}, remote {remote}. Run remote `herdr update --handoff` using its configured channel and attempt live handoff? [y/N] "
    )?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn discover_local_version(herdr_bin: &Path) -> Result<HerdrVersion> {
    herdr_version::query(herdr_bin).context(
        "could not determine the local Herdr version; attachment and remote upgrade were not started",
    )
}

fn ensure_endpoint_not_local(
    registry_dir: &Path,
    endpoint_identity: [u8; 32],
    warnings: &mut impl Write,
) -> Result<()> {
    match crate::endpoint_registry::is_active(registry_dir, endpoint_identity) {
        Ok(active) => {
            ensure!(
                !active,
                "synchronized session is served locally; attach to the local session instead"
            );
            Ok(())
        }
        Err(_) => {
            writeln!(
                warnings,
                "warning: could not inspect the local endpoint registry; attachment continued"
            )?;
            Ok(())
        }
    }
}

#[tracing::instrument(name = "attach_synchronized_session", level = "debug", skip_all)]
pub async fn attach(
    state_dir: &Path,
    target: &str,
    herdr_bin: PathBuf,
    upgrade_remote: bool,
) -> Result<i32> {
    let (host, session) = parse_target(target)?;
    let account = state::load_account(state_dir, ApiKeyScope::Download)?;
    let local_identity = iroh::SecretKey::from_bytes(
        account
            .consumer_identity_secret()
            .context("download account bundle has no consumer Iroh identity")?,
    );
    let attachment =
        state_catalog::attachment(state_dir, &account, host, session, super::utc_now_seconds())?
            .with_context(|| format!("synchronized session `{target}` is unavailable"))?;
    match crate::endpoint_registry::default_dir() {
        Ok(registry_dir) => ensure_endpoint_not_local(
            &registry_dir,
            attachment.endpoint_identity,
            &mut std::io::stderr().lock(),
        )?,
        Err(_) => writeln!(
            std::io::stderr().lock(),
            "warning: could not inspect the local endpoint registry; attachment continued"
        )?,
    }
    ensure!(
        super::utc_now_seconds() < attachment.expires_at,
        "session access descriptor expired before attachment"
    );
    let endpoint = EndpointTicket::from_str(&attachment.endpoint_ticket)
        .context("stored synchronized endpoint ticket is invalid")?;
    ensure!(
        endpoint.endpoint_addr().id.as_bytes() == &attachment.endpoint_identity,
        "stored synchronized endpoint identity does not match its ticket"
    );
    let mut remote_version = HerdrVersion::new(
        u32::from(attachment.herdr_version[0]),
        u32::from(attachment.herdr_version[1]),
        u32::from(attachment.herdr_version[2]),
    );
    let local_version = discover_local_version(&herdr_bin)?;
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let upgrade = decide_upgrade(
        local_version,
        remote_version,
        upgrade_remote,
        interactive,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
    )?;
    if local_version != remote_version {
        ensure!(
            upgrade,
            "remote Herdr upgrade declined; attachment was not started"
        );
        let installed = finish_remote_operation(
            state_dir,
            &account,
            target,
            &attachment,
            tunnel::request_upgrade(
                endpoint.endpoint_addr().clone(),
                &local_identity,
                &attachment.session,
                &CapabilitySecret::from_bytes(attachment.attach_capability),
                local_version,
            )
            .await,
        )?;
        ensure!(
            installed == local_version,
            "remote channel installed Herdr {installed}, but local Herdr is {local_version}; attachment was not started"
        );
        remote_version = installed;
    }
    ensure!(
        local_version == remote_version,
        "remote Herdr version did not match after update"
    );
    let connection = tunnel::connect(
        endpoint.endpoint_addr().clone(),
        &local_identity,
        attachment.session.clone(),
        CapabilitySecret::from_bytes(attachment.attach_capability),
        herdr_bin,
        local_version,
    )
    .await;
    finish_remote_operation(state_dir, &account, target, &attachment, connection)
}

fn finish_remote_operation<T>(
    state_dir: &Path,
    account: &state::AccountCredentials,
    target: &str,
    attachment: &state_catalog::SyncedAttachment,
    result: Result<T>,
) -> Result<T> {
    match result {
        Err(error) if tunnel::is_remote_unavailable(&error) => {
            match state_catalog::remove_if_revision(
                state_dir,
                account,
                attachment.record_id,
                attachment.service_revision,
            ) {
                Ok(true) => warn!(
                    target,
                    service_revision = attachment.service_revision,
                    "removed unreachable synchronized session from the local catalog"
                ),
                Ok(false) => debug!(
                    target,
                    service_revision = attachment.service_revision,
                    "kept synchronized session because its catalog revision changed"
                ),
                Err(prune_error) => {
                    return Err(error.context(format!(
                        "remote session failed and its stale catalog entry could not be removed: {prune_error:#}"
                    )));
                }
            }
            Err(error)
        }
        result => result,
    }
}

fn parse_target(target: &str) -> Result<(&str, &str)> {
    let (host, session) = target
        .split_once('/')
        .context("session target must be `HOST/SESSION`")?;
    ensure!(!host.is_empty(), "session target host is empty");
    ensure!(!session.is_empty(), "session target name is empty");
    ensure!(
        !session.contains('/'),
        "session target contains more than one `/`"
    );
    Ok((host, session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn active_endpoint_is_rejected_at_attachment_time() {
        let root = crate::test_support::canonical_tempdir();
        let registry = root.path().join("registry-user/live-endpoints");
        let identity = [0x63; 32];
        let _guard = crate::endpoint_registry::register(&registry, identity).unwrap();
        let mut warnings = Vec::new();

        let error = ensure_endpoint_not_local(&registry, identity, &mut warnings)
            .unwrap_err()
            .to_string();

        assert!(error.contains("served locally"), "{error}");
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn attachment_probe_error_warns_once_and_fails_open() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::test_support::canonical_tempdir();
        let registry_root = root.path().join("registry-user");
        std::fs::create_dir(&registry_root).unwrap();
        std::fs::set_permissions(&registry_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let registry = registry_root.join("live-endpoints");
        std::fs::create_dir(&registry).unwrap();
        std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut warnings = Vec::new();

        ensure_endpoint_not_local(&registry, [0x71; 32], &mut warnings).unwrap();

        let warnings = String::from_utf8(warnings).unwrap();
        assert_eq!(warnings.lines().count(), 1, "{warnings:?}");
        assert!(warnings.len() < 128, "warning was not bounded");
        assert!(!warnings.contains(&registry.display().to_string()));
        assert!(!warnings.contains("71"));
    }

    #[test]
    fn missing_local_version_fails_closed_before_attach() {
        let missing = Path::new("/definitely/missing/attached-secret-path");
        let error = discover_local_version(missing).unwrap_err().to_string();
        assert!(error.contains("local Herdr version"), "{error}");
    }

    #[test]
    fn remote_newer_never_authorizes_mutation_even_with_explicit_opt_in() {
        let mut output = Vec::new();
        for remote in [
            HerdrVersion::new(1, 2, 4),
            HerdrVersion::new(1, 3, 0),
            HerdrVersion::new(2, 0, 0),
        ] {
            let error = decide_upgrade(
                HerdrVersion::new(1, 2, 3),
                remote,
                true,
                false,
                &mut Cursor::new(b""),
                &mut output,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("update local Herdr"), "{error}");
            assert!(!error.contains("request `herdr update`"), "{error}");
        }
    }

    #[test]
    fn exact_version_mismatch_requires_an_explicit_decision() {
        let local = HerdrVersion::new(1, 2, 3);
        let remote = HerdrVersion::new(1, 2, 2);
        let mut output = Vec::new();
        assert!(
            !decide_upgrade(
                local,
                local,
                false,
                false,
                &mut Cursor::new(b""),
                &mut output
            )
            .unwrap()
        );
        assert!(
            output.is_empty(),
            "exact matches must keep attach unchanged"
        );

        let error = decide_upgrade(
            local,
            remote,
            false,
            false,
            &mut Cursor::new(b""),
            &mut output,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("local Herdr 1.2.3"), "{error}");
        assert!(error.contains("remote Herdr 1.2.2"), "{error}");
        assert!(error.contains("--upgrade-remote"), "{error}");

        output.clear();
        assert!(
            !decide_upgrade(
                local,
                remote,
                false,
                true,
                &mut Cursor::new(b"n\n"),
                &mut output
            )
            .unwrap()
        );
        assert!(
            String::from_utf8(output.clone())
                .unwrap()
                .contains("herdr update --handoff")
        );
        assert!(
            decide_upgrade(
                local,
                remote,
                false,
                true,
                &mut Cursor::new(b"yes\n"),
                &mut output
            )
            .unwrap()
        );
        assert!(
            decide_upgrade(
                local,
                remote,
                true,
                false,
                &mut Cursor::new(b""),
                &mut output
            )
            .unwrap()
        );
    }

    #[test]
    fn targets_have_exactly_one_host_and_session_component() {
        assert_eq!(
            parse_target("office/default").unwrap(),
            ("office", "default")
        );
        assert!(parse_target("default").is_err());
        assert!(parse_target("host/a/b").is_err());
        assert!(parse_target("host/").is_err());
    }
}
