use std::{path::Path, str::FromStr as _};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use attached_tunnel_protocol::{AttachedVersion, CapabilitySecret, HerdrVersion};
use iroh_tickets::endpoint::EndpointTicket;

use crate::session_picker::{self, SessionSelection};

use super::{refresh, state, state_catalog};

#[tracing::instrument(name = "update_remote_attached", level = "debug", skip_all)]
pub async fn update(state_dir: &Path, target: Option<&str>, verbosity: u8) -> Result<()> {
    let account = state::load_account(state_dir, ApiKeyScope::Download)
        .context("`update --remote` requires a download account bundle")?;
    // Native catalog opening only needs a structured Herdr version in this flow;
    // Attached self-update must not depend on a local Herdr executable.
    let refreshed = refresh::refresh_sessions(state_dir, HerdrVersion::new(0, 0, 0))
        .await
        .context("could not refresh synchronized sessions")?;
    for warning in refreshed
        .warnings
        .iter()
        .filter(|warning| verbosity > 0 || !warning.is_verbose_only())
    {
        eprintln!("Warning: {warning}");
    }
    let target = match target {
        Some(target) => {
            ensure!(
                refreshed
                    .sessions
                    .iter()
                    .any(|session| session.target == target),
                "synchronized session `{target}` is unavailable"
            );
            target.to_owned()
        }
        None => match session_picker::select(&[], &refreshed.sessions).await? {
            Some(SessionSelection::Synchronized(target)) => target,
            Some(SessionSelection::Local(_)) => unreachable!("remote-only picker returned local"),
            None => return Ok(()),
        },
    };
    let (host, session) = parse_target(&target)?;
    let attachment =
        state_catalog::attachment(state_dir, &account, host, session, super::utc_now_seconds())?
            .with_context(|| format!("synchronized session `{target}` is unavailable"))?;
    if let Ok(registry_dir) = crate::endpoint_registry::default_dir() {
        ensure!(
            !crate::endpoint_registry::is_active(&registry_dir, attachment.endpoint_identity)?,
            "synchronized session is served locally; run `attached update` locally instead"
        );
    }
    ensure!(
        super::utc_now_seconds() < attachment.expires_at,
        "session access descriptor expired before the update"
    );
    let endpoint = EndpointTicket::from_str(&attachment.endpoint_ticket)
        .context("stored synchronized endpoint ticket is invalid")?;
    ensure!(
        endpoint.endpoint_addr().id.as_bytes() == &attachment.endpoint_identity,
        "stored synchronized endpoint identity does not match its ticket"
    );
    let previous = attachment
        .attached_version
        .map(|[major, minor, patch]| {
            AttachedVersion::new(u32::from(major), u32::from(minor), u32::from(patch))
        })
        .context(
            "remote host did not publish its Attached version and does not support remote updates",
        )?;
    let local_identity = iroh::SecretKey::from_bytes(
        account
            .consumer_identity_secret()
            .context("download account bundle has no consumer Iroh identity")?,
    );
    eprintln!("Requesting the latest Attached release for `{target}` (currently {previous})…");
    let installed = crate::tunnel::request_attached_update(
        endpoint.endpoint_addr().clone(),
        &local_identity,
        &attachment.session,
        &CapabilitySecret::from_bytes(attachment.attach_capability),
    )
    .await
    .context("remote Attached update failed")?;
    eprintln!("Remote host `{host}` is serving with Attached {installed} (previously {previous}).");
    Ok(())
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

    #[test]
    fn remote_update_targets_use_host_and_session() {
        assert_eq!(parse_target("office/work").unwrap(), ("office", "work"));
        for invalid in ["office", "/work", "office/", "office/a/b"] {
            assert!(parse_target(invalid).is_err(), "accepted {invalid}");
        }
    }
}
