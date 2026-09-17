use std::{path::Path, str::FromStr as _};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use attached_tunnel_protocol::{AttachedVersion, CapabilitySecret};
use iroh_tickets::endpoint::EndpointTicket;

use super::{refresh, state, state_catalog};

#[tracing::instrument(name = "update_remote_attached", level = "debug", skip_all)]
pub async fn update(state_dir: &Path, target: Option<&str>, verbosity: u8) -> Result<()> {
    let account = state::load_account(state_dir, ApiKeyScope::Download)
        .context("`update --remote` requires a download account bundle")?;
    let refreshed = refresh::refresh_hosts(state_dir)
        .await
        .context("could not refresh synchronized hosts")?;
    for warning in refreshed
        .warnings
        .iter()
        .filter(|warning| verbosity > 0 || !warning.is_verbose_only())
    {
        eprintln!("Warning: {warning}");
    }
    let target = match target {
        Some(target) => target.to_owned(),
        None => match crate::host_picker::select(&refreshed.hosts).await? {
            Some(target) => target,
            None => return Ok(()),
        },
    };
    // Remote self-update remains a fixed capability-authorized operation, independent
    // of arbitrary shell consent. An explicitly selected disabled host can be updated.
    let host = state_catalog::host(state_dir, &account, &target, super::utc_now_seconds())?;
    if let Ok(registry_dir) = crate::endpoint_registry::default_dir() {
        ensure!(
            !crate::endpoint_registry::is_active(&registry_dir, host.endpoint_identity)?,
            "host is served locally; run `attached update` locally instead"
        );
    }
    ensure!(
        super::utc_now_seconds() < host.expires_at,
        "host access descriptor expired before the update"
    );
    let endpoint = EndpointTicket::from_str(&host.endpoint_ticket)
        .context("stored host endpoint ticket is invalid")?;
    ensure!(
        endpoint.endpoint_addr().id.as_bytes() == &host.endpoint_identity,
        "stored host identity does not match its ticket"
    );
    let [major, minor, patch] = host.attached_version;
    let previous = AttachedVersion::new(major.into(), minor.into(), patch.into());
    let local_identity = iroh::SecretKey::from_bytes(
        account
            .consumer_identity_secret()
            .context("download account bundle has no consumer Iroh identity")?,
    );
    eprintln!("Requesting the latest Attached release for `{target}` (currently {previous})…");
    let installed = crate::remote_update::request_attached_update(
        endpoint.endpoint_addr().clone(),
        &local_identity,
        &CapabilitySecret::from_bytes(host.attach_capability),
    )
    .await
    .context("remote Attached update failed")?;
    eprintln!(
        "Remote host `{target}` is serving with Attached {installed} (previously {previous})."
    );
    Ok(())
}
