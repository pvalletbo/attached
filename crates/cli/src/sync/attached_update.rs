use std::{collections::BTreeMap, path::Path, str::FromStr as _};

use anyhow::{Context, Result, bail, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use attached_tunnel_protocol::{AttachedVersion, CapabilitySecret, HerdrVersion};
use futures_util::{StreamExt as _, stream};
use iroh_tickets::endpoint::EndpointTicket;

use crate::{
    session_picker::{self, SessionSelection},
    tunnel::AttachedUpdateClient,
};

use super::{refresh, state, state_catalog};

const MAX_CONCURRENT_REMOTE_UPDATES: usize = 4;

struct RemoteUpdate {
    target: String,
    host: String,
    session: String,
    endpoint: iroh::EndpointAddr,
    capability: CapabilitySecret,
    previous: AttachedVersion,
}

#[tracing::instrument(name = "update_remote_attached", level = "debug", skip_all)]
pub async fn update(state_dir: &Path, target: Option<&str>, verbosity: u8) -> Result<()> {
    let account = state::load_account(state_dir, ApiKeyScope::Download)
        .context("`update --remote` requires a download account bundle")?;
    let refreshed = refresh_remote_sessions(state_dir, verbosity).await?;
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
    let update = prepare_update(state_dir, &account, &target)?;
    let local_identity = local_identity(&account)?;
    let client = AttachedUpdateClient::bind(&local_identity).await?;
    let result = perform_update(&client, &update).await;
    client.close().await;
    result
}

#[tracing::instrument(name = "update_all_remote_attached", level = "debug", skip_all)]
pub async fn update_all(state_dir: &Path, verbosity: u8) -> Result<()> {
    let account = state::load_account(state_dir, ApiKeyScope::Download)
        .context("`update --remote --all` requires a download account bundle")?;
    let refreshed = refresh_remote_sessions(state_dir, verbosity).await?;
    let targets = one_target_per_host(&refreshed.sessions);
    ensure!(
        !targets.is_empty(),
        "no synchronized remote hosts are available"
    );
    let host_count = targets.len();

    let mut updates = Vec::with_capacity(host_count);
    let mut failures = Vec::new();
    for (host, target) in targets {
        match prepare_update(state_dir, &account, &target) {
            Ok(update) => updates.push(update),
            Err(error) => failures.push((host, error)),
        }
    }

    if !updates.is_empty() {
        let local_identity = local_identity(&account)?;
        let client = AttachedUpdateClient::bind(&local_identity).await?;
        let results = run_concurrently(updates, |update| {
            let client = &client;
            async move {
                let result = perform_update(client, &update).await;
                (update.host.clone(), result)
            }
        })
        .await;
        client.close().await;
        for (host, result) in results {
            if let Err(error) = result {
                failures.push((host, error));
            }
        }
    }

    if !failures.is_empty() {
        for (host, error) in &failures {
            eprintln!("Warning: remote host `{host}` was not updated: {error:#}");
        }
        bail!(
            "failed to update {} of {host_count} synchronized remote hosts",
            failures.len()
        );
    }
    eprintln!(
        "All {host_count} synchronized remote hosts are running the latest Attached release."
    );
    Ok(())
}

async fn refresh_remote_sessions(
    state_dir: &Path,
    verbosity: u8,
) -> Result<refresh::RefreshResult> {
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
    Ok(refreshed)
}

fn one_target_per_host(sessions: &[state_catalog::SyncedSession]) -> Vec<(String, String)> {
    let mut hosts = BTreeMap::new();
    for session in sessions {
        hosts
            .entry(session.host.clone())
            .or_insert_with(|| session.target.clone());
    }
    hosts.into_iter().collect()
}

fn local_identity(account: &state::AccountCredentials) -> Result<iroh::SecretKey> {
    Ok(iroh::SecretKey::from_bytes(
        account
            .consumer_identity_secret()
            .context("download account bundle has no consumer Iroh identity")?,
    ))
}

fn prepare_update(
    state_dir: &Path,
    account: &state::AccountCredentials,
    target: &str,
) -> Result<RemoteUpdate> {
    let (host, session) = parse_target(target)?;
    let attachment =
        state_catalog::attachment(state_dir, account, host, session, super::utc_now_seconds())?
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
    Ok(RemoteUpdate {
        target: target.to_owned(),
        host: host.to_owned(),
        session: attachment.session,
        endpoint: endpoint.endpoint_addr().clone(),
        capability: CapabilitySecret::from_bytes(attachment.attach_capability),
        previous,
    })
}

async fn perform_update(client: &AttachedUpdateClient, update: &RemoteUpdate) -> Result<()> {
    eprintln!(
        "Requesting the latest Attached release for `{}` (currently {})…",
        update.target, update.previous
    );
    let installed = client
        .request(update.endpoint.clone(), &update.session, &update.capability)
        .await
        .context("remote Attached update failed")?;
    eprintln!(
        "Remote host `{}` is serving with Attached {installed} (previously {}).",
        update.host, update.previous
    );
    Ok(())
}

async fn run_concurrently<Item, Output, Run, RunFuture>(items: Vec<Item>, run: Run) -> Vec<Output>
where
    Run: FnMut(Item) -> RunFuture,
    RunFuture: Future<Output = Output>,
{
    stream::iter(items)
        .map(run)
        .buffer_unordered(MAX_CONCURRENT_REMOTE_UPDATES)
        .collect()
        .await
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
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;

    fn synced_session(host: &str, session: &str) -> state_catalog::SyncedSession {
        state_catalog::SyncedSession {
            target: format!("{host}/{session}"),
            host: host.to_owned(),
            session: session.to_owned(),
            attached_version: Some([0, 2, 5]),
            herdr_version: [1, 2, 3],
            published_at: None,
        }
    }

    #[test]
    fn remote_update_targets_use_host_and_session() {
        assert_eq!(parse_target("office/work").unwrap(), ("office", "work"));
        for invalid in ["office", "/work", "office/", "office/a/b"] {
            assert!(parse_target(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn all_updates_choose_one_session_per_host() {
        let targets = one_target_per_host(&[
            synced_session("office", "work"),
            synced_session("lab", "admin"),
            synced_session("office", "personal"),
        ]);
        assert_eq!(
            targets,
            vec![
                ("lab".to_owned(), "lab/admin".to_owned()),
                ("office".to_owned(), "office/work".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn all_updates_run_more_than_one_host_concurrently() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Barrier::new(2));
        let results = tokio::time::timeout(
            Duration::from_secs(1),
            run_concurrently(vec!["office", "lab"], |host| {
                let active = active.clone();
                let maximum = maximum.clone();
                let gate = gate.clone();
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    gate.wait().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    host
                }
            }),
        )
        .await
        .expect("remote host updates ran sequentially");

        assert_eq!(results.len(), 2);
        assert_eq!(maximum.load(Ordering::SeqCst), 2);
    }
}
