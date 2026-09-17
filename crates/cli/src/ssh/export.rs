//! One foreground, unlocked consumer endpoint for every discovered SSH publisher.
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use attached_session_sync_protocol::account::ApiKeyScope;
use iroh::{Endpoint, endpoint::presets};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::{client::Broker, configuration::ManagedConfig};
use crate::sync::{
    self,
    state::AccountCredentials,
    state_catalog::{HostConnection, SyncedHost},
};

const PREPARE_CONCURRENCY: usize = 8;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);

type Snapshot = BTreeMap<String, Advertisement>;

struct Advertisement {
    label: String,
    connection: HostConnection,
}

struct RunningHost {
    broker: Arc<Broker>,
    retired: CancellationToken,
    generation: u64,
}

impl Drop for RunningHost {
    fn drop(&mut self) {
        self.retired.cancel();
    }
}

pub(crate) async fn export(path: &Path, refresh_interval: Duration) -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};
    let account = Arc::new(sync::state::load_account(path, ApiKeyScope::Download)?);
    // Register before touching user configuration, so all normal terminal/session
    // shutdown paths run the same cleanup, including a signal during discovery.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let managed = ManagedConfig::install(Path::new(&home))?;
    let consumer = iroh::SecretKey::from_bytes(
        account
            .consumer_identity_secret()
            .context("download bundle has no consumer identity")?,
    );
    // Never one endpoint per host: relays would displace the same consumer identity.
    // Keep relay support even when the initial catalog is empty or entirely local.
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(consumer)
        .bind()
        .await?;
    let cancellation = CancellationToken::new();
    let _cancel = cancellation.clone().drop_guard();
    let run = run(
        &endpoint,
        path,
        account,
        &managed,
        refresh_interval,
        cancellation.clone(),
    );
    tokio::pin!(run);
    eprintln!(
        "SSH forwarding enabled. Use ssh attached-HOST [command] or ssh attached-ENDPOINT-ID [command]. Discovering hosts every {} seconds; keep this terminal running. Ctrl-C removes the managed Include and temporary keys.",
        refresh_interval.as_secs()
    );
    let result = tokio::select! {
        result = &mut run => result,
        _ = async { tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {}, _ = hangup.recv() => {} } } => {
            cancellation.cancel();
            run.await
        }
    };
    // QUIC draining depends on peer acknowledgements/RTT and can otherwise
    // outlive cancellation when a discovered publisher never answers setup.
    // All SSH tasks/temporary keys are already gone; bound this best-effort wait.
    if tokio::time::timeout(Duration::from_secs(3), endpoint.close())
        .await
        .is_err()
    {
        tracing::debug!("SSH exporter stopped waiting for QUIC close acknowledgements");
    }
    result?;
    Ok(0)
}

async fn discover(path: &Path, account: &AccountCredentials) -> Result<Snapshot> {
    let refreshed = sync::refresh::refresh_hosts_unlocked(path, account).await?;
    for warning in refreshed
        .warnings
        .iter()
        .filter(|warning| !warning.is_verbose_only())
    {
        eprintln!("Warning: {warning}");
    }
    let mut snapshot = BTreeMap::new();
    for SyncedHost { target, host, .. } in refreshed.hosts {
        // Recheck consent and expiry against completion time, not HTTP start time.
        if let Ok(connection) =
            sync::state_catalog::host(path, account, &target, sync::utc_now_seconds())
            && connection.ssh_enabled
        {
            snapshot.insert(
                target,
                Advertisement {
                    label: host,
                    connection,
                },
            );
        }
    }
    Ok(snapshot)
}

async fn run(
    endpoint: &Endpoint,
    path: &Path,
    account: Arc<AccountCredentials>,
    managed: &ManagedConfig,
    refresh_interval: Duration,
    cancellation: CancellationToken,
) -> Result<()> {
    let (sender, mut discoveries) = mpsc::channel(1);
    let discovery = {
        let path = path.to_owned();
        let account = account.clone();
        let token = cancellation.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(refresh_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    _ = interval.tick() => {}
                }
                let result = tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    result = tokio::time::timeout(DISCOVERY_TIMEOUT, discover(&path, &account)) => result.context("SSH host discovery timed out").and_then(|result| result),
                };
                tokio::select! {
                    _ = token.cancelled() => break,
                    result = sender.send(result) => if result.is_err() { break; },
                }
            }
        })
    };
    let mut known = Snapshot::new();
    let mut running = BTreeMap::<String, RunningHost>::new();
    let mut preparing = JoinSet::new();
    let mut serving = JoinSet::new();
    let mut pending = HashSet::new();
    let mut retry_after = BTreeMap::new();
    let mut generation = 0_u64;
    let mut published = String::new();
    let mut expiry = tokio::time::interval(Duration::from_secs(1));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = async {
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break,
                snapshot = discoveries.recv() => {
                    match snapshot.context("SSH discovery task ended unexpectedly")? {
                        Ok(snapshot) => { known = snapshot; }
                        Err(error) => eprintln!("Warning: SSH discovery failed: {error:#}; retaining only unexpired hosts and retrying"),
                    }
                }
                completed = preparing.join_next(), if !preparing.is_empty() => {
                    let (target, prepared): (String, Result<Broker>) = completed.context("missing SSH setup task")??;
                    pending.remove(&target);
                    match prepared {
                        Ok(broker) if known.contains_key(&target) => {
                            let broker = Arc::new(broker);
                            let retired = CancellationToken::new();
                            generation += 1;
                            running.insert(target.clone(), RunningHost { broker: broker.clone(), retired: retired.clone(), generation });
                            let token = cancellation.clone();
                            serving.spawn(async move { (target, generation, broker.serve(token, retired).await) });
                        }
                        Ok(_) => {}, // Removed/revoked during preparation: do not publish it.
                        Err(error) => {
                            retry_after.insert(target.clone(), tokio::time::Instant::now() + refresh_interval);
                            eprintln!("Warning: SSH host attached-{target} is unavailable: {error:#}; retrying");
                        }
                    }
                }
                completed = serving.join_next(), if !serving.is_empty() => {
                    let (target, finished_generation, result) = completed.context("missing SSH broker task")??;
                    if running.get(&target).is_some_and(|host| host.generation == finished_generation) {
                        running.remove(&target);
                    }
                    if let Err(error) = result { eprintln!("Warning: SSH host attached-{target} stopped: {error:#}"); }
                }
                _ = expiry.tick() => {},
            }
            // Also expire aliases during a hanging/failed HTTP refresh. Established
            // streams drain independently; no expired lease can admit a new setup.
            known.retain(|_, host| sync::utc_now_seconds() < host.connection.expires_at);
            running.retain(|target, _| known.contains_key(target));
            retry_after.retain(|target, _| known.contains_key(target));
            for (target, host) in &running {
                host.broker.observe(&known[target].connection);
            }
            // New/unattempted hosts first, then the oldest retries. Clearing a
            // retry set on every poll would let slow offline hosts at the front
            // of the catalog starve later hosts indefinitely.
            let candidates = preparation_order(&known, &retry_after);
            for target in candidates {
                if pending.len() >= PREPARE_CONCURRENCY { break; }
                if running.contains_key(&target) || pending.contains(&target) { continue; }
                let host = &known[&target];
                retry_after.insert(target.clone(), tokio::time::Instant::now() + refresh_interval);
                pending.insert(target.clone());
                let endpoint = endpoint.clone();
                let path = path.to_owned();
                let account = account.clone();
                let connection = host.connection.clone();
                let target = target.clone();
                preparing.spawn(async move {
                    let result = Broker::prepare(&endpoint, &path, connection, account, false).await;
                    (target, result)
                });
            }
            let aliases = aliases(&known);
            let mut configuration = String::new();
            for (target, host) in &running {
                configuration.push_str(&host.broker.configuration(&aliases[target])?);
            }
            if configuration != published {
                managed.publish(&configuration)?;
                for target in running.keys() {
                    println!("Ready: ssh {} [command]", aliases[target].split_whitespace().last().unwrap());
                }
                published = configuration;
            }
        }
        Ok(())
    }.await;
    cancellation.cancel();
    running.clear();
    preparing.abort_all();
    while preparing.join_next().await.is_some() {}
    while serving.join_next().await.is_some() {}
    discovery.await.context("SSH discovery task failed")?;
    result
}

fn preparation_order(
    hosts: &Snapshot,
    retry_after: &BTreeMap<String, tokio::time::Instant>,
) -> Vec<String> {
    let now = tokio::time::Instant::now();
    let mut candidates = hosts
        .keys()
        .filter(|target| {
            retry_after
                .get(*target)
                .is_none_or(|deadline| *deadline <= now)
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|target| retry_after.get(target).copied());
    candidates
}

fn aliases(hosts: &Snapshot) -> BTreeMap<String, String> {
    let mut counts = BTreeMap::<String, usize>::new();
    for host in hosts.values() {
        *counts.entry(host.label.to_ascii_lowercase()).or_default() += 1;
    }
    hosts
        .iter()
        .map(|(target, host)| {
            let stable = format!("attached-{target}");
            let label = host.label.to_ascii_lowercase();
            // ID-shaped labels must never impersonate an absent publisher's identity.
            // Case-insensitive duplicates are ambiguous even if one host is offline.
            let aliases = if counts[&label] == 1 && label.parse::<iroh::EndpointId>().is_err() {
                format!("{stable} attached-{label}")
            } else {
                stable
            };
            (target.clone(), aliases)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attached_session_sync_protocol::account::RecordId;
    use iroh_tickets::endpoint::EndpointTicket;

    fn fixture_hosts() -> (Vec<iroh::EndpointId>, Snapshot) {
        let mut hosts = Snapshot::new();
        let identities: Vec<_> = (0..5)
            .map(|_| iroh::SecretKey::generate().public())
            .collect();
        for (id, label) in identities.iter().zip([
            "Office",
            "office",
            "Laptop",
            &identities[4].to_string(),
            "other",
        ]) {
            hosts.insert(
                id.to_string(),
                Advertisement {
                    label: label.into(),
                    connection: HostConnection {
                        record_id: RecordId::from_bytes([0; 16]),
                        service_revision: 1,
                        endpoint_ticket: EndpointTicket::new(iroh::EndpointAddr::new(*id))
                            .to_string(),
                        endpoint_identity: *id.as_bytes(),
                        attach_capability: [0; 32],
                        attached_version: [0; 3],
                        expires_at: sync::utc_now_seconds() + chrono::Duration::seconds(60),
                        ssh_enabled: true,
                    },
                },
            );
        }
        (identities, hosts)
    }

    #[test]
    fn new_hosts_cannot_be_starved_by_repeated_offline_retries() {
        let (identities, hosts) = fixture_hosts();
        let oldest = identities[0].to_string();
        let newer = identities[1].to_string();
        let cooling = identities[2].to_string();
        let now = tokio::time::Instant::now();
        let retry_after = BTreeMap::from([
            (oldest.clone(), now - Duration::from_secs(2)),
            (newer.clone(), now - Duration::from_secs(1)),
            (cooling.clone(), now + Duration::from_secs(30)),
        ]);
        let order = preparation_order(&hosts, &retry_after);
        assert_eq!(order.len(), 4);
        assert!(!order.contains(&cooling));
        assert_eq!(&order[2..], &[oldest, newer]);
        assert!(order[..2].contains(&identities[3].to_string()));
        assert!(order[..2].contains(&identities[4].to_string()));
    }

    #[test]
    fn aliases_are_namespaced_case_insensitive_and_never_impersonate_identities() {
        let (identities, hosts) = fixture_hosts();
        let names = aliases(&hosts);
        for id in [&identities[0], &identities[1], &identities[3]] {
            assert_eq!(names[&id.to_string()], format!("attached-{id}"));
        }
        assert_eq!(
            names[&identities[2].to_string()],
            format!("attached-{} attached-laptop", identities[2])
        );
        assert_eq!(
            names[&identities[4].to_string()],
            format!("attached-{} attached-other", identities[4])
        );
    }
}
