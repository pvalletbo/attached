//! One foreground, unlocked consumer endpoint for every discovered SSH publisher.
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
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
use crate::workspace::{self, Workspace};

const PREPARE_CONCURRENCY: usize = 8;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);
const RESUME_GAP: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq)]
enum RunExit {
    Shutdown,
    Resumed,
}

struct ResumeDetector {
    last_tick: SystemTime,
}

impl ResumeDetector {
    fn new(now: SystemTime) -> Self {
        Self { last_tick: now }
    }

    fn observe(&mut self, now: SystemTime) -> bool {
        // Instant may stop during suspend (notably on macOS). Compare wall time
        // instead: an unchanged interface/IP does not imply a usable relay/NAT
        // session after waking. Backward clock corrections simply rebase us.
        let elapsed = now.duration_since(self.last_tick).unwrap_or_default();
        self.last_tick = now;
        elapsed >= RESUME_GAP
    }
}

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

/// One configuration owner, with independent per-workspace snapshots. Publishing
/// one workspace must never replace another workspace's aliases or keys.
struct PublishedConfigs {
    managed: ManagedConfig,
    snapshots: Mutex<BTreeMap<String, String>>,
}

struct WorkspaceConfig {
    name: String,
    shared: Arc<PublishedConfigs>,
}

impl WorkspaceConfig {
    fn publish(&self, configuration: &str) -> Result<()> {
        let mut snapshots = self
            .shared
            .snapshots
            .lock()
            .map_err(|_| anyhow::anyhow!("SSH configuration lock failed"))?;
        snapshots.insert(self.name.clone(), configuration.into());
        self.shared
            .managed
            .publish(&snapshots.values().cloned().collect::<String>())
    }
}

pub(crate) async fn export(
    workspaces: Vec<Workspace>,
    refresh_interval: Duration,
    all: bool,
) -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut accounts = Vec::new();
    for workspace in workspaces {
        crate::secure_state::prepare_private_dir(&workspace.path)?;
        eprintln!("Unlocking workspace `{}`...", workspace.name);
        let account = sync::state::load_account_optional(&workspace.path, ApiKeyScope::Download)
            .with_context(|| format!("could not unlock workspace `{}`", workspace.name))?;
        match account {
            Some(account) => accounts.push((workspace, Arc::new(account))),
            None if all => {}
            None => anyhow::bail!(
                "workspace `{}` has no consumer credentials; import a download-only bundle",
                workspace.name
            ),
        }
    }
    ensure!(
        !accounts.is_empty(),
        "no consumer workspaces are configured; use `attached account create` or `attached account import`"
    );
    // Register before touching user configuration, so all normal terminal/session
    // shutdown paths run the same cleanup, including a signal during discovery.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let shared = Arc::new(PublishedConfigs {
        managed: ManagedConfig::install(Path::new(&home))?,
        snapshots: Mutex::new(BTreeMap::new()),
    });
    let cancellation = CancellationToken::new();
    let _cancel = cancellation.clone().drop_guard();
    let run = async {
        loop {
            // Reuse an endpoint even if the same account was imported under two
            // names. Separate endpoints for one identity would displace each
            // other on relays. Publishers use their own, distinct identities.
            let mut endpoints = BTreeMap::new();
            for (_, account) in &accounts {
                let consumer = iroh::SecretKey::from_bytes(
                    account
                        .consumer_identity_secret()
                        .context("download bundle has no consumer identity")?,
                );
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    endpoints.entry(consumer.public())
                {
                    entry.insert(
                        Endpoint::builder(presets::N0)
                            .secret_key(consumer)
                            .bind()
                            .await?,
                    );
                }
            }
            let iteration = cancellation.child_token();
            let mut tasks = JoinSet::new();
            for (workspace, account) in &accounts {
                let identity = iroh::SecretKey::from_bytes(
                    account
                        .consumer_identity_secret()
                        .expect("validated identity"),
                )
                .public();
                let endpoint = endpoints[&identity].clone();
                let workspace = workspace.clone();
                let account = account.clone();
                let managed = WorkspaceConfig {
                    name: workspace.name,
                    shared: shared.clone(),
                };
                let token = iteration.child_token();
                tasks.spawn(async move {
                    run(
                        &endpoint,
                        &workspace.path,
                        account,
                        &managed,
                        refresh_interval,
                        token,
                    )
                    .await
                });
            }
            let result = match tasks.join_next().await {
                Some(result) => result
                    .context("SSH workspace task failed")
                    .and_then(|result| result),
                None => Err(anyhow::anyhow!("no SSH workspace tasks")),
            };
            // A resume rebuilds all endpoints together. Always cancel and drain
            // every task before removing config or rebinding shared identities.
            iteration.cancel();
            while let Some(other) = tasks.join_next().await {
                if let Err(error) = other
                    .context("SSH workspace task failed")
                    .and_then(|result| result)
                {
                    tracing::warn!(%error, "SSH workspace stopped during shutdown");
                }
            }
            let unpublished = shared.managed.publish("");
            shared
                .snapshots
                .lock()
                .map_err(|_| anyhow::anyhow!("SSH configuration lock failed"))?
                .clear();
            futures_util::future::join_all(endpoints.values().map(|endpoint| async move {
                if tokio::time::timeout(Duration::from_secs(3), endpoint.close())
                    .await
                    .is_err()
                {
                    tracing::debug!("SSH exporter stopped waiting for QUIC close acknowledgements");
                }
            }))
            .await;
            drop(endpoints);
            unpublished?;
            if result? == RunExit::Shutdown || cancellation.is_cancelled() {
                return Ok::<_, anyhow::Error>(());
            }
            eprintln!(
                "SSH forwarding resumed after suspension; rebuilding network connections. Reconnect any interrupted SSH sessions."
            );
        }
    };
    tokio::pin!(run);
    eprintln!(
        "SSH forwarding enabled for {}. Named workspaces use ssh attached-WORKSPACE--HOST; default keeps attached-HOST. Discovering every {} seconds; keep this terminal running. Ctrl-C removes the managed Include and temporary keys. Restart to change the exported workspace selection.",
        accounts
            .iter()
            .map(|(workspace, _)| workspace.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        refresh_interval.as_secs()
    );
    let result = tokio::select! {
        result = &mut run => result,
        _ = async { tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {}, _ = hangup.recv() => {} } } => {
            cancellation.cancel();
            run.await
        }
    };
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
    managed: &WorkspaceConfig,
    refresh_interval: Duration,
    cancellation: CancellationToken,
) -> Result<RunExit> {
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
    let mut resume = ResumeDetector::new(SystemTime::now());
    let mut expiry = tokio::time::interval(Duration::from_secs(1));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = async {
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(RunExit::Shutdown),
                // Check before queued discovery/setup completions after wake.
                // Otherwise stale work could be republished first.
                _ = expiry.tick() => {
                    if resume.observe(SystemTime::now()) {
                        return Ok(RunExit::Resumed);
                    }
                }
                snapshot = discoveries.recv() => {
                    match snapshot.context("SSH discovery task ended unexpectedly")? {
                        Ok(snapshot) => { known = snapshot; }
                        Err(error) => eprintln!("Warning [{}]: SSH discovery failed: {error:#}; retaining only unexpired hosts and retrying", managed.name),
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
            let aliases = aliases(&known, &managed.name);
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

fn aliases(hosts: &Snapshot, workspace: &str) -> BTreeMap<String, String> {
    let mut counts = BTreeMap::<String, usize>::new();
    for host in hosts.values() {
        *counts.entry(host.label.to_ascii_lowercase()).or_default() += 1;
    }
    hosts
        .iter()
        .map(|(target, host)| {
            let stable = workspace::ssh_target(workspace, target);
            let label = host.label.to_ascii_lowercase();
            // ID-shaped labels must never impersonate an absent publisher's identity.
            // Case-insensitive duplicates are ambiguous even if one host is offline.
            // Reserve `--` for named workspaces even when a default publisher
            // has a label shaped like `work--office`. Never let a mutable label
            // impersonate a workspace-qualified alias (including absent hosts).
            let aliases = if counts[&label] == 1
                && label.parse::<iroh::EndpointId>().is_err()
                && (workspace != workspace::DEFAULT || !label.contains("--"))
            {
                format!("{stable} {}", workspace::ssh_target(workspace, &label))
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
    fn resume_detection_uses_wall_time_even_when_the_monotonic_clock_does_not_advance() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let mut detector = ResumeDetector::new(now);
        assert!(!detector.observe(now + Duration::from_secs(1)));
        // No actual wait/advance of Instant: model the clock used on macOS sleep.
        let wake = now + Duration::from_secs(3600);
        assert!(detector.observe(wake));
        assert!(!detector.observe(wake));
        assert!(!detector.observe(wake + Duration::from_secs(1)));
        assert!(detector.observe(wake + Duration::from_secs(1) + RESUME_GAP));
    }

    #[test]
    fn ordinary_ticks_and_backward_clock_corrections_do_not_restart_transport() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let mut detector = ResumeDetector::new(now);
        for seconds in 1..120 {
            assert!(!detector.observe(now + Duration::from_secs(seconds)));
        }
        assert!(!detector.observe(now));
        assert!(!detector.observe(now + Duration::from_secs(1)));
        assert!(detector.observe(now + Duration::from_secs(1) + RESUME_GAP));
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
    fn workspace_aliases_do_not_collide_or_allow_cross_workspace_label_spoofing() {
        let (identities, mut hosts) = fixture_hosts();
        let work = aliases(&hosts, "work");
        let personal = aliases(&hosts, "personal");
        assert_eq!(
            work[&identities[2].to_string()],
            format!("attached-work--{} attached-work--laptop", identities[2])
        );
        for alias in work.values().flat_map(|aliases| aliases.split_whitespace()) {
            assert!(
                !personal
                    .values()
                    .any(|aliases| aliases.split_whitespace().any(|other| other == alias))
            );
        }
        hosts.get_mut(&identities[2].to_string()).unwrap().label = "work--laptop".into();
        let default = aliases(&hosts, workspace::DEFAULT);
        assert_eq!(
            default[&identities[2].to_string()],
            format!("attached-{}", identities[2])
        );
        // Duplicate labels remain disallowed inside each workspace, even if
        // the same label is perfectly valid in another workspace.
        assert_eq!(
            work[&identities[0].to_string()],
            format!("attached-work--{}", identities[0])
        );
    }

    #[test]
    fn aliases_are_namespaced_case_insensitive_and_never_impersonate_identities() {
        let (identities, hosts) = fixture_hosts();
        let names = aliases(&hosts, workspace::DEFAULT);
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
