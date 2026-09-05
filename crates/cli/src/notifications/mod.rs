pub(crate) mod activity;
pub(crate) mod desktop;
mod protocol;
mod tracker;
pub(crate) mod transport;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use attached_tunnel_protocol::CapabilitySecret;
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use tokio::{
    io::BufReader,
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{MissedTickBehavior, interval, sleep, timeout},
};
use tracing::{info, warn};

use crate::{
    herdr_version,
    sync::{
        self, state,
        state_catalog::{self, SyncedAttachment},
    },
    tunnel,
};
use desktop::{Desktop, Launch};
use tracker::{Notice, Tracker};

const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const MAX_SESSIONS: usize = 128;
const MAX_DESKTOP_JOBS: usize = 16;

struct Access {
    target: String,
    attachment: SyncedAttachment,
}

struct Job {
    access: Access,
    epoch: u64,
    task: JoinHandle<()>,
}

impl Drop for Job {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Queued {
    epoch: u64,
    target: String,
    endpoint: [u8; 32],
    session: String,
    notice: Notice,
    created: Instant,
}

fn expire_jobs(jobs: &mut BTreeMap<String, Job>, now: chrono::DateTime<chrono::Utc>) {
    jobs.retain(|_, job| job.access.attachment.expires_at > now);
}

fn same_access(a: &SyncedAttachment, b: &SyncedAttachment) -> bool {
    a.endpoint_identity == b.endpoint_identity
        && a.attach_capability == b.attach_capability
        && a.session == b.session
        && a.endpoint_ticket == b.endpoint_ticket
}

pub async fn watch(
    state_dir: PathBuf,
    herdr_bin: PathBuf,
    terminal: Option<PathBuf>,
    one_password: bool,
    print: bool,
) -> Result<()> {
    let _singleton = activity::singleton(&state_dir)?;
    let account = state::load_account(&state_dir, ApiKeyScope::Download)
        .context("notifications watch requires a download account bundle")?;
    let identity_bytes = *account
        .consumer_identity_secret()
        .context("download account has no Iroh identity")?;
    let identity = iroh::SecretKey::from_bytes(&identity_bytes);
    let herdr_bin = desktop::program(&herdr_bin)?;
    let local_version = herdr_version::query(&herdr_bin)?;
    let desktop = if print {
        None
    } else {
        Some(
            Desktop::detect(Launch {
                attached: std::env::current_exe()?,
                state_dir: std::fs::canonicalize(&state_dir)?,
                herdr_bin,
                terminal,
                one_password,
            })
            .await?,
        )
    };
    let endpoint = tunnel::bind_client_endpoint(&iroh::SecretKey::generate()).await?;
    eprintln!(
        "Watching remote agent events (Ctrl-C to stop). Both ends need Attached event support; no Herdr UI is opened."
    );
    let result = run(&state_dir, &endpoint, local_version, identity, desktop).await;
    endpoint.close().await;
    result
}

async fn shutdown() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("could not listen for Ctrl-C"),
        _ = terminate.recv() => Ok(()),
    }
}

async fn run(
    state_dir: &Path,
    endpoint: &Endpoint,
    local_version: herdr_version::HerdrVersion,
    identity: iroh::SecretKey,
    desktop: Option<Desktop>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Queued>(64);
    let mut jobs: BTreeMap<String, Job> = BTreeMap::new();
    let mut next_epoch = 0_u64;
    let mut refresh = JoinSet::new();
    let mut displays = JoinSet::new();
    let mut timer = interval(Duration::from_secs(1));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_refresh = Instant::now() - REFRESH_INTERVAL;
    let stop = shutdown();
    tokio::pin!(stop);
    let result = loop {
        tokio::select! {
            result = &mut stop => break result,
            _ = timer.tick() => {
                let now = sync::utc_now_seconds();
                // Expiry is enforced even while catalog refresh is unavailable.
                expire_jobs(&mut jobs, now);
                if refresh.is_empty() && last_refresh.elapsed() >= REFRESH_INTERVAL {
                    last_refresh = Instant::now();
                    let state_dir = state_dir.to_path_buf();
                    let identity_bytes = identity.to_bytes();
                    refresh.spawn(async move { discover(&state_dir, local_version, identity_bytes).await });
                }
            }
            completed = refresh.join_next(), if !refresh.is_empty() => {
                match completed {
                    Some(Ok(Ok(accesses))) => {
                        let retained: std::collections::BTreeSet<_> = accesses.iter().map(|a| a.target.clone()).collect();
                        jobs.retain(|target, _| retained.contains(target));
                        for access in accesses {
                            if access.attachment.expires_at <= sync::utc_now_seconds() { continue; }
                            if let Some(job) = jobs.get_mut(&access.target)
                                && same_access(&job.access.attachment, &access.attachment)
                                && !job.task.is_finished()
                            {
                                // Publication revisions and renewed expiry do not interrupt live subscriptions.
                                job.access = access;
                                continue;
                            }
                            jobs.remove(&access.target);
                            if jobs.len() >= MAX_SESSIONS {
                                warn!("notification session limit reached (128); additional sessions skipped");
                                break;
                            }
                            next_epoch = next_epoch.wrapping_add(1);
                            let task = tokio::spawn(watch_session(endpoint.clone(), identity.clone(), state_dir.to_path_buf(),
                                access.target.clone(), access.attachment.clone(), next_epoch, tx.clone()));
                            jobs.insert(access.target.clone(), Job { access, epoch: next_epoch, task });
                        }
                    }
                    Some(Ok(Err(error))) => warn!(%error, "notification discovery failed; existing unexpired sessions retained"),
                    Some(Err(error)) => warn!(%error, "notification discovery task failed"),
                    None => {}
                }
            }
            Some(queued) = rx.recv() => {
                let current = jobs.get(&queued.target).is_some_and(|job|
                    job.epoch == queued.epoch
                    && job.access.attachment.endpoint_identity == queued.endpoint
                    && job.access.attachment.session == queued.session
                    && job.access.attachment.expires_at > sync::utc_now_seconds());
                if !current || queued.created.elapsed() > Duration::from_secs(15) { continue; }
                match activity::is_attached(state_dir, queued.endpoint, &queued.session) {
                    Ok(true) => continue,
                    Err(error) => { warn!(%error, "could not check active attachment; notification suppressed"); continue; }
                    Ok(false) => {}
                }
                if let Some(desktop) = &desktop {
                    if displays.len() >= MAX_DESKTOP_JOBS {
                        warn!("too many pending desktop notifications; notification dropped");
                        continue;
                    }
                    let desktop = desktop.clone();
                    displays.spawn(async move { desktop.show(&queued.target, &queued.notice).await });
                } else {
                    use std::io::Write;
                    let value = serde_json::json!({"target":queued.target, "title":queued.notice.title, "body":queued.notice.body});
                    let output = (|| -> Result<()> {
                        let mut stdout = std::io::stdout().lock();
                        serde_json::to_writer(&mut stdout, &value)?;
                        writeln!(stdout)?;
                        stdout.flush()?;
                        Ok(())
                    })();
                    if let Err(error) = output { break Err(error); }
                }
            }
            completed = displays.join_next(), if !displays.is_empty() => {
                match completed {
                    Some(Ok(Err(error))) => warn!(%error, "desktop notification failed"),
                    Some(Err(error)) => warn!(%error, "desktop notification task failed"),
                    _ => {}
                }
            }
        }
    };
    // Abort and join before endpoint shutdown so sockets, locks, and helper
    // subprocesses are released promptly. Interactive terminal windows are independent.
    let tasks: Vec<_> = jobs
        .values_mut()
        .map(|job| {
            job.task.abort();
            &mut job.task
        })
        .collect();
    for task in tasks {
        let _ = task.await;
    }
    refresh.shutdown().await;
    displays.shutdown().await;
    result
}

async fn discover(
    state_dir: &Path,
    version: herdr_version::HerdrVersion,
    identity: [u8; 32],
) -> Result<Vec<Access>> {
    let refreshed = sync::refresh::refresh_sessions(state_dir, version).await?;
    for warning in refreshed.warnings {
        if !warning.is_verbose_only() {
            warn!(%warning, "notification discovery warning");
        }
    }
    let account = state::load_account(state_dir, ApiKeyScope::Download)?;
    ensure!(
        account.consumer_identity_secret() == Some(&identity),
        "consumer identity changed; restart the notification watcher"
    );
    let mut accesses = Vec::new();
    if refreshed.sessions.len() > MAX_SESSIONS {
        warn!("notification session limit reached (128); additional sessions skipped");
    }
    for session in refreshed.sessions.into_iter().take(MAX_SESSIONS) {
        if let Some(attachment) = state_catalog::attachment(
            state_dir,
            &account,
            &session.host,
            &session.session,
            sync::utc_now_seconds(),
        )? {
            let ticket = EndpointTicket::from_str(&attachment.endpoint_ticket)?;
            ensure!(
                ticket.endpoint_addr().id.as_bytes() == &attachment.endpoint_identity,
                "event endpoint ticket identity mismatch"
            );
            accesses.push(Access {
                target: session.target,
                attachment,
            });
        }
    }
    Ok(accesses)
}

async fn watch_session(
    endpoint: Endpoint,
    identity: iroh::SecretKey,
    state_dir: PathBuf,
    target: String,
    attachment: SyncedAttachment,
    epoch: u64,
    notices: mpsc::Sender<Queued>,
) {
    let mut backoff = 1;
    loop {
        let started = Instant::now();
        let result = receive_session(
            &endpoint,
            &identity,
            &state_dir,
            &target,
            &attachment,
            epoch,
            &notices,
        )
        .await;
        if let Err(error) = result {
            warn!(target, %error, "event subscription disconnected; retrying without replay");
        }
        if started.elapsed() >= Duration::from_secs(60) {
            backoff = 1;
        }
        let mut jitter = [0u8; 2];
        let _ = getrandom::fill(&mut jitter);
        sleep(
            Duration::from_secs(backoff)
                + Duration::from_millis(u64::from(u16::from_le_bytes(jitter) % 1000)),
        )
        .await;
        backoff = (backoff * 2).min(60);
    }
}

async fn receive_session(
    endpoint: &Endpoint,
    identity: &iroh::SecretKey,
    state_dir: &Path,
    target: &str,
    attachment: &SyncedAttachment,
    epoch: u64,
    notices: &mpsc::Sender<Queued>,
) -> Result<()> {
    let ticket = EndpointTicket::from_str(&attachment.endpoint_ticket)?;
    let (_connection, receive) = transport::connect(
        endpoint,
        identity,
        ticket.endpoint_addr().clone(),
        &attachment.session,
        &CapabilitySecret::from_bytes(attachment.attach_capability),
    )
    .await?;
    let mut lines = protocol::Lines::new(BufReader::new(receive));
    let first = timeout(Duration::from_secs(15), lines.next())
        .await
        .context("event bootstrap timed out")??;
    let first = protocol::decode_message(&first)?;
    ensure!(
        matches!(first, protocol::Message::Snapshot { .. }),
        "event stream has no initial snapshot"
    );
    let mut tracker = Tracker::default();
    tracker.apply(first);
    info!(target, "passive agent subscription established");
    loop {
        let line = timeout(Duration::from_secs(20), lines.next())
            .await
            .context("event heartbeat timed out")??;
        let message = protocol::decode_message(&line)?;
        let updates = tracker.apply(message);
        // Always update state even while suppressed: detaching must not replay it.
        if updates.is_empty()
            || activity::is_attached(state_dir, attachment.endpoint_identity, &attachment.session)?
        {
            continue;
        }
        for notice in updates {
            if notices
                .try_send(Queued {
                    epoch,
                    target: target.to_owned(),
                    endpoint: attachment.endpoint_identity,
                    session: attachment.session.clone(),
                    notice,
                    created: Instant::now(),
                })
                .is_err()
            {
                warn!(target, "notification queue is full; live event dropped");
            }
        }
    }
}

#[cfg(test)]
mod watcher_tests;

#[cfg(test)]
mod tests {
    use super::*;
    fn attachment() -> SyncedAttachment {
        SyncedAttachment {
            record_id: attached_session_sync_protocol::account::RecordId::from_bytes([1; 16]),
            service_revision: 1,
            endpoint_ticket: "ticket".into(),
            endpoint_identity: [1; 32],
            attach_capability: [2; 32],
            attached_version: None,
            herdr_version: [0, 8, 2],
            expires_at: sync::utc_now_seconds(),
            session: "work".into(),
        }
    }

    #[tokio::test]
    async fn expiry_aborts_only_expired_sessions_even_without_catalog_refresh() {
        let now = sync::utc_now_seconds();
        let mut jobs = BTreeMap::new();
        let mut handles = Vec::new();
        for (target, expires_at) in [
            ("expired", now),
            ("live", now + chrono::Duration::seconds(60)),
        ] {
            let task = tokio::spawn(std::future::pending::<()>());
            handles.push(task.abort_handle());
            let mut attachment = attachment();
            attachment.expires_at = expires_at;
            jobs.insert(
                target.into(),
                Job {
                    access: Access {
                        target: target.into(),
                        attachment,
                    },
                    epoch: 1,
                    task,
                },
            );
        }
        expire_jobs(&mut jobs, now);
        assert_eq!(jobs.len(), 1);
        assert!(jobs.contains_key("live"));
        tokio::task::yield_now().await;
        assert!(handles[0].is_finished());
        assert!(!handles[1].is_finished());
        jobs.clear();
        tokio::task::yield_now().await;
        assert!(handles[1].is_finished());
    }

    #[test]
    fn publication_renewal_does_not_reconnect_but_capability_rotation_does() {
        let mut a = attachment();
        let mut b = a.clone();
        b.expires_at += chrono::Duration::seconds(300);
        b.service_revision += 1;
        assert!(same_access(&a, &b));
        a.attach_capability = [3; 32];
        assert!(!same_access(&a, &b));
    }
}
