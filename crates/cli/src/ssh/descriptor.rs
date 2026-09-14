//! On-demand renewal of a broker's discovery lease, not of its SSH sessions.
use std::{future::Future, str::FromStr, time::Duration};

use anyhow::{Context, Result, ensure};
use iroh_tickets::endpoint::EndpointTicket;
use tokio::{
    sync::Mutex,
    time::{Instant, timeout},
};

use crate::sync::{self, state::AccountCredentials, state_catalog::SyncedAttachment};

const REFRESH_TIMEOUT: Duration = Duration::from_secs(10);
const REFRESH_RETRY_DELAY: Duration = Duration::from_secs(2);

pub(super) struct Descriptors {
    state: Mutex<State>,
}

struct State {
    current: SyncedAttachment,
    last_attempt: Option<Instant>,
}

impl Descriptors {
    pub(super) fn new(current: SyncedAttachment) -> Self {
        Self {
            state: Mutex::new(State {
                current,
                last_attempt: None,
            }),
        }
    }

    pub(super) async fn get(
        &self,
        account: &AccountCredentials,
        failed: Option<&SyncedAttachment>,
    ) -> Result<SyncedAttachment> {
        self.get_with(failed, |previous| async move {
            sync::refresh::refresh_ssh_attachment(account, &previous).await
        })
        .await
    }

    // The mutex single-flights renewal across concurrent SSH connections. Only
    // setup waits for this lock: already-established byte streams never use it.
    async fn get_with<Fetch, F>(
        &self,
        failed: Option<&SyncedAttachment>,
        fetch: Fetch,
    ) -> Result<SyncedAttachment>
    where
        Fetch: FnOnce(SyncedAttachment) -> F,
        F: Future<Output = Result<SyncedAttachment>>,
    {
        let mut state = self.state.lock().await;
        let live = sync::utc_now_seconds() < state.current.expires_at;
        if live && failed.is_none_or(|failed| failed != &state.current) {
            return Ok(state.current.clone());
        }
        // Bound retries during outages, including callers already queued on the
        // same failed refresh. Never turn this cooldown into permission to use
        // an expired descriptor. A still-valid descriptor may be used unchanged.
        if state
            .last_attempt
            .is_some_and(|at| at.elapsed() < REFRESH_RETRY_DELAY)
        {
            ensure!(
                live,
                "SSH publisher descriptor expired and discovery refresh is temporarily unavailable; retry shortly"
            );
            return Ok(state.current.clone());
        }
        // Also record before awaiting so cancellation doesn't create a retry storm.
        state.last_attempt = Some(Instant::now());
        let result = timeout(REFRESH_TIMEOUT, fetch(state.current.clone())).await;
        state.last_attempt = Some(Instant::now());
        let next = result
            .context("SSH publisher discovery refresh timed out")?
            .context("could not refresh SSH publisher; existing SSH streams are unaffected")?;
        ensure!(
            next.endpoint_identity == state.current.endpoint_identity
                && next.record_id == state.current.record_id,
            "SSH publisher identity changed during discovery refresh"
        );
        ensure!(
            next.service_revision >= state.current.service_revision,
            "SSH publisher record revision moved backwards"
        );
        ensure!(
            sync::utc_now_seconds() < next.expires_at,
            "refreshed SSH publisher descriptor is already expired"
        );
        let ticket = EndpointTicket::from_str(&next.endpoint_ticket)?;
        ensure!(
            ticket.endpoint_addr().id.as_bytes() == &next.endpoint_identity,
            "refreshed SSH publisher ticket identity mismatch"
        );
        state.current = next;
        Ok(state.current.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attached_session_sync_protocol::account::RecordId;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn descriptor(expired: bool) -> SyncedAttachment {
        let id = iroh::SecretKey::generate().public();
        SyncedAttachment {
            record_id: RecordId::from_bytes([1; 16]),
            service_revision: 1,
            endpoint_ticket: EndpointTicket::new(iroh::EndpointAddr::new(id)).to_string(),
            endpoint_identity: *id.as_bytes(),
            attach_capability: [2; 32],
            attached_version: None,
            herdr_version: [0, 0, 0],
            session: String::new(),
            expires_at: sync::utc_now_seconds()
                + chrono::Duration::seconds(if expired { -1 } else { 300 }),
        }
    }

    fn renewed(mut previous: SyncedAttachment) -> SyncedAttachment {
        previous.service_revision += 1;
        previous.expires_at = sync::utc_now_seconds() + chrono::Duration::seconds(300);
        previous.attach_capability = [3; 32];
        previous
    }

    #[tokio::test]
    async fn live_descriptors_do_not_poll_the_service() {
        let original = descriptor(false);
        let cache = Descriptors::new(original.clone());
        let current = cache
            .get_with(None, |_| async { panic!("unnecessary HTTP refresh") })
            .await
            .unwrap();
        assert!(current == original);
    }

    #[tokio::test]
    async fn concurrent_expired_connections_share_one_refresh() {
        let cache = Arc::new(Descriptors::new(descriptor(true)));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let calls = calls.clone();
            tasks.spawn(async move {
                let current = cache
                    .get_with(None, |previous| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok(renewed(previous))
                    })
                    .await
                    .unwrap();
                assert_eq!(current.service_revision, 2);
                assert_eq!(current.attach_capability, [3; 32]);
            });
        }
        while let Some(task) = tasks.join_next().await {
            task.unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn setup_failure_refreshes_before_expiry_without_duplicate_renewal() {
        let original = descriptor(false);
        let cache = Descriptors::new(original.clone());
        let next = cache
            .get_with(Some(&original), |previous| async { Ok(renewed(previous)) })
            .await
            .unwrap();
        assert_eq!(next.service_revision, 2);
        let same = cache
            .get_with(Some(&original), |_| async {
                panic!("another caller already refreshed this failed snapshot")
            })
            .await
            .unwrap();
        assert!(same == next);
        let same = cache
            .get_with(Some(&next), |_| async {
                panic!("refresh cooldown must bound repeated rejection requests")
            })
            .await
            .unwrap();
        assert!(same == next);
    }

    #[tokio::test]
    async fn failed_refresh_never_reuses_an_expired_lease_and_recovers_later() {
        let original = descriptor(true);
        let cache = Descriptors::new(original.clone());
        assert!(
            cache
                .get_with(None, |_| async { anyhow::bail!("service offline") })
                .await
                .is_err()
        );
        assert!(cache.state.lock().await.current == original);
        assert!(
            cache
                .get_with(None, |_| async {
                    panic!("failure cooldown must coalesce retries")
                })
                .await
                .is_err()
        );
        cache.state.lock().await.last_attempt = Some(Instant::now() - REFRESH_RETRY_DELAY);
        let next = cache
            .get_with(None, |previous| async { Ok(renewed(previous)) })
            .await
            .unwrap();
        assert_eq!(next.service_revision, 2);
    }

    #[tokio::test]
    async fn refresh_rejects_identity_revision_expiry_and_ticket_substitutions() {
        for scenario in 0..5 {
            let original = descriptor(true);
            let cache = Descriptors::new(original.clone());
            let result = cache
                .get_with(None, |previous| async move {
                    let mut next = renewed(previous);
                    match scenario {
                        0 => next.endpoint_identity = [0; 32],
                        1 => next.record_id = RecordId::from_bytes([9; 16]),
                        2 => next.service_revision = 0,
                        3 => next.expires_at = sync::utc_now_seconds(),
                        4 => next.endpoint_ticket = descriptor(false).endpoint_ticket,
                        _ => unreachable!(),
                    }
                    Ok(next)
                })
                .await;
            assert!(
                result.is_err(),
                "accepted invalid renewal scenario {scenario}"
            );
            assert!(cache.state.lock().await.current == original);
        }
    }

    #[tokio::test]
    async fn cancellation_releases_refresh_lock_without_replacing_the_snapshot() {
        let original = descriptor(true);
        let cache = Descriptors::new(original.clone());
        let result = timeout(
            Duration::from_millis(20),
            cache.get_with(None, |_| async {
                std::future::pending::<Result<SyncedAttachment>>().await
            }),
        )
        .await;
        assert!(result.is_err());
        assert!(cache.state.lock().await.current == original);
    }
}
