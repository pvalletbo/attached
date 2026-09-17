use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use attached_session_sync_protocol::account::AuthorizedConsumerIdentity;
use attached_tunnel_protocol::{
    ATTACHED_UPDATE_ALPN, AttachedUpdateRequest, AttachedUpdateResponse, AttachedVersion,
    CapabilitySecret, UpdateOperationId, read_attached_update_request,
    write_attached_update_response,
};
use iroh::{
    Endpoint,
    endpoint::{AfterHandshakeOutcome, BindOpts, EndpointHooks, presets},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::{
    attached_version,
    diagnostics::next_connection_id,
    identity, installation, local_encryption,
    serve_handoff::{
        ActivatedCandidateIpc, CandidateConfig, CandidateDisposition, CandidateEvent, CandidateIpc,
        CandidateProcess, ParentCommand, ServeConfig,
    },
    sync::{publisher, state},
};

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(5);
const PUBLISH_INTERVAL: Duration = Duration::from_secs(30);
const MAX_PENDING_CONNECTIONS: usize = 16;
const MAX_AUTHENTICATED_CONNECTIONS: usize = 16;
const UNAUTHORIZED_IDENTITY_ERROR_CODE: u32 = 403;
const UNAUTHORIZED_IDENTITY_REASON: &[u8] = b"unauthorized consumer identity";
const CANDIDATE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const CLIENT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const CANDIDATE_EVENT_TIMEOUT: Duration = Duration::from_secs(5);
const ATTACHED_UPDATE_PREPARE_TIMEOUT: Duration = Duration::from_secs(130);

#[derive(Debug)]
struct ConsumerIdentityAuthorization {
    authorized_identity: AuthorizedConsumerIdentity,
}

impl ConsumerIdentityAuthorization {
    const fn new(authorized_identity: AuthorizedConsumerIdentity) -> Self {
        Self {
            authorized_identity,
        }
    }

    fn authorize(&self, remote_identity: &[u8; 32]) -> AfterHandshakeOutcome {
        if remote_identity == self.authorized_identity.as_bytes() {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: UNAUTHORIZED_IDENTITY_ERROR_CODE.into(),
                reason: UNAUTHORIZED_IDENTITY_REASON.to_vec(),
            }
        }
    }
}

impl EndpointHooks for ConsumerIdentityAuthorization {
    async fn after_handshake(
        &self,
        connection: &iroh::endpoint::Connection,
    ) -> AfterHandshakeOutcome {
        // Iroh exposes the authenticated peer key after TLS, but rejecting from this hook keeps
        // the connection from reaching application dispatch or opening a tunnel stream.
        let outcome = self.authorize(connection.remote_id().as_bytes());
        if matches!(outcome, AfterHandshakeOutcome::Reject { .. }) {
            warn!(
                category = "authorization",
                authentication_layer = "iroh_remote_identity",
                "Iroh connection admission rejected: unauthorized remote identity"
            );
        }
        outcome
    }
}

#[cfg(test)]
async fn run_registered_lifecycle<Lifecycle, LifecycleFuture>(
    registry_dir: &std::path::Path,
    endpoint_identity: [u8; 32],
    lifecycle: Lifecycle,
) -> Result<()>
where
    Lifecycle: FnOnce() -> LifecycleFuture,
    LifecycleFuture: std::future::Future<Output = Result<()>>,
{
    let active_endpoint = crate::endpoint_registry::register(registry_dir, endpoint_identity)
        .context("could not register the live local endpoint")?;
    let result = lifecycle().await;
    drop(active_endpoint);
    result
}

struct ServerRuntime {
    config: ServeConfig,
    authorized_consumer_identity: AuthorizedConsumerIdentity,
    key: iroh::SecretKey,
    capability: CapabilitySecret,
    master_key: Zeroizing<[u8; 32]>,
    update_limit: Arc<Semaphore>,
    active_operation: Arc<Mutex<Option<UpdateOperationId>>>,
}

#[derive(Clone)]
struct CandidateConfirmation {
    operation_id: UpdateOperationId,
    version: AttachedVersion,
    events: mpsc::UnboundedSender<CandidateEvent>,
    disposition: watch::Receiver<CandidateDisposition>,
    abort: CancellationToken,
    announced_consumer: Arc<AtomicBool>,
}

impl CandidateConfirmation {
    fn new(
        operation_id: UpdateOperationId,
        version: AttachedVersion,
        ipc: ActivatedCandidateIpc,
    ) -> Self {
        Self {
            operation_id,
            version,
            events: ipc.events,
            disposition: ipc.disposition,
            abort: ipc.abort,
            announced_consumer: Arc::new(AtomicBool::new(false)),
        }
    }

    fn is_pending(&self) -> bool {
        *self.disposition.borrow() == CandidateDisposition::Pending
    }
}

#[derive(Clone)]
struct RollbackRecord {
    operation_id: UpdateOperationId,
    reason: String,
}

struct UpdateResources {
    config: ServeConfig,
    master_key: Arc<Zeroizing<[u8; 32]>>,
    endpoint_identity: [u8; 32],
    bind_sockets: Vec<SocketAddr>,
    capability: CapabilitySecret,
    update_limit: Arc<Semaphore>,
    active_operation: Arc<Mutex<Option<UpdateOperationId>>>,
    candidate: Option<Arc<CandidateConfirmation>>,
    rollback: Option<RollbackRecord>,
}

struct PreparedHandoff {
    operation_id: UpdateOperationId,
    version: AttachedVersion,
    update: installation::PreparedRemoteUpdate,
    candidate: CandidateProcess,
    _permit: OwnedSemaphorePermit,
}

enum PreparedAttachedUpdate {
    Current(AttachedVersion),
    Handoff(Box<PreparedHandoff>),
}

enum EndpointOutcome {
    Shutdown,
    Handoff(Box<PreparedHandoff>),
    CandidateAborted,
}

enum HandoffResolution {
    Retired,
    RolledBack(RollbackRecord),
}

pub async fn serve(state_dir: PathBuf, host_label: Option<String>) -> Result<()> {
    let account = state::load_account(
        &state_dir,
        attached_session_sync_protocol::account::ApiKeyScope::Publish,
    )
    .context("`serve` requires a publish account bundle")?;
    let authorized_consumer_identity = account
        .authorized_consumer_identity()
        .context("publish account bundle has no authorized consumer identity")?;
    let key = identity::load_or_create(&state_dir)?;
    let master_key = local_encryption::handoff_master_key(&state_dir)?;
    installation::current_attached_executable()?;
    let endpoint = bind_server_endpoint(&key, authorized_consumer_identity, None).await?;
    let host_label = host_label.unwrap_or_else(|| publisher::default_host_label(&endpoint.addr()));
    let runtime = ServerRuntime {
        config: ServeConfig {
            state_dir,
            host_label,
        },
        authorized_consumer_identity,
        key,
        capability: CapabilitySecret::generate(),
        master_key,
        update_limit: Arc::new(Semaphore::new(1)),
        active_operation: Arc::new(Mutex::new(None)),
    };
    run_supervisor(runtime, Some(endpoint), None, None).await
}

pub(crate) async fn serve_candidate() -> Result<()> {
    let (config, ipc) = CandidateIpc::receive().await?;
    local_encryption::configure_handoff_master_key(config.master_key)?;
    let current_version = attached_version::current();
    ensure!(
        current_version == config.expected_version,
        "candidate version {current_version} does not match expected version {}",
        config.expected_version
    );
    let account = state::load_account(
        &config.serve.state_dir,
        attached_session_sync_protocol::account::ApiKeyScope::Publish,
    )
    .context("candidate could not load the publish account")?;
    let authorized_consumer_identity = account
        .authorized_consumer_identity()
        .context("publish account bundle has no authorized consumer identity")?;
    let key = identity::load_or_create(&config.serve.state_dir)?;
    ensure!(
        key.public().as_bytes() == &config.expected_endpoint_identity,
        "candidate endpoint identity changed during handoff"
    );
    let attached_executable = installation::current_attached_executable()?;
    ensure!(
        attached_version::query(&attached_executable)? == current_version,
        "candidate executable version changed during preflight"
    );
    publisher::Publisher::load(&config.serve.state_dir, config.expected_endpoint_identity)
        .context("candidate could not initialize the host publisher")?;
    ipc.send(CandidateEvent::Prepared {
        version: current_version,
    })?;
    let operation_id = config.operation_id;
    let bind_sockets = config.bind_sockets.clone();
    let capability = CapabilitySecret::from_bytes(config.capability);
    let serve_config = config.serve.clone();
    let master_key = Zeroizing::new(config.master_key);
    drop(config);
    let activated = ipc.activate().await?;
    let confirmation = Arc::new(CandidateConfirmation::new(
        operation_id,
        current_version,
        activated,
    ));
    let failure_events = confirmation.events.clone();
    let runtime = ServerRuntime {
        config: serve_config,
        authorized_consumer_identity,
        key,
        capability,
        master_key,
        update_limit: Arc::new(Semaphore::new(1)),
        active_operation: Arc::new(Mutex::new(None)),
    };
    let result = run_supervisor(runtime, None, Some(bind_sockets), Some(confirmation)).await;
    if let Err(error) = &result {
        let _ = failure_events.send(CandidateEvent::Failed {
            reason: bounded_public_error(error),
        });
    }
    result
}

fn server_endpoint_builder(
    key: &iroh::SecretKey,
    authorized_consumer_identity: AuthorizedConsumerIdentity,
) -> iroh::endpoint::Builder {
    Endpoint::builder(presets::N0)
        .secret_key(key.clone())
        .alpns(vec![
            ATTACHED_UPDATE_ALPN.to_vec(),
            crate::ssh::ALPN.to_vec(),
        ])
        .hooks(ConsumerIdentityAuthorization::new(
            authorized_consumer_identity,
        ))
}

async fn bind_server_endpoint(
    key: &iroh::SecretKey,
    authorized_consumer_identity: AuthorizedConsumerIdentity,
    bind_sockets: Option<&[SocketAddr]>,
) -> Result<Endpoint> {
    let mut builder = server_endpoint_builder(key, authorized_consumer_identity);
    if let Some(bind_sockets) = bind_sockets {
        builder = builder.clear_ip_transports();
        for socket in bind_sockets {
            builder = builder
                .bind_addr_with_opts(*socket, BindOpts::default())
                .with_context(|| format!("could not reuse Iroh socket {socket}"))?;
        }
    }
    let endpoint = builder
        .bind()
        .await
        .context("failed to bind the Iroh endpoint")?;
    endpoint.online().await;
    Ok(endpoint)
}

async fn run_supervisor(
    runtime: ServerRuntime,
    mut initial_endpoint: Option<Endpoint>,
    mut bind_sockets: Option<Vec<SocketAddr>>,
    mut candidate: Option<Arc<CandidateConfirmation>>,
) -> Result<()> {
    let registry_dir = crate::endpoint_registry::default_dir()
        .context("could not locate the live local endpoint registry")?;
    let mut rollback = None;
    let mut announced = false;
    loop {
        let endpoint = match initial_endpoint.take() {
            Some(endpoint) => endpoint,
            None => {
                bind_server_endpoint(
                    &runtime.key,
                    runtime.authorized_consumer_identity,
                    bind_sockets.as_deref(),
                )
                .await?
            }
        };
        bind_sockets = Some(endpoint.bound_sockets());
        let endpoint_identity = *endpoint.addr().id.as_bytes();
        let active_endpoint = crate::endpoint_registry::register(&registry_dir, endpoint_identity)
            .context("could not register the live local endpoint")?;
        let publication = Arc::new(Mutex::new(
            publisher::Publisher::load(&runtime.config.state_dir, endpoint_identity)
                .context("could not initialize the host publisher")?,
        ));
        publish_host(
            &publication,
            &runtime.config.host_label,
            &endpoint,
            &runtime.capability,
        )
        .await
        .context("could not publish the initial host catalog")?;
        if let Some(candidate) = &candidate {
            candidate
                .events
                .send(CandidateEvent::Ready {
                    version: candidate.version,
                })
                .map_err(|_| anyhow!("candidate watchdog stopped before readiness"))?;
        }
        if !announced {
            eprintln!(
                "Serving Attached SSH tunnels as `{}`.",
                runtime.config.host_label
            );
            announced = true;
        }
        let publisher_task = tokio::spawn(run_publisher(
            publication,
            runtime.config.host_label.clone(),
            endpoint.clone(),
            runtime.capability.clone(),
        ));
        let outcome = serve_endpoint(
            &endpoint,
            runtime.capability.clone(),
            Arc::new(UpdateResources {
                config: runtime.config.clone(),
                master_key: Arc::new(Zeroizing::new(*runtime.master_key)),
                endpoint_identity,
                bind_sockets: bind_sockets.clone().unwrap_or_default(),
                capability: runtime.capability.clone(),
                update_limit: runtime.update_limit.clone(),
                active_operation: runtime.active_operation.clone(),
                candidate: candidate.clone(),
                rollback: rollback.clone(),
            }),
            candidate.as_ref().map(|candidate| candidate.abort.clone()),
        )
        .await;
        publisher_task.abort();
        let _ = publisher_task.await;
        endpoint.close().await;
        drop(endpoint);
        drop(active_endpoint);
        match outcome? {
            EndpointOutcome::Shutdown => return Ok(()),
            EndpointOutcome::CandidateAborted => bail!("candidate handoff was aborted"),
            EndpointOutcome::Handoff(handoff) => match coordinate_handoff(*handoff).await? {
                HandoffResolution::Retired => return Ok(()),
                HandoffResolution::RolledBack(record) => {
                    rollback = Some(record);
                    candidate = None;
                    *runtime.active_operation.lock().await = None;
                }
            },
        }
    }
}

async fn coordinate_handoff(mut handoff: PreparedHandoff) -> Result<HandoffResolution> {
    let precommit = confirm_attached_candidate(
        &mut handoff.candidate,
        handoff.version,
        CANDIDATE_CONFIRM_TIMEOUT,
    )
    .await;

    if let Err(error) = precommit {
        warn!(
            operation_id = %handoff.operation_id,
            error = %error,
            "Attached update candidate failed; rolling back"
        );
        handoff.candidate.abort().await;
        handoff
            .update
            .rollback()
            .context("could not restore the previous Attached binary")?;
        return Ok(HandoffResolution::RolledBack(RollbackRecord {
            operation_id: handoff.operation_id,
            reason: "updated Attached candidate did not become reachable; the previous server was restored"
                .to_owned(),
        }));
    }

    match timeout(CANDIDATE_EVENT_TIMEOUT, handoff.candidate.next_event()).await {
        Ok(Ok(CandidateEvent::ClientSucceeded)) => {}
        Ok(Ok(event)) => warn!(
            operation_id = %handoff.operation_id,
            ?event,
            "candidate committed without the expected client acknowledgement"
        ),
        Ok(Err(error)) => warn!(
            operation_id = %handoff.operation_id,
            error = %error,
            "candidate committed after its control channel closed"
        ),
        Err(_) => warn!(
            operation_id = %handoff.operation_id,
            "candidate committed before client acknowledgement was observed"
        ),
    }
    if let Err(error) = handoff.update.commit() {
        warn!(
            operation_id = %handoff.operation_id,
            error = %error,
            "updated Attached is running but its rollback file could not be removed"
        );
    }
    info!(
        operation_id = %handoff.operation_id,
        version = %handoff.version,
        "remote Attached update committed"
    );
    let status = handoff.candidate.supervise().await?;
    ensure!(
        status.success(),
        "updated Attached server exited with {status}"
    );
    Ok(HandoffResolution::Retired)
}

async fn confirm_attached_candidate(
    candidate: &mut CandidateProcess,
    expected_version: AttachedVersion,
    confirmation_timeout: Duration,
) -> Result<()> {
    // Preparation finishes while the old endpoint is still serving. This function is called only
    // after that endpoint has been drained and closed, so start the confirmation budget here to
    // prevent shutdown latency from causing an early rollback.
    let deadline = Instant::now() + confirmation_timeout;
    candidate.send(&ParentCommand::Activate).await?;
    match timeout_at(deadline, candidate.next_event())
        .await
        .context("updated Attached candidate readiness timed out")??
    {
        CandidateEvent::Ready { version } if version == expected_version => {}
        CandidateEvent::Failed { reason } => {
            bail!("updated Attached candidate failed: {reason}")
        }
        event => bail!("updated Attached candidate sent unexpected readiness event {event:?}"),
    }
    match timeout_at(deadline, candidate.next_event())
        .await
        .context("consumer did not reach the updated Attached candidate")??
    {
        CandidateEvent::ConsumerConnected => {}
        CandidateEvent::Failed { reason } => {
            bail!("updated Attached candidate failed: {reason}")
        }
        event => {
            bail!("updated Attached candidate sent unexpected confirmation event {event:?}")
        }
    }
    candidate.send(&ParentCommand::Commit).await
}

fn new_operation_id() -> Result<UpdateOperationId> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .context("operating-system randomness is unavailable for the update operation")?;
    Ok(UpdateOperationId::from_bytes(bytes))
}

fn bounded_public_error(_error: &anyhow::Error) -> String {
    "updated Attached candidate failed".to_owned()
}

async fn run_publisher(
    publication: Arc<Mutex<publisher::Publisher>>,
    host_label: String,
    endpoint: Endpoint,
    capability: CapabilitySecret,
) {
    let mut ticker = tokio::time::interval_at(Instant::now() + PUBLISH_INTERVAL, PUBLISH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(error) = publish_host(&publication, &host_label, &endpoint, &capability).await {
            warn!(error = %error, "host catalog publication failed");
        }
    }
}

async fn publish_host(
    publication: &Arc<Mutex<publisher::Publisher>>,
    host_label: &str,
    endpoint: &Endpoint,
    capability: &CapabilitySecret,
) -> Result<()> {
    match publication
        .lock()
        .await
        .publish_snapshot(host_label, endpoint.addr(), capability)
        .await?
    {
        publisher::PublishOutcome::Unchanged => {}
        publisher::PublishOutcome::Published { revision } => {
            info!(revision, "published encrypted host catalog")
        }
    }
    Ok(())
}

async fn prepare_attached_handoff(
    resources: &UpdateResources,
    operation_id: UpdateOperationId,
    permit: OwnedSemaphorePermit,
) -> Result<PreparedAttachedUpdate> {
    let update = timeout(
        ATTACHED_UPDATE_PREPARE_TIMEOUT,
        tokio::task::spawn_blocking(installation::prepare_remote_update),
    )
    .await
    .context("remote `attached update` exceeded its preparation deadline")?
    .context("remote `attached update` task failed")??;
    let version = update.candidate_version();
    if version == attached_version::current() {
        update.commit()?;
        return Ok(PreparedAttachedUpdate::Current(version));
    }
    let config = CandidateConfig {
        serve: resources.config.clone(),
        operation_id,
        expected_version: version,
        expected_endpoint_identity: resources.endpoint_identity,
        capability: resources.capability.to_bytes(),
        master_key: **resources.master_key,
        bind_sockets: resources.bind_sockets.clone(),
    };
    let candidate = CandidateProcess::spawn(update.executable(), &config).await?;
    Ok(PreparedAttachedUpdate::Handoff(Box::new(PreparedHandoff {
        operation_id,
        version,
        update,
        candidate,
        _permit: permit,
    })))
}

async fn abort_prepared_handoff(mut handoff: PreparedHandoff) -> Result<()> {
    handoff.candidate.abort().await;
    handoff.update.rollback()
}

async fn candidate_confirmation_response(
    resources: &UpdateResources,
    operation_id: UpdateOperationId,
    observed_version: AttachedVersion,
) -> (
    AttachedUpdateResponse,
    Option<mpsc::UnboundedSender<CandidateEvent>>,
) {
    if let Some(candidate) = &resources.candidate
        && candidate.operation_id == operation_id
    {
        if candidate.version != observed_version {
            return (
                AttachedUpdateResponse::Failed(
                    "updated Attached version did not match the prepared candidate".to_owned(),
                ),
                None,
            );
        }
        let mut disposition = candidate.disposition.clone();
        let notify_watchdog = *disposition.borrow() == CandidateDisposition::Pending
            && !candidate.announced_consumer.swap(true, Ordering::SeqCst);
        if notify_watchdog {
            let _ = candidate.events.send(CandidateEvent::ConsumerConnected);
        }
        loop {
            let current = *disposition.borrow();
            match current {
                CandidateDisposition::Pending => {
                    if disposition.changed().await.is_err() {
                        return (
                            AttachedUpdateResponse::Failed(
                                "updated Attached watchdog stopped before commit".to_owned(),
                            ),
                            None,
                        );
                    }
                }
                CandidateDisposition::Committed => {
                    return (
                        AttachedUpdateResponse::Committed(candidate.version),
                        notify_watchdog.then(|| candidate.events.clone()),
                    );
                }
                CandidateDisposition::Aborted => {
                    return (
                        AttachedUpdateResponse::Failed(
                            "updated Attached candidate was rolled back".to_owned(),
                        ),
                        None,
                    );
                }
            }
        }
    }

    if resources
        .active_operation
        .lock()
        .await
        .is_some_and(|active| active == operation_id)
    {
        return (AttachedUpdateResponse::Waiting, None);
    }
    if let Some(rollback) = &resources.rollback
        && rollback.operation_id == operation_id
    {
        return (
            AttachedUpdateResponse::Failed(rollback.reason.clone()),
            None,
        );
    }
    (
        AttachedUpdateResponse::Failed("unknown Attached update operation".to_owned()),
        None,
    )
}

async fn reply_attached_update(
    send: &mut iroh::endpoint::SendStream,
    response: AttachedUpdateResponse,
) -> Result<()> {
    // Dropping the last connection handle immediately after FIN can discard
    // even a small terminal response. Keep it alive until delivery is acknowledged.
    timeout(AUTHENTICATION_TIMEOUT, async {
        write_attached_update_response(send, response).await?;
        send.stopped().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("Attached update response was not acknowledged")?
}

async fn serve_attached_update_connection(
    connection: iroh::endpoint::Connection,
    resources: Arc<UpdateResources>,
    handoff_tx: mpsc::Sender<PreparedHandoff>,
) -> Result<()> {
    let (mut send, mut receive) = timeout(AUTHENTICATION_TIMEOUT, connection.accept_bi())
        .await
        .context("Attached update request handshake timed out")??;
    let request = timeout(
        AUTHENTICATION_TIMEOUT,
        read_attached_update_request(&mut receive, &resources.capability),
    )
    .await
    .context("Attached update request frame timed out")??;
    match request {
        AttachedUpdateRequest::Start => {
            if resources
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.is_pending())
            {
                reply_attached_update(&mut send, AttachedUpdateResponse::Busy).await?;
                return Ok(());
            }
            let permit = match resources.update_limit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    reply_attached_update(&mut send, AttachedUpdateResponse::Busy).await?;
                    return Ok(());
                }
            };
            let operation_id = new_operation_id()?;
            *resources.active_operation.lock().await = Some(operation_id);
            let prepared = prepare_attached_handoff(&resources, operation_id, permit).await;
            let prepared = match prepared {
                Ok(PreparedAttachedUpdate::Current(version)) => {
                    *resources.active_operation.lock().await = None;
                    reply_attached_update(&mut send, AttachedUpdateResponse::Current(version))
                        .await?;
                    return Ok(());
                }
                Ok(PreparedAttachedUpdate::Handoff(prepared)) => *prepared,
                Err(_error) => {
                    *resources.active_operation.lock().await = None;
                    let _ = reply_attached_update(
                        &mut send,
                        AttachedUpdateResponse::Failed(
                            "remote Attached update could not be prepared".to_owned(),
                        ),
                    )
                    .await;
                    bail!("remote Attached update preparation failed");
                }
            };
            if let Err(error) = reply_attached_update(
                &mut send,
                AttachedUpdateResponse::Restarting {
                    operation_id,
                    version: prepared.version,
                    reconnect_timeout_secs: CLIENT_RECONNECT_TIMEOUT.as_secs() as u16,
                },
            )
            .await
            {
                *resources.active_operation.lock().await = None;
                abort_prepared_handoff(prepared).await?;
                return Err(error).context("could not announce the Attached update handoff");
            }
            if let Err(error) = handoff_tx.send(prepared).await {
                *resources.active_operation.lock().await = None;
                abort_prepared_handoff(error.0).await?;
                bail!("Attached server stopped before the prepared handoff");
            }
            Ok(())
        }
        AttachedUpdateRequest::Confirm {
            operation_id,
            observed_version,
        } => {
            let (response, succeeded) =
                candidate_confirmation_response(&resources, operation_id, observed_version).await;
            reply_attached_update(&mut send, response).await?;
            if let Some(events) = succeeded {
                let _ = events.send(CandidateEvent::ClientSucceeded);
            }
            Ok(())
        }
    }
}

async fn shutdown_connections(connections: &mut JoinSet<Result<()>>) {
    // Admission has stopped and tunnel cancellation has been signalled. Drain every accepted
    // connection so fixed updater work remains owned until bounded_process completes or kills
    // and reaps its process group at the hard deadline.
    while connections.join_next().await.is_some() {}
}

async fn serve_endpoint(
    endpoint: &Endpoint,
    capability: CapabilitySecret,
    update_resources: Arc<UpdateResources>,
    candidate_abort: Option<CancellationToken>,
) -> Result<EndpointOutcome> {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_CONNECTIONS));
    let authenticated = Arc::new(Semaphore::new(MAX_AUTHENTICATED_CONNECTIONS));
    let cancellation = CancellationToken::new();
    let mut connections = JoinSet::new();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    let (handoff_tx, mut handoff_rx) = mpsc::channel(1);
    let abort_enabled = candidate_abort.is_some();
    let candidate_abort = candidate_abort.unwrap_or_default();

    let result = loop {
        tokio::select! {
            result = &mut shutdown => {
                result.context("failed to listen for Ctrl-C")?;
                break Ok(EndpointOutcome::Shutdown);
            }
            () = candidate_abort.cancelled(), if abort_enabled => {
                break Ok(EndpointOutcome::CandidateAborted);
            }
            handoff = handoff_rx.recv() => {
                let handoff = handoff.context("Attached update handoff channel stopped")?;
                break Ok(EndpointOutcome::Handoff(Box::new(handoff)));
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break Err(anyhow!("Iroh endpoint stopped accepting connections"));
                };
                let Ok(pending_permit) = pending.clone().try_acquire_owned() else {
                    drop(incoming);
                    continue;
                };
                let connection_id = next_connection_id();
                let capability = capability.clone();
                let authenticated = authenticated.clone();
                let child_cancellation = cancellation.child_token();
                let update_resources = update_resources.clone();
                let handoff_tx = handoff_tx.clone();
                connections.spawn(async move {
                    let result = async {
                        let connection = timeout(AUTHENTICATION_TIMEOUT, incoming)
                            .await
                            .context("Iroh connection handshake timed out")??;
                        drop(pending_permit);
                        let _permit = authenticated.try_acquire_owned()
                            .context("authenticated connection capacity is exhausted")?;
                        if connection.alpn() == crate::ssh::ALPN {
                            return crate::ssh::serve(connection, update_resources.config.state_dir.clone(), capability, child_cancellation, update_resources.master_key.clone()).await;
                        }
                        if connection.alpn() == ATTACHED_UPDATE_ALPN {
                            return serve_attached_update_connection(
                                connection,
                                update_resources,
                                handoff_tx,
                            )
                            .await;
                        }
                        bail!("unsupported tunnel protocol");
                    }
                    .await;
                    if let Err(error) = result {
                        warn!(connection_id, error = %error, "Iroh connection rejected");
                    }
                    Ok::<_, anyhow::Error>(())
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "Iroh connection task failed");
                }
            }
        }
    };

    cancellation.cancel();
    shutdown_connections(&mut connections).await;
    result
}

#[cfg(test)]
#[path = "server_integration_tests.rs"]
mod integration_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use attached_session_sync_protocol::account::ConsumerIdentitySecret;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn consumer_identity_hook_accepts_only_the_published_public_key() {
        let hook = ConsumerIdentityAuthorization::new(
            ConsumerIdentitySecret::from_bytes([0x11; 32]).authorized_identity(),
        );
        let authorized = iroh::SecretKey::from_bytes(&[0x11; 32]).public();
        let unauthorized = iroh::SecretKey::from_bytes(&[0x22; 32]).public();

        assert!(matches!(
            hook.authorize(authorized.as_bytes()),
            AfterHandshakeOutcome::Accept
        ));
        let AfterHandshakeOutcome::Reject { error_code, reason } =
            hook.authorize(unauthorized.as_bytes())
        else {
            panic!("unauthorized identity was accepted");
        };
        assert_eq!(error_code, UNAUTHORIZED_IDENTITY_ERROR_CODE.into());
        assert_eq!(reason, UNAUTHORIZED_IDENTITY_REASON);
    }

    #[tokio::test]
    async fn endpoint_registration_is_held_for_serving_lifetime() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let root = crate::test_support::canonical_tempdir();
            let registry = root.path().join("registry-user/live-endpoints");
            let identity = [0x44; 32];

            run_registered_lifecycle(&registry, identity, || async {
                assert!(
                    crate::endpoint_registry::is_active(&registry, identity).unwrap(),
                    "registry was inactive during initial publication"
                );
                tokio::task::yield_now().await;
                assert!(
                    crate::endpoint_registry::is_active(&registry, identity).unwrap(),
                    "registry was inactive while serving"
                );
                tokio::task::yield_now().await;
                assert!(
                    crate::endpoint_registry::is_active(&registry, identity).unwrap(),
                    "registry was inactive during endpoint shutdown"
                );
                Ok(())
            })
            .await
            .unwrap();

            assert!(!crate::endpoint_registry::is_active(&registry, identity).unwrap());
        })
        .await
        .expect("endpoint registration lifecycle scenario timed out");
    }

    #[tokio::test]
    async fn candidate_confirmation_budget_begins_at_cutover() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let root = crate::test_support::canonical_tempdir();
            let executable = root.path().join("candidate");
            fs::write(
                &executable,
                "#!/bin/sh\nset -eu\nIFS= read -r config\nprintf '%s\\n' '{\"type\":\"prepared\",\"version\":{\"major\":0,\"minor\":4,\"patch\":0}}'\nIFS= read -r activate\nsleep 1\nprintf '%s\\n' '{\"type\":\"ready\",\"version\":{\"major\":0,\"minor\":4,\"patch\":0}}' '{\"type\":\"consumer_connected\"}'\nIFS= read -r commit\n",
            )
            .unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            let version = AttachedVersion::new(0, 4, 0);
            let config = CandidateConfig {
                serve: ServeConfig {
                    state_dir: root.path().join("state"),

                    host_label: "office".to_owned(),
                },
                operation_id: UpdateOperationId::from_bytes([0x30; 16]),

                expected_version: version,
                expected_endpoint_identity: [0x51; 32],
                capability: [0x61; 32],
                master_key: [0x71; 32],
                bind_sockets: Vec::new(),
            };
            let mut candidate = CandidateProcess::spawn(&executable, &config).await.unwrap();

            // Simulate slow response acknowledgement and old-endpoint shutdown taking longer than
            // the candidate confirmation budget. That pre-cutover work must not consume the budget.
            tokio::time::sleep(Duration::from_millis(2_200)).await;
            confirm_attached_candidate(&mut candidate, version, Duration::from_secs(2))
                .await
                .unwrap();
            assert!(candidate.supervise().await.unwrap().success());
        })
        .await
        .expect("candidate confirmation scenario timed out");
    }

    #[tokio::test]
    async fn candidate_confirmation_waits_for_watchdog_commit() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let operation_id = UpdateOperationId::from_bytes([0x31; 16]);
            let candidate_version = AttachedVersion::new(0, 4, 0);
            let (events, mut received_events) = mpsc::unbounded_channel();
            let (disposition_tx, disposition) = watch::channel(CandidateDisposition::Pending);
            let candidate = Arc::new(CandidateConfirmation {
                operation_id,

                version: candidate_version,
                events,
                disposition,
                abort: CancellationToken::new(),
                announced_consumer: Arc::new(AtomicBool::new(false)),
            });
            let resources = Arc::new(UpdateResources {
                config: ServeConfig {
                    state_dir: PathBuf::from("/state"),

                    host_label: "office".to_owned(),
                },
                master_key: Arc::new(Zeroizing::new([0x41; 32])),
                endpoint_identity: [0x51; 32],
                bind_sockets: Vec::new(),
                capability: CapabilitySecret::from_bytes([0x61; 32]),
                update_limit: Arc::new(Semaphore::new(1)),
                active_operation: Arc::new(Mutex::new(None)),
                candidate: Some(candidate),
                rollback: None,
            });
            let confirmation = tokio::spawn(async move {
                candidate_confirmation_response(&resources, operation_id, candidate_version).await
            });

            assert_eq!(
                received_events.recv().await.unwrap(),
                CandidateEvent::ConsumerConnected
            );
            assert!(!confirmation.is_finished());
            disposition_tx.send_replace(CandidateDisposition::Committed);
            let (response, completion) = confirmation.await.unwrap();
            assert_eq!(
                response,
                AttachedUpdateResponse::Committed(candidate_version)
            );
            completion
                .unwrap()
                .send(CandidateEvent::ClientSucceeded)
                .unwrap();
            assert_eq!(
                received_events.recv().await.unwrap(),
                CandidateEvent::ClientSucceeded
            );
        })
        .await
        .expect("candidate confirmation scenario timed out");
    }

    #[tokio::test]
    async fn rolled_back_operation_returns_a_terminal_failure() {
        let operation_id = UpdateOperationId::from_bytes([0x32; 16]);
        let resources = UpdateResources {
            config: ServeConfig {
                state_dir: PathBuf::from("/state"),

                host_label: "office".to_owned(),
            },
            master_key: Arc::new(Zeroizing::new([0x41; 32])),
            endpoint_identity: [0x51; 32],
            bind_sockets: Vec::new(),
            capability: CapabilitySecret::from_bytes([0x61; 32]),
            update_limit: Arc::new(Semaphore::new(1)),
            active_operation: Arc::new(Mutex::new(None)),
            candidate: None,
            rollback: Some(RollbackRecord {
                operation_id,
                reason: "previous server restored".to_owned(),
            }),
        };

        let (response, completion) = candidate_confirmation_response(
            &resources,
            operation_id,
            AttachedVersion::new(0, 4, 0),
        )
        .await;
        assert_eq!(
            response,
            AttachedUpdateResponse::Failed("previous server restored".to_owned())
        );
        assert!(completion.is_none());
    }

    #[tokio::test]
    async fn accepted_updater_work_remains_owned_during_shutdown() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let task_completed = completed.clone();
            let mut connections = JoinSet::new();
            connections.spawn(async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                task_completed.store(true, Ordering::SeqCst);
                Ok(())
            });

            shutdown_connections(&mut connections).await;
            assert!(completed.load(Ordering::SeqCst));
        })
        .await
        .expect("shutdown ownership scenario timed out");
    }
}
