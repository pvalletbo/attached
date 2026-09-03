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
    CapabilitySecret, HerdrVersion, TUNNEL_ALPN, UPGRADE_ALPN, UpdateOperationId, UpgradeResponse,
    read_attached_update_request, read_upgrade_request, write_attached_update_response,
    write_upgrade_response,
};
use iroh::{
    Endpoint,
    endpoint::{AfterHandshakeOutcome, BindOpts, EndpointHooks, presets},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
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
    herdr_version, identity, installation, local_encryption,
    serve_handoff::{
        ActivatedCandidateIpc, CandidateConfig, CandidateDisposition, CandidateEvent, CandidateIpc,
        CandidateProcess, ParentCommand, ServeConfig,
    },
    session::{self, Session},
    sync::{publisher, state},
    tunnel,
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
    herdr_version: HerdrVersion,
    update_limit: Arc<Semaphore>,
    active_operation: Arc<Mutex<Option<UpdateOperationId>>>,
}

#[derive(Clone)]
struct CandidateConfirmation {
    operation_id: UpdateOperationId,
    session: String,
    version: AttachedVersion,
    events: mpsc::UnboundedSender<CandidateEvent>,
    disposition: watch::Receiver<CandidateDisposition>,
    abort: CancellationToken,
    announced_consumer: Arc<AtomicBool>,
}

impl CandidateConfirmation {
    fn new(
        operation_id: UpdateOperationId,
        session: String,
        version: AttachedVersion,
        ipc: ActivatedCandidateIpc,
    ) -> Self {
        Self {
            operation_id,
            session,
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
    confirmation_deadline: Instant,
    update: Option<installation::PreparedRemoteUpdate>,
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

pub async fn serve(
    state_dir: PathBuf,
    herdr_bin: PathBuf,
    host_label: Option<String>,
) -> Result<()> {
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
    let initial_version =
        herdr_version::query(&herdr_bin).context("could not determine the local Herdr version")?;
    installation::current_attached_executable()?;
    let endpoint = bind_server_endpoint(&key, authorized_consumer_identity, None).await?;
    let host_label = host_label.unwrap_or_else(|| publisher::default_host_label(&endpoint.addr()));
    let runtime = ServerRuntime {
        config: ServeConfig {
            state_dir,
            herdr_bin,
            host_label,
        },
        authorized_consumer_identity,
        key,
        capability: CapabilitySecret::generate(),
        master_key,
        herdr_version: initial_version,
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
    let herdr_version = herdr_version::query(&config.serve.herdr_bin)
        .context("candidate could not determine the local Herdr version")?;
    let attached_executable = installation::current_attached_executable()?;
    ensure!(
        attached_version::query(&attached_executable)? == current_version,
        "candidate executable version changed during preflight"
    );
    publisher::Publisher::load(&config.serve.state_dir, config.expected_endpoint_identity)
        .context("candidate could not initialize the session publisher")?;
    ipc.send(CandidateEvent::Prepared {
        version: current_version,
    })?;
    let operation_id = config.operation_id;
    let operation_session = config.session.clone();
    let bind_sockets = config.bind_sockets.clone();
    let capability = CapabilitySecret::from_bytes(config.capability);
    let serve_config = config.serve.clone();
    let master_key = Zeroizing::new(config.master_key);
    drop(config);
    let activated = ipc.activate().await?;
    let confirmation = Arc::new(CandidateConfirmation::new(
        operation_id,
        operation_session,
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
        herdr_version,
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

async fn bind_server_endpoint(
    key: &iroh::SecretKey,
    authorized_consumer_identity: AuthorizedConsumerIdentity,
    bind_sockets: Option<&[SocketAddr]>,
) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(key.clone())
        .alpns(vec![
            TUNNEL_ALPN.to_vec(),
            UPGRADE_ALPN.to_vec(),
            ATTACHED_UPDATE_ALPN.to_vec(),
        ])
        .hooks(ConsumerIdentityAuthorization::new(
            authorized_consumer_identity,
        ));
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
    mut runtime: ServerRuntime,
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
        session::ensure_active(registry_dir.clone(), runtime.config.herdr_bin.clone())
            .await
            .context("could not ensure an active Herdr session before serving")?;
        match herdr_version::query_running_sessions(&runtime.config.herdr_bin) {
            Ok(running_version) => runtime.herdr_version = running_version,
            Err(_) => warn!(
                "could not verify running Herdr server versions; publishing the installed binary version"
            ),
        }
        let (version, published_versions) = watch::channel(runtime.herdr_version);
        let publication = Arc::new(Mutex::new(
            publisher::Publisher::load(&runtime.config.state_dir, endpoint_identity)
                .context("could not initialize the session publisher")?,
        ));
        publish_sessions(
            &publication,
            &runtime.config.herdr_bin,
            &runtime.config.host_label,
            &endpoint,
            &runtime.capability,
            runtime.herdr_version,
        )
        .await
        .context("could not publish the initial session catalog")?;
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
                "Serving synchronized Herdr sessions as `{}`.",
                runtime.config.host_label
            );
            announced = true;
        }
        let publisher_task = tokio::spawn(run_publisher(
            publication,
            runtime.config.herdr_bin.clone(),
            runtime.config.host_label.clone(),
            endpoint.clone(),
            runtime.capability.clone(),
            published_versions,
        ));
        let outcome = serve_endpoint(
            &endpoint,
            runtime.config.herdr_bin.clone(),
            runtime.capability.clone(),
            version.clone(),
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
        runtime.herdr_version = *version.borrow();
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
    let deadline = handoff.confirmation_deadline;
    let precommit = async {
        handoff.candidate.send(&ParentCommand::Activate).await?;
        match timeout_at(deadline, handoff.candidate.next_event())
            .await
            .context("updated Attached candidate readiness timed out")??
        {
            CandidateEvent::Ready { version } if version == handoff.version => {}
            CandidateEvent::Failed { reason } => {
                bail!("updated Attached candidate failed: {reason}")
            }
            event => bail!("updated Attached candidate sent unexpected readiness event {event:?}"),
        }
        match timeout_at(deadline, handoff.candidate.next_event())
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
        handoff.candidate.send(&ParentCommand::Commit).await
    }
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
            .take()
            .context("Attached update rollback binary is unavailable")?
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
    if let Err(error) = handoff
        .update
        .take()
        .context("Attached update commit binary is unavailable")?
        .commit()
    {
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

fn new_operation_id() -> Result<UpdateOperationId> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .context("operating-system randomness is unavailable for the update operation")?;
    Ok(UpdateOperationId::from_bytes(bytes))
}

fn bounded_public_error(_error: &anyhow::Error) -> String {
    "updated Attached candidate failed".to_owned()
}

async fn run_publish_loop<Publish, PublishFuture>(
    mut version: watch::Receiver<HerdrVersion>,
    interval: Duration,
    mut publish: Publish,
) where
    Publish: FnMut(HerdrVersion) -> PublishFuture,
    PublishFuture: std::future::Future<Output = Result<()>>,
{
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            changed = version.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        let published_version = *version.borrow_and_update();
        if let Err(error) = publish(published_version).await {
            warn!(error = %error, "session catalog publication failed");
        }
    }
}

async fn run_publisher(
    publication: Arc<Mutex<publisher::Publisher>>,
    herdr_bin: PathBuf,
    host_label: String,
    endpoint: Endpoint,
    capability: CapabilitySecret,
    version: watch::Receiver<HerdrVersion>,
) {
    run_publish_loop(version, PUBLISH_INTERVAL, move |published_version| {
        let publication = publication.clone();
        let herdr_bin = herdr_bin.clone();
        let host_label = host_label.clone();
        let endpoint = endpoint.clone();
        let capability = capability.clone();
        async move {
            publish_sessions(
                &publication,
                &herdr_bin,
                &host_label,
                &endpoint,
                &capability,
                published_version,
            )
            .await
        }
    })
    .await;
}

async fn publish_sessions(
    publication: &Arc<Mutex<publisher::Publisher>>,
    herdr_bin: &std::path::Path,
    host_label: &str,
    endpoint: &Endpoint,
    capability: &CapabilitySecret,
    version: HerdrVersion,
) -> Result<()> {
    let sessions = session::discover_active(herdr_bin.to_owned()).await?;
    let names = sessions
        .into_iter()
        .map(|session| session.name().to_owned())
        .collect();
    match publication
        .lock()
        .await
        .publish_snapshot(host_label, endpoint.addr(), capability, version, names)
        .await?
    {
        publisher::PublishOutcome::Unchanged => {}
        publisher::PublishOutcome::Published { revision } => {
            info!(revision, "published encrypted session catalog");
        }
    }
    Ok(())
}

async fn resolve_session(herdr_bin: PathBuf, name: String) -> Result<Session> {
    let sessions = session::discover_active(herdr_bin).await?;
    let session = sessions
        .into_iter()
        .find(|session| session.name() == name)
        .with_context(|| format!("Herdr session `{name}` is not running"))?;
    session.validate()?;
    Ok(session)
}

fn perform_upgrade(
    herdr_bin: &std::path::Path,
    session: &str,
    requested_version: HerdrVersion,
    version: &watch::Sender<HerdrVersion>,
    updater: Arc<Semaphore>,
) -> UpgradeResponse {
    perform_upgrade_with(
        herdr_bin,
        session,
        requested_version,
        version,
        updater,
        herdr_version::update_session,
    )
}

fn perform_upgrade_with<Update>(
    herdr_bin: &std::path::Path,
    session: &str,
    requested_version: HerdrVersion,
    version: &watch::Sender<HerdrVersion>,
    updater: Arc<Semaphore>,
    update: Update,
) -> UpgradeResponse
where
    Update: FnOnce(&std::path::Path, &str, HerdrVersion) -> Result<HerdrVersion>,
{
    let current = *version.borrow();
    if (
        requested_version.major(),
        requested_version.minor(),
        requested_version.patch(),
    ) < (current.major(), current.minor(), current.patch())
    {
        return UpgradeResponse::Failed(
            "remote Herdr is newer than the requested version".to_owned(),
        );
    }
    if let Ok(installed) = herdr_version::query(herdr_bin)
        && (installed.major(), installed.minor(), installed.patch())
            > (
                requested_version.major(),
                requested_version.minor(),
                requested_version.patch(),
            )
    {
        if let Ok(running) = herdr_version::query_running_sessions(herdr_bin) {
            version.send_replace(running);
        }
        return UpgradeResponse::Failed(
            "remote Herdr is newer than the requested version".to_owned(),
        );
    }
    let Ok(_permit) = updater.try_acquire_owned() else {
        return UpgradeResponse::Busy;
    };
    match update(herdr_bin, session, requested_version) {
        Ok(installed) => {
            version.send_replace(installed);
            UpgradeResponse::Updated(installed)
        }
        Err(error) if herdr_version::is_rolled_back(&error) => {
            UpgradeResponse::Failed("remote Herdr update failed and was rolled back".to_owned())
        }
        Err(error) if herdr_version::is_package_managed(&error) => UpgradeResponse::Failed(
            "remote Herdr is package-managed; update it on the serving host".to_owned(),
        ),
        Err(_error) => {
            if let Ok(running) = herdr_version::query_running_sessions(herdr_bin) {
                version.send_replace(running);
            }
            UpgradeResponse::Failed(
                "remote Herdr update or live-handoff verification failed".to_owned(),
            )
        }
    }
}

async fn process_upgrade_stream<R, W, Resolve, ResolveFuture, Update>(
    receive: &mut R,
    send: &mut W,
    capability: &CapabilitySecret,
    framing_timeout: Duration,
    resolve: Resolve,
    update: Update,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Resolve: FnOnce(String) -> ResolveFuture,
    ResolveFuture: std::future::Future<Output = Result<()>>,
    Update: FnOnce(String, HerdrVersion) -> UpgradeResponse,
{
    let request = timeout(framing_timeout, read_upgrade_request(receive, capability))
        .await
        .context("upgrade request frame timed out")??;
    // Authentication is complete before session resolution or update execution.
    resolve(request.session.clone()).await?;
    timeout(
        framing_timeout,
        write_upgrade_response(send, update(request.session, request.requested_version)),
    )
    .await
    .context("upgrade response frame timed out")?
}

async fn serve_upgrade_connection(
    connection: iroh::endpoint::Connection,
    capability: &CapabilitySecret,
    herdr_bin: PathBuf,
    version: watch::Sender<HerdrVersion>,
    updater: Arc<Semaphore>,
) -> Result<()> {
    let (mut send, mut receive) = timeout(AUTHENTICATION_TIMEOUT, connection.accept_bi())
        .await
        .context("upgrade request handshake timed out")??;
    process_upgrade_stream(
        &mut receive,
        &mut send,
        capability,
        AUTHENTICATION_TIMEOUT,
        |session| async {
            resolve_session(herdr_bin.clone(), session)
                .await
                .map(|_| ())
        },
        |session, requested_version| {
            tokio::task::block_in_place(|| {
                perform_upgrade(&herdr_bin, &session, requested_version, &version, updater)
            })
        },
    )
    .await
}

async fn prepare_attached_handoff(
    resources: &UpdateResources,
    session: String,
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
        session,
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
        confirmation_deadline: Instant::now() + CANDIDATE_CONFIRM_TIMEOUT,
        update: Some(update),
        candidate,
        _permit: permit,
    })))
}

async fn abort_prepared_handoff(mut handoff: PreparedHandoff) -> Result<()> {
    handoff.candidate.abort().await;
    handoff
        .update
        .take()
        .context("Attached update rollback binary is unavailable")?
        .rollback()
}

async fn candidate_confirmation_response(
    resources: &UpdateResources,
    session: &str,
    operation_id: UpdateOperationId,
    observed_version: AttachedVersion,
) -> (
    AttachedUpdateResponse,
    Option<mpsc::UnboundedSender<CandidateEvent>>,
) {
    if let Some(candidate) = &resources.candidate
        && candidate.operation_id == operation_id
    {
        if candidate.session != session {
            return (
                AttachedUpdateResponse::Failed(
                    "Attached update confirmation selected a different session".to_owned(),
                ),
                None,
            );
        }
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
        AttachedUpdateRequest::Start { session } => {
            resolve_session(resources.config.herdr_bin.clone(), session.clone())
                .await
                .context("requested update session is unavailable")?;
            if resources
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.is_pending())
            {
                write_attached_update_response(&mut send, AttachedUpdateResponse::Busy).await?;
                return Ok(());
            }
            let permit = match resources.update_limit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    write_attached_update_response(&mut send, AttachedUpdateResponse::Busy).await?;
                    return Ok(());
                }
            };
            let operation_id = new_operation_id()?;
            *resources.active_operation.lock().await = Some(operation_id);
            let prepared =
                prepare_attached_handoff(&resources, session, operation_id, permit).await;
            let prepared = match prepared {
                Ok(PreparedAttachedUpdate::Current(version)) => {
                    *resources.active_operation.lock().await = None;
                    write_attached_update_response(
                        &mut send,
                        AttachedUpdateResponse::Current(version),
                    )
                    .await?;
                    return Ok(());
                }
                Ok(PreparedAttachedUpdate::Handoff(prepared)) => *prepared,
                Err(_error) => {
                    *resources.active_operation.lock().await = None;
                    let _ = write_attached_update_response(
                        &mut send,
                        AttachedUpdateResponse::Failed(
                            "remote Attached update could not be prepared".to_owned(),
                        ),
                    )
                    .await;
                    bail!("remote Attached update preparation failed");
                }
            };
            if let Err(error) = write_attached_update_response(
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
            if let Err(error) = timeout(AUTHENTICATION_TIMEOUT, send.stopped())
                .await
                .context("client did not acknowledge the Attached update handoff")
                .and_then(|result| result.map(|_| ()).map_err(Into::into))
            {
                *resources.active_operation.lock().await = None;
                abort_prepared_handoff(prepared).await?;
                return Err(error);
            }
            if let Err(error) = handoff_tx.send(prepared).await {
                *resources.active_operation.lock().await = None;
                abort_prepared_handoff(error.0).await?;
                bail!("Attached server stopped before the prepared handoff");
            }
            Ok(())
        }
        AttachedUpdateRequest::Confirm {
            session,
            operation_id,
            observed_version,
        } => {
            let (response, succeeded) = candidate_confirmation_response(
                &resources,
                &session,
                operation_id,
                observed_version,
            )
            .await;
            write_attached_update_response(&mut send, response).await?;
            if let Some(events) = succeeded {
                timeout(AUTHENTICATION_TIMEOUT, send.stopped())
                    .await
                    .context("client did not acknowledge the committed Attached update")??;
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
    herdr_bin: PathBuf,
    capability: CapabilitySecret,
    version: watch::Sender<HerdrVersion>,
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
                let herdr_bin = herdr_bin.clone();
                let capability = capability.clone();
                let authenticated = authenticated.clone();
                let updater = update_resources.update_limit.clone();
                let version = version.clone();
                let child_cancellation = cancellation.child_token();
                let update_resources = update_resources.clone();
                let handoff_tx = handoff_tx.clone();
                connections.spawn(async move {
                    let result = async {
                        let connection = timeout(AUTHENTICATION_TIMEOUT, incoming)
                            .await
                            .context("Iroh connection handshake timed out")??;
                        if connection.alpn() == ATTACHED_UPDATE_ALPN {
                            drop(pending_permit);
                            return serve_attached_update_connection(
                                connection,
                                update_resources,
                                handoff_tx,
                            )
                            .await;
                        }
                        if connection.alpn() == UPGRADE_ALPN {
                            return serve_upgrade_connection(
                                connection,
                                &capability,
                                herdr_bin,
                                version,
                                updater,
                            )
                            .await;
                        }
                        if connection.alpn() != TUNNEL_ALPN {
                            bail!("unsupported tunnel protocol");
                        }
                        let advertised_version = *version.borrow();
                        tunnel::serve_connection(
                            connection,
                            connection_id,
                            &capability,
                            advertised_version,
                            child_cancellation,
                            move |name| resolve_session(herdr_bin, name),
                            move || {
                                drop(pending_permit);
                                authenticated
                                    .try_acquire_owned()
                                    .context("authenticated connection capacity is exhausted")
                            },
                        )
                        .await
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
mod tests {
    use super::*;
    use attached_session_sync_protocol::account::ConsumerIdentitySecret;
    use attached_tunnel_protocol::{
        authenticate_server, read_auth_response, read_upgrade_response, write_auth_request,
        write_upgrade_request,
    };
    use iroh::{RelayMode, endpoint::BindOpts};
    use std::{
        fs,
        net::Ipv4Addr,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    fn fake_herdr(root: &std::path::Path, version: &str) -> PathBuf {
        let path = root.join("herdr");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = update ]; then printf updated > '{}/updated'; exit 0; fi\nif [ \"$1\" = --version ]; then printf 'herdr {}\\n'; exit 0; fi\nif [ \"$1\" = session ] && [ \"$2\" = list ]; then printf '{{\"sessions\":[{{\"name\":\"work\",\"running\":true}}]}}\\n'; exit 0; fi\nif [ \"$1\" = --session ] && [ \"$3\" = status ]; then printf '{{\"running\":true,\"version\":\"{}\"}}\\n'; exit 0; fi\nexit 9\n",
                root.display(), version, version
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

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
    async fn live_quic_enforces_identity_before_capability_and_session_authentication() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let consumer_identity_secret = ConsumerIdentitySecret::from_bytes([0x5a; 32]);
            let authorized_identity = consumer_identity_secret.authorized_identity();
            let authorized_key = iroh::SecretKey::from_bytes(consumer_identity_secret.as_bytes());
            assert_eq!(
                authorized_key.public().as_bytes(),
                authorized_identity.as_bytes(),
                "account and Iroh identity derivation must remain byte-exact",
            );
            let unauthorized_key = iroh::SecretKey::generate();
            let capability = CapabilitySecret::from_bytes([0x51; 32]);
            let wrong_capability = CapabilitySecret::from_bytes([0x52; 32]);
            let server = Endpoint::builder(presets::N0)
                .clear_ip_transports()
                .bind_addr_with_opts(
                    (Ipv4Addr::LOCALHOST, 0),
                    BindOpts::default().set_prefix_len(8),
                )
                .unwrap()
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
                .alpns(vec![TUNNEL_ALPN.to_vec()])
                .hooks(ConsumerIdentityAuthorization::new(authorized_identity))
                .bind()
                .await
                .unwrap();
            let server_addr = server.addr();
            let server_endpoint = server.clone();
            let server_capability = capability.clone();
            let capability_attempts = Arc::new(AtomicUsize::new(0));
            let session_resolutions = Arc::new(AtomicUsize::new(0));
            let server_attempts = capability_attempts.clone();
            let server_resolutions = session_resolutions.clone();
            let (processed, mut events) = tokio::sync::mpsc::unbounded_channel();

            let server_task = tokio::spawn(async move {
                for _ in 0..3 {
                    let incoming = server_endpoint.accept().await.unwrap();
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(error) => {
                            assert!(
                                error.to_string().contains("rejected locally"),
                                "unexpected handshake error: {error}"
                            );
                            processed.send("identity_rejected").unwrap();
                            continue;
                        }
                    };

                    server_attempts.fetch_add(1, Ordering::SeqCst);
                    let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                    let resolutions = server_resolutions.clone();
                    let result = authenticate_server(
                        &mut receive,
                        &mut send,
                        &server_capability,
                        HerdrVersion::new(0, 7, 5),
                        move |session| async move {
                            resolutions.fetch_add(1, Ordering::SeqCst);
                            anyhow::ensure!(session == "work", "unexpected session");
                            Ok(())
                        },
                        || Ok(()),
                    )
                    .await;

                    processed
                        .send(if result.is_ok() {
                            "authorized"
                        } else {
                            "capability_rejected"
                        })
                        .unwrap();
                    let _ = send.stopped().await;
                    drop(connection);
                }
            });

            let unauthorized = Endpoint::builder(presets::N0)
                .secret_key(unauthorized_key)
                .clear_ip_transports()
                .bind_addr_with_opts(
                    (Ipv4Addr::LOCALHOST, 0),
                    BindOpts::default().set_prefix_len(8),
                )
                .unwrap()
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
                .bind()
                .await
                .unwrap();
            let unauthorized_connection =
                unauthorized.connect(server_addr.clone(), TUNNEL_ALPN).await;
            assert_eq!(events.recv().await.unwrap(), "identity_rejected");
            assert_eq!(capability_attempts.load(Ordering::SeqCst), 0);
            assert_eq!(session_resolutions.load(Ordering::SeqCst), 0);
            drop(unauthorized_connection);
            unauthorized.close().await;

            async fn authenticate(
                key: iroh::SecretKey,
                address: iroh::EndpointAddr,
                capability: &CapabilitySecret,
            ) -> (Endpoint, anyhow::Result<()>) {
                let endpoint = Endpoint::builder(presets::N0)
                    .secret_key(key)
                    .clear_ip_transports()
                    .bind_addr_with_opts(
                        (Ipv4Addr::LOCALHOST, 0),
                        BindOpts::default().set_prefix_len(8),
                    )
                    .unwrap()
                    .relay_mode(RelayMode::Disabled)
                    .clear_address_lookup()
                    .bind()
                    .await
                    .unwrap();
                let connection = endpoint.connect(address, TUNNEL_ALPN).await.unwrap();

                let (mut send, mut receive) = connection.open_bi().await.unwrap();
                let result = async {
                    write_auth_request(&mut send, "work", capability, None).await?;

                    read_auth_response(&mut receive, None).await
                }
                .await;
                (endpoint, result)
            }

            let (authorized, result) =
                authenticate(authorized_key.clone(), server_addr.clone(), &capability).await;
            result.unwrap();
            assert_eq!(events.recv().await.unwrap(), "authorized");
            assert_eq!(capability_attempts.load(Ordering::SeqCst), 1);
            assert_eq!(session_resolutions.load(Ordering::SeqCst), 1);
            authorized.close().await;

            let (wrong, result) =
                authenticate(authorized_key, server_addr, &wrong_capability).await;
            assert!(result.is_err());
            assert_eq!(events.recv().await.unwrap(), "capability_rejected");
            assert_eq!(capability_attempts.load(Ordering::SeqCst), 2);
            assert_eq!(session_resolutions.load(Ordering::SeqCst), 1);
            wrong.close().await;

            server_task.await.unwrap();
            server.close().await;
        })
        .await
        .expect("live Iroh identity authorization scenario timed out");
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

    #[test]
    fn successful_update_command_refreshes_in_memory_and_published_version() {
        let root = tempfile::tempdir().unwrap();
        let executable = fake_herdr(root.path(), "1.2.3");
        let (advertised, mut published) = watch::channel(HerdrVersion::new(1, 2, 2));
        assert_eq!(
            perform_upgrade(
                &executable,
                "work",
                HerdrVersion::new(1, 2, 3),
                &advertised,
                Arc::new(Semaphore::new(1)),
            ),
            UpgradeResponse::Updated(HerdrVersion::new(1, 2, 3))
        );
        assert_eq!(*advertised.borrow(), HerdrVersion::new(1, 2, 3));
        assert!(published.has_changed().unwrap());
        assert_eq!(*published.borrow_and_update(), HerdrVersion::new(1, 2, 3));

        assert!(
            !root.path().join("updated").exists(),
            "a current binary and live session reran the updater"
        );
        assert_eq!(
            perform_upgrade(
                &executable,
                "work",
                HerdrVersion::new(1, 2, 3),
                &advertised,
                Arc::new(Semaphore::new(1)),
            ),
            UpgradeResponse::Updated(HerdrVersion::new(1, 2, 3))
        );
        assert!(
            !root.path().join("updated").exists(),
            "an already-current live session reran the updater"
        );

        let mismatched = fake_herdr(root.path(), "1.2.4");
        let (advertised, mut published) = watch::channel(HerdrVersion::new(1, 2, 2));
        let response = perform_upgrade(
            &mismatched,
            "work",
            HerdrVersion::new(1, 2, 3),
            &advertised,
            Arc::new(Semaphore::new(1)),
        );
        assert_eq!(
            response,
            UpgradeResponse::Failed("remote Herdr is newer than the requested version".to_owned())
        );
        assert_eq!(*advertised.borrow(), HerdrVersion::new(1, 2, 4));
        assert!(published.has_changed().unwrap());
        assert_eq!(*published.borrow_and_update(), HerdrVersion::new(1, 2, 4));
    }

    #[test]
    fn newer_requested_or_running_versions_never_execute_remote_update() {
        for requested in [HerdrVersion::new(1, 2, 3), HerdrVersion::new(1, 2, 2)] {
            let root = tempfile::tempdir().unwrap();
            let executable = fake_herdr(root.path(), "9.9.9");
            let (advertised, _) = watch::channel(HerdrVersion::new(1, 2, 3));

            assert_eq!(
                perform_upgrade(
                    &executable,
                    "work",
                    requested,
                    &advertised,
                    Arc::new(Semaphore::new(1)),
                ),
                UpgradeResponse::Failed(
                    "remote Herdr is newer than the requested version".to_owned()
                )
            );
            assert!(
                !root.path().join("updated").exists(),
                "server executed the updater for requested {requested}"
            );
            let expected_advertised = if requested == HerdrVersion::new(1, 2, 3) {
                HerdrVersion::new(9, 9, 9)
            } else {
                HerdrVersion::new(1, 2, 3)
            };
            assert_eq!(*advertised.borrow(), expected_advertised);
        }
    }

    #[test]
    fn concurrent_upgrade_is_rejected_before_command_execution() {
        let root = tempfile::tempdir().unwrap();
        let executable = fake_herdr(root.path(), "1.2.3");
        let updater = Arc::new(Semaphore::new(1));
        let _held = updater.clone().try_acquire_owned().unwrap();
        let (advertised, _) = watch::channel(HerdrVersion::new(1, 2, 2));
        assert_eq!(
            perform_upgrade(
                &executable,
                "work",
                HerdrVersion::new(1, 2, 3),
                &advertised,
                updater,
            ),
            UpgradeResponse::Busy
        );
        assert!(!root.path().join("updated").exists());
    }

    #[test]
    fn updater_child_diagnostics_are_never_exposed_on_the_wire() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("secret-herdr");
        let secret = "TOKEN=wire-secret https://user:pass@example.test /srv/private/herdr";
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nif [ \"$1\" = update ]; then printf '%s' '{secret}' >&2; exit 7; fi\nif [ \"$1\" = --version ]; then printf 'herdr 1.2.2\\n'; exit 0; fi\nif [ \"$1\" = session ] && [ \"$2\" = list ]; then printf '{{\"sessions\":[{{\"name\":\"work\",\"running\":true}}]}}\\n'; exit 0; fi\nif [ \"$1\" = --session ] && [ \"$3\" = status ]; then printf '{{\"running\":true,\"version\":\"1.2.2\"}}\\n'; exit 0; fi\nexit 9\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let (advertised, _) = watch::channel(HerdrVersion::new(1, 2, 2));

        let response = perform_upgrade_with(
            &executable,
            "work",
            HerdrVersion::new(1, 2, 3),
            &advertised,
            Arc::new(Semaphore::new(1)),
            |executable, session, requested| {
                herdr_version::update_session_with_config(executable, session, requested, None)
            },
        );
        assert_eq!(
            response,
            UpgradeResponse::Failed("remote Herdr update failed and was rolled back".to_owned())
        );
        let wire = format!("{response:?}");
        assert!(!wire.contains("wire-secret"), "{wire}");
        assert!(!wire.contains("example.test"), "{wire}");
        assert!(!wire.contains("/srv/private"), "{wire}");
        assert!(!wire.contains("secret-herdr"), "{wire}");
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
                session: "work".to_owned(),
                version: candidate_version,
                events,
                disposition,
                abort: CancellationToken::new(),
                announced_consumer: Arc::new(AtomicBool::new(false)),
            });
            let resources = Arc::new(UpdateResources {
                config: ServeConfig {
                    state_dir: PathBuf::from("/state"),
                    herdr_bin: PathBuf::from("herdr"),
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
                candidate_confirmation_response(&resources, "work", operation_id, candidate_version)
                    .await
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
                herdr_bin: PathBuf::from("herdr"),
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
            "work",
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
    async fn changed_version_invokes_publisher_and_periodic_retry() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let (version, receiver) = watch::channel(HerdrVersion::new(1, 2, 2));
            let (published, mut publications) = tokio::sync::mpsc::unbounded_channel();
            let publisher = tokio::spawn(run_publish_loop(
                receiver,
                Duration::from_millis(30),
                move |observed| {
                    let published = published.clone();
                    async move {
                        published.send(observed).unwrap();
                        Ok(())
                    }
                },
            ));

            version.send_replace(HerdrVersion::new(1, 2, 3));
            assert_eq!(
                publications.recv().await.unwrap(),
                HerdrVersion::new(1, 2, 3)
            );
            assert_eq!(
                publications.recv().await.unwrap(),
                HerdrVersion::new(1, 2, 3),
                "periodic publication retry was not retained"
            );
            publisher.abort();
            let _ = publisher.await;
        })
        .await
        .expect("publisher action scenario timed out");
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

    #[tokio::test]
    async fn invalid_capability_never_resolves_session_or_executes_update() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let expected = CapabilitySecret::from_bytes([1; 32]);
            let supplied = CapabilitySecret::from_bytes([2; 32]);
            let calls = Arc::new(AtomicUsize::new(0));
            let (client, server) = tokio::io::duplex(512);
            let (_client_receive, mut client_send) = tokio::io::split(client);
            let (mut server_receive, mut server_send) = tokio::io::split(server);
            let server_calls = calls.clone();

            let client = write_upgrade_request(
                &mut client_send,
                "work",
                &supplied,
                HerdrVersion::new(1, 2, 3),
            );
            let server = process_upgrade_stream(
                &mut server_receive,
                &mut server_send,
                &expected,
                Duration::from_secs(1),
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                },
                |_, _| {
                    server_calls.fetch_add(1, Ordering::SeqCst);
                    UpgradeResponse::Busy
                },
            );
            let (client_result, server_result) = tokio::join!(client, server);
            client_result.unwrap();
            assert!(server_result.unwrap_err().to_string().contains("denied"));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        })
        .await
        .expect("invalid-capability duplex scenario timed out");
    }

    #[tokio::test]
    async fn authenticated_upgrade_stream_binds_session_and_requested_version() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let capability = CapabilitySecret::from_bytes([3; 32]);
            let (client, server) = tokio::io::duplex(512);
            let (mut client_receive, mut client_send) = tokio::io::split(client);
            let (mut server_receive, mut server_send) = tokio::io::split(server);
            let requested = HerdrVersion::new(4, 5, 6);

            let client = async {
                write_upgrade_request(&mut client_send, "work", &capability, requested).await?;
                read_upgrade_response(&mut client_receive).await
            };
            let server = process_upgrade_stream(
                &mut server_receive,
                &mut server_send,
                &capability,
                Duration::from_secs(1),
                |session| async move {
                    anyhow::ensure!(session == "work", "wrong session");
                    Ok(())
                },
                |session, version| {
                    assert_eq!(session, "work");
                    assert_eq!(version, requested);
                    UpgradeResponse::Updated(version)
                },
            );
            let (response, ()) = tokio::try_join!(client, server).unwrap();
            assert_eq!(response, UpgradeResponse::Updated(requested));
        })
        .await
        .expect("authenticated duplex scenario timed out");
    }
}
