use std::{
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use attached_tunnel_protocol::{
    ATTACHED_UPDATE_ALPN, AttachedUpdateResponse, AttachedVersion, CapabilitySecret, TUNNEL_ALPN,
    UPGRADE_ALPN, UpdateOperationId, UpgradeResponse, authenticate_server,
    read_attached_update_response, read_auth_response, read_stream_header, read_upgrade_response,
    write_attached_update_confirm_request, write_attached_update_start_request, write_auth_request,
    write_stream_header, write_upgrade_request,
};
use iroh::{
    Endpoint,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use tokio::{
    net::{UnixListener, UnixStream},
    process::{Child, Command},
    sync::Semaphore,
    task::JoinSet,
    time::{sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    diagnostics::{TerminalOutputGuard, log_stream_closed, next_connection_id, next_stream_id},
    herdr_version::HerdrVersion,
    local_sockets::SocketWorkspace,
    proxy::copy_until_cancelled,
    session::Session,
};

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(5);
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
// One failed Herdr handoff can consume its 240-second deadline and then require a verified
// rollback, so the requester must outlive both phases.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(900);
const ATTACHED_UPDATE_START_TIMEOUT: Duration = Duration::from_secs(150);
const ATTACHED_UPDATE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ATTACHED_RECONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const CHILD_EXIT_GRACE: Duration = Duration::from_secs(3);
const MAX_STREAMS_PER_CONNECTION: usize = 64;

#[derive(Debug)]
struct RemoteUnavailable(anyhow::Error);

impl std::fmt::Display for RemoteUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for RemoteUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

fn remote_unavailable(error: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(RemoteUnavailable(error))
}

pub(crate) fn is_remote_unavailable(error: &anyhow::Error) -> bool {
    error.downcast_ref::<RemoteUnavailable>().is_some()
}

pub(crate) async fn bind_client_endpoint(local_identity: &iroh::SecretKey) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(local_identity.clone())
        .bind()
        .await
        .context("could not bind persistent local Iroh identity")
}

pub async fn request_upgrade(
    endpoint_addr: iroh::EndpointAddr,
    local_identity: &iroh::SecretKey,
    session: &str,
    capability: &CapabilitySecret,
    requested_version: HerdrVersion,
) -> Result<HerdrVersion> {
    let endpoint = bind_client_endpoint(local_identity)
        .await
        .context("could not initialize the local upgrade endpoint")?;
    let result = request_upgrade_on_endpoint(
        &endpoint,
        endpoint_addr,
        session,
        capability,
        requested_version,
    )
    .await;
    endpoint.close().await;
    result
}

async fn request_upgrade_on_endpoint(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    session: &str,
    capability: &CapabilitySecret,
    requested_version: HerdrVersion,
) -> Result<HerdrVersion> {
    let result = timeout(UPGRADE_TIMEOUT, async {
        let connection = endpoint.connect(endpoint_addr, UPGRADE_ALPN).await?;
        let (mut send, mut receive) = connection.open_bi().await?;
        write_upgrade_request(&mut send, session, capability, requested_version).await?;
        read_upgrade_response(&mut receive).await
    })
    .await
    .context("remote Herdr upgrade request timed out")
    .and_then(|result| result);
    finish_upgrade_response(finish_upgrade_result(result)?)
}

pub async fn request_attached_update(
    endpoint_addr: iroh::EndpointAddr,
    local_identity: &iroh::SecretKey,
    session: &str,
    capability: &CapabilitySecret,
) -> Result<AttachedVersion> {
    let endpoint = bind_client_endpoint(local_identity)
        .await
        .context("could not initialize the local Attached update endpoint")?;
    let result =
        request_attached_update_on_endpoint(&endpoint, endpoint_addr, session, capability).await;
    endpoint.close().await;
    result
}

async fn request_attached_update_on_endpoint(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    session: &str,
    capability: &CapabilitySecret,
) -> Result<AttachedVersion> {
    let initial = timeout(
        ATTACHED_UPDATE_START_TIMEOUT,
        exchange_attached_update_start(endpoint, endpoint_addr.clone(), session, capability),
    )
    .await
    .context("remote Attached update preparation timed out")??;
    match initial {
        AttachedUpdateResponse::Current(version) | AttachedUpdateResponse::Committed(version) => {
            Ok(version)
        }
        AttachedUpdateResponse::Restarting {
            operation_id,
            version,
            reconnect_timeout_secs,
        } => {
            let reconnect_timeout = Duration::from_secs(u64::from(reconnect_timeout_secs));
            ensure!(
                !reconnect_timeout.is_zero() && reconnect_timeout <= MAX_ATTACHED_RECONNECT_TIMEOUT,
                "remote Attached returned an invalid reconnect deadline"
            );
            eprintln!("Remote Attached {version} is prepared; waiting for the server to restart…");
            confirm_attached_candidate(
                endpoint,
                endpoint_addr,
                session,
                capability,
                operation_id,
                version,
                reconnect_timeout,
            )
            .await
        }
        AttachedUpdateResponse::Failed(message) => bail!("{message}"),
        AttachedUpdateResponse::Busy => {
            bail!("a remote Attached update is already in progress; retry later")
        }
        AttachedUpdateResponse::Waiting => {
            bail!("remote Attached returned an unexpected waiting response")
        }
    }
}

async fn exchange_attached_update_start(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    session: &str,
    capability: &CapabilitySecret,
) -> Result<AttachedUpdateResponse> {
    let connection = endpoint
        .connect(endpoint_addr, ATTACHED_UPDATE_ALPN)
        .await
        .context("could not connect to the remote Attached update service")?;
    let (mut send, mut receive) = connection.open_bi().await?;
    write_attached_update_start_request(&mut send, session, capability).await?;
    read_attached_update_response(&mut receive).await
}

async fn exchange_attached_update_confirm(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    session: &str,
    capability: &CapabilitySecret,
    operation_id: UpdateOperationId,
    version: AttachedVersion,
) -> Result<AttachedUpdateResponse> {
    let connection = endpoint
        .connect(endpoint_addr, ATTACHED_UPDATE_ALPN)
        .await?;
    let (mut send, mut receive) = connection.open_bi().await?;
    write_attached_update_confirm_request(&mut send, session, capability, operation_id, version)
        .await?;
    read_attached_update_response(&mut receive).await
}

async fn confirm_attached_candidate(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    session: &str,
    capability: &CapabilitySecret,
    operation_id: UpdateOperationId,
    version: AttachedVersion,
    reconnect_timeout: Duration,
) -> Result<AttachedVersion> {
    let deadline = tokio::time::Instant::now() + reconnect_timeout;
    let mut delay = Duration::from_millis(100);
    let mut last_error = None;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            let detail = last_error.map_or_else(
                || "the replacement server did not answer".to_owned(),
                |error: anyhow::Error| error.to_string(),
            );
            bail!("timed out confirming remote Attached {version} after restart: {detail}");
        }
        let attempt_deadline = (now + ATTACHED_UPDATE_ATTEMPT_TIMEOUT).min(deadline);
        match timeout_at(
            attempt_deadline,
            exchange_attached_update_confirm(
                endpoint,
                endpoint_addr.clone(),
                session,
                capability,
                operation_id,
                version,
            ),
        )
        .await
        {
            Ok(Ok(AttachedUpdateResponse::Committed(installed))) => {
                ensure!(
                    installed == version,
                    "replacement server reported Attached {installed}, expected {version}"
                );
                return Ok(installed);
            }
            Ok(Ok(AttachedUpdateResponse::Current(installed))) if installed == version => {
                return Ok(installed);
            }
            Ok(Ok(AttachedUpdateResponse::Failed(message))) => bail!("{message}"),
            Ok(Ok(AttachedUpdateResponse::Busy | AttachedUpdateResponse::Waiting)) => {}
            Ok(Ok(response)) => {
                last_error = Some(anyhow!("unexpected confirmation response {response:?}"));
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(error) => last_error = Some(error.into()),
        }
        sleep(delay.min(deadline.saturating_duration_since(tokio::time::Instant::now()))).await;
        delay = (delay * 2).min(Duration::from_secs(1));
    }
}

fn finish_upgrade_result<T>(result: Result<T>) -> Result<T> {
    result.map_err(remote_unavailable)
}

fn finish_upgrade_response(response: UpgradeResponse) -> Result<HerdrVersion> {
    match response {
        UpgradeResponse::Updated(installed) => Ok(installed),
        UpgradeResponse::Failed(message) => bail!("{message}"),
        UpgradeResponse::Busy => {
            bail!("remote Herdr update is already in progress; retry later")
        }
    }
}

/// Authenticates a synchronized host capability before resolving the requested
/// session or opening its interactive TUI socket.
pub(crate) async fn serve_connection<R, Fut, F, T>(
    connection: Connection,
    connection_id: u64,
    secret: &CapabilitySecret,
    herdr_version: HerdrVersion,
    cancellation: CancellationToken,
    resolve: R,
    admit: F,
) -> Result<()>
where
    R: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<Session>>,
    F: FnOnce() -> Result<T>,
{
    let authentication = async {
        let (mut send, mut receive) = connection
            .accept_bi()
            .await
            .context("client did not open an authentication stream")?;
        let result = authenticate_server(
            &mut receive,
            &mut send,
            secret,
            herdr_version,
            resolve,
            admit,
        )
        .await;
        if result.is_err() {
            let _ = timeout(Duration::from_secs(1), send.stopped()).await;
        }
        result
    };
    let (session, _admission) = timeout(AUTHENTICATION_TIMEOUT, authentication)
        .await
        .context("client authentication timed out")??;
    info!(
        connection_id,
        session = session.name(),
        phase = "authenticated",
        "host client authenticated"
    );
    serve_authenticated_connection(connection, connection_id, session, cancellation).await
}

async fn serve_authenticated_connection(
    connection: Connection,
    connection_id: u64,
    session: Session,
    cancellation: CancellationToken,
) -> Result<()> {
    let stream_limit = Arc::new(Semaphore::new(MAX_STREAMS_PER_CONNECTION));
    let mut streams = JoinSet::new();
    let result = loop {
        tokio::select! {
            () = cancellation.cancelled() => break Ok(()),
            accepted = connection.accept_bi() => {
                let (send, receive) = match accepted {
                    Ok(streams) => streams,
                    Err(error) => break Err(error).context("parent Iroh connection closed"),
                };
                let permit = match stream_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        drop(send);
                        drop(receive);
                        warn!(connection_id, category = "limit", "rejected stream: per-connection stream limit reached");
                        continue;
                    }
                };
                let stream_id = next_stream_id();
                let session = session.clone();
                let stream_cancellation = cancellation.child_token();
                streams.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_stream(send, receive, connection_id, stream_id, session, stream_cancellation).await {
                        warn!(connection_id, stream_id, category = "stream", error = %error, "Iroh stream closed");
                    }
                });
            }
            completed = streams.join_next(), if !streams.is_empty() => {
                if let Some(Err(error)) = completed {
                    error!(connection_id, category = "task", error = %error, "Iroh stream task failed");
                }
            }
        }
    };

    connection.close(0_u32.into(), b"connection closed");
    streams.abort_all();
    while streams.join_next().await.is_some() {}
    result
}

async fn serve_stream(
    send: SendStream,
    mut receive: RecvStream,
    connection_id: u64,
    stream_id: u64,
    session: Session,
    cancellation: CancellationToken,
) -> Result<()> {
    timeout(AUTHENTICATION_TIMEOUT, read_stream_header(&mut receive))
        .await
        .context("timed out reading interactive stream header")??;
    let started = Instant::now();
    debug!(
        connection_id,
        stream_id,
        session = session.name(),
        phase = "routing",
        "routing interactive tunnel stream"
    );
    let unix = connect_session_tui_socket(&session).await?;
    let (unix_reader, unix_writer) = unix.into_split();
    let stats = copy_until_cancelled(unix_reader, unix_writer, receive, send, cancellation)
        .await
        .context("stream proxy failed")?;
    log_stream_closed(
        connection_id,
        stream_id,
        Some(session.name()),
        stats.left_to_right,
        stats.right_to_left,
        started.elapsed().as_millis(),
        "clean_eof",
    );
    Ok(())
}

async fn connect_session_tui_socket(session: &Session) -> Result<UnixStream> {
    let socket_path = session.validated_tui_socket()?;
    UnixStream::connect(socket_path).await.with_context(|| {
        format!(
            "Herdr session `{}` socket {} is unavailable; the selected session may have stopped",
            session.name(),
            socket_path.display()
        )
    })
}

pub async fn connect(
    endpoint_addr: iroh::EndpointAddr,
    local_identity: &iroh::SecretKey,
    session: String,
    capability: CapabilitySecret,
    herdr_bin: PathBuf,
    local_herdr_version: HerdrVersion,
) -> Result<i32> {
    // Tracing writes directly to stderr, which corrupts Herdr's alternate-screen
    // rendering if Iroh emits a warning while the interactive child is active.
    // Preserve those diagnostics, but replay them only after Herdr restores the
    // caller's terminal.
    let _terminal_output = TerminalOutputGuard::for_interactive_client();
    let connection_id = next_connection_id();
    info!(
        connection_id,
        phase = "startup",
        session,
        "connecting to tunnel host"
    );
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let endpoint = setup_step(
        async {
            bind_client_endpoint(local_identity)
                .await
                .context("failed to bind local Iroh endpoint")
        },
        &mut ctrl_c,
        SETUP_TIMEOUT,
        "binding local Iroh endpoint",
    )
    .await?;
    let result = async {
        let connection = setup_remote_step(
            async {
                endpoint
                    .connect(endpoint_addr, TUNNEL_ALPN)
                    .await
                    .context("failed to connect to the Iroh endpoint")
            },
            &mut ctrl_c,
            SETUP_TIMEOUT,
            "connecting to Iroh endpoint",
        )
        .await?;
        info!(connection_id, peer_id = %connection.remote_id(), phase = "connected", "connected to Iroh endpoint");
        setup_remote_step(
            authenticate_client(
                &connection,
                &session,
                &capability,
                local_herdr_version,
            ),
            &mut ctrl_c,
            AUTHENTICATION_TIMEOUT,
            "authenticating with Iroh endpoint",
        )
        .await?;
        info!(
            connection_id,
            phase = "authenticated",
            session,
            "tunnel authentication succeeded"
        );

        let (workspace, tui_listener) = SocketWorkspace::create().await?;
        let mut child = spawn_herdr(&herdr_bin, workspace.tui_path())?;

        let cancellation = CancellationToken::new();
        let mut forwarders = spawn_forwarders(
            tui_listener,
            connection.clone(),
            cancellation.clone(),
            connection_id,
        );
        let result = supervise_connect_runtime(
            &mut child,
            &mut forwarders,
            cancellation.clone(),
            async { connection.closed().await.to_string() },
            &mut ctrl_c,
        )
        .await;

        cancellation.cancel();
        connection.close(0_u32.into(), b"client exiting");
        if timeout(CHILD_EXIT_GRACE, async {
            while forwarders.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            forwarders.abort_all();
            while forwarders.join_next().await.is_some() {}
            if result.is_ok() {
                bail!("timed out shutting down local proxy tasks");
            }
        }
        drop(workspace);
        result
    }
    .await;
    endpoint.close().await;
    result
}

async fn setup_remote_step<T, Operation, Shutdown, ShutdownError>(
    operation: Operation,
    shutdown: Shutdown,
    deadline: Duration,
    description: &'static str,
) -> Result<T>
where
    Operation: Future<Output = Result<T>>,
    Shutdown: Future<Output = std::result::Result<(), ShutdownError>>,
    ShutdownError: Into<anyhow::Error>,
{
    tokio::select! {
        result = timeout(deadline, operation) => {
            match result {
                Ok(result) => result.map_err(remote_unavailable),
                Err(error) => Err(remote_unavailable(
                    anyhow!(error).context(format!("timed out while {description}"))
                )),
            }
        }
        shutdown_result = shutdown => {
            shutdown_result.map_err(Into::into)?;
            bail!("interrupted while {description}")
        }
    }
}

async fn setup_step<T, Operation, Shutdown, ShutdownError>(
    operation: Operation,
    shutdown: Shutdown,
    deadline: Duration,
    action: &'static str,
) -> Result<T>
where
    Operation: std::future::Future<Output = Result<T>>,
    Shutdown: std::future::Future<Output = std::result::Result<(), ShutdownError>>,
    ShutdownError: Into<anyhow::Error>,
{
    tokio::select! {
        result = timeout(deadline, operation) => {
            result.with_context(|| format!("timed out while {action}"))?
        }
        shutdown_result = shutdown => {
            shutdown_result.map_err(Into::into)?;
            bail!("interrupted while {action}")
        }
    }
}

async fn supervise_connect_runtime<ConnectionClosed, Shutdown, ShutdownError>(
    child: &mut Child,
    forwarders: &mut JoinSet<Result<()>>,
    cancellation: CancellationToken,
    connection_closed: ConnectionClosed,
    shutdown: Shutdown,
) -> Result<i32>
where
    ConnectionClosed: std::future::Future<Output = String>,
    Shutdown: std::future::Future<Output = std::result::Result<(), ShutdownError>>,
    ShutdownError: Into<anyhow::Error>,
{
    let shutdown = async { shutdown.await.map_err(Into::into) };
    let outcome = tokio::select! {
        status = child.wait() => ConnectOutcome::Child(status),
        reason = connection_closed => ConnectOutcome::ConnectionLost(reason),
        signal = shutdown => ConnectOutcome::Interrupted(signal),
        completed = forwarders.join_next() => ConnectOutcome::Forwarder(completed),
    };
    cancellation.cancel();
    finish_connect_outcome(child, outcome).await
}

enum ConnectOutcome {
    Child(std::io::Result<ExitStatus>),
    ConnectionLost(String),
    Interrupted(Result<()>),
    Forwarder(Option<std::result::Result<Result<()>, tokio::task::JoinError>>),
}

async fn finish_connect_outcome(child: &mut Child, outcome: ConnectOutcome) -> Result<i32> {
    match outcome {
        ConnectOutcome::Child(Ok(status)) => Ok(exit_code(status)),
        ConnectOutcome::Child(Err(error)) => {
            stop_child_after_error(child, anyhow!(error).context("failed to wait for Herdr")).await
        }
        ConnectOutcome::ConnectionLost(reason) => {
            let lost = format!(
                "Iroh connection was lost ({reason}); run `attach` again to refresh the session"
            );
            stop_child_after_error(child, remote_unavailable(anyhow!(lost))).await
        }
        ConnectOutcome::Interrupted(signal) => {
            match signal.context("failed to listen for Ctrl-C") {
                Ok(()) => wait_then_stop_child(child).await.map(exit_code),
                Err(error) => stop_child_after_error(child, error).await,
            }
        }
        ConnectOutcome::Forwarder(completed) => {
            let failure = match completed {
                Some(Ok(Ok(()))) => anyhow!("local proxy forwarder stopped unexpectedly"),
                Some(Ok(Err(error))) => error.context("local proxy forwarder failed"),
                Some(Err(error)) => anyhow!(error).context("local proxy forwarder task failed"),
                None => anyhow!("local proxy forwarder set stopped unexpectedly"),
            };
            stop_child_after_error(child, failure).await
        }
    }
}

async fn stop_child_after_error<T>(child: &mut Child, primary: anyhow::Error) -> Result<T> {
    match stop_child(child).await {
        Ok(_) => Err(primary),
        Err(cleanup) => Err(cleanup.context(primary)),
    }
}

async fn authenticate_client(
    connection: &Connection,
    session: &str,
    capability: &CapabilitySecret,
    local_herdr_version: HerdrVersion,
) -> Result<()> {
    timeout(AUTHENTICATION_TIMEOUT, async {
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .context("failed to open authentication stream")?;
        write_auth_request(&mut send, session, capability, Some(local_herdr_version)).await?;
        read_auth_response(&mut receive, Some(local_herdr_version)).await
    })
    .await
    .context("authentication timed out")??;
    Ok(())
}

fn spawn_herdr(herdr_bin: &Path, tui_socket: &Path) -> Result<Child> {
    let mut command = Command::new(herdr_bin);
    command
        // The proxy exposes only Herdr's TUI socket. Bare `herdr` also probes the
        // default API socket and can reject an unrelated stale local server.
        .arg("client")
        .env_remove("HERDR_SOCKET_PATH")
        .env("HERDR_CLIENT_SOCKET_PATH", tui_socket)
        // A proxied socket attach otherwise looks local to Herdr and requests the
        // server keymap. Use the same internal handoff as `herdr --remote` so the
        // local Herdr binary serializes its configured keymap into the TUI hello.
        .env("HERDR_REMOTE_KEYBINDINGS", "local")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    command
        .spawn()
        .with_context(|| format!("failed to launch Herdr executable {}", herdr_bin.display()))
}

fn spawn_forwarders(
    tui_listener: UnixListener,
    connection: Connection,
    cancellation: CancellationToken,
    connection_id: u64,
) -> JoinSet<Result<()>> {
    let mut tasks = JoinSet::new();
    tasks.spawn(forward_local(
        tui_listener,
        connection,
        Arc::new(Semaphore::new(MAX_STREAMS_PER_CONNECTION)),
        cancellation.child_token(),
        connection_id,
    ));
    tasks
}

async fn forward_local(
    listener: UnixListener,
    connection: Connection,
    stream_limit: Arc<Semaphore>,
    cancellation: CancellationToken,
    connection_id: u64,
) -> Result<()> {
    let mut streams = JoinSet::new();
    let result = loop {
        tokio::select! {
            () = cancellation.cancelled() => break Ok(()),
            accepted = listener.accept() => {
                let (unix, _) = match accepted {
                    Ok(stream) => stream,
                    Err(error) => break Err(error).context("local listener failed"),
                };
                let permit = tokio::select! {
                    () = cancellation.cancelled() => break Ok(()),
                    permit = stream_limit.clone().acquire_owned() => match permit {
                        Ok(permit) => permit,
                        Err(_) => break Err(anyhow!("local stream semaphore closed")),
                    },
                };
                let connection = connection.clone();
                let stream_id = next_stream_id();
                let stream_cancellation = cancellation.child_token();
                streams.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = forward_one_local(unix, connection, connection_id, stream_id, stream_cancellation).await {
                        warn!(connection_id, stream_id, category = "stream", error = %error, "local TUI proxy stream closed");
                    }
                });
            }
            completed = streams.join_next(), if !streams.is_empty() => {
                if let Some(Err(error)) = completed {
                    error!(connection_id, category = "task", error = %error, "local TUI proxy task failed");
                }
            }
        }
    };
    streams.abort_all();
    while streams.join_next().await.is_some() {}
    result
}

async fn forward_one_local(
    unix: UnixStream,
    connection: Connection,
    connection_id: u64,
    stream_id: u64,
    cancellation: CancellationToken,
) -> Result<()> {
    let started = Instant::now();
    let (mut send, receive) = setup_step(
        async {
            connection
                .open_bi()
                .await
                .context("failed to open Iroh stream")
        },
        async {
            cancellation.cancelled().await;
            Result::<()>::Ok(())
        },
        SETUP_TIMEOUT,
        "opening Iroh proxy stream",
    )
    .await?;
    setup_step(
        async { write_stream_header(&mut send).await },
        async {
            cancellation.cancelled().await;
            Result::<()>::Ok(())
        },
        SETUP_TIMEOUT,
        "writing interactive stream header",
    )
    .await?;
    let (unix_reader, unix_writer) = unix.into_split();
    let stats = copy_until_cancelled(unix_reader, unix_writer, receive, send, cancellation).await?;
    log_stream_closed(
        connection_id,
        stream_id,
        None,
        stats.left_to_right,
        stats.right_to_left,
        started.elapsed().as_millis(),
        "clean_eof",
    );
    Ok(())
}

async fn stop_child(child: &mut Child) -> Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    child.start_kill().context("failed to terminate Herdr")?;
    timeout(CHILD_EXIT_GRACE, child.wait())
        .await
        .context("timed out waiting for Herdr to terminate")?
        .context("failed to reap Herdr")
}

async fn wait_then_stop_child(child: &mut Child) -> Result<ExitStatus> {
    let deadline = tokio::time::Instant::now() + CHILD_EXIT_GRACE;
    match timeout_at(deadline, child.wait()).await {
        Ok(status) => finish_interrupted_child_wait(child, status).await,
        Err(_) => stop_child(child).await,
    }
}

async fn finish_interrupted_child_wait(
    child: &mut Child,
    status: std::io::Result<ExitStatus>,
) -> Result<ExitStatus> {
    match status {
        Ok(status) => Ok(status),
        Err(error) => {
            stop_child_after_error(
                child,
                anyhow!(error).context("failed to wait for Herdr after Ctrl-C"),
            )
            .await
        }
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(test)]
#[path = "tunnel_integration_tests.rs"]
mod integration_tests;
#[cfg(test)]
#[path = "tunnel_unit_tests.rs"]
mod tests;
