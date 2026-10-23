//! Raw TCP forwarding. Neither the CLI nor the wire format accepts a remote
//! address: the publisher can only dial literal IPv4/IPv6 loopback addresses.
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use attached_tunnel_protocol::{
    CapabilitySecret, TcpForwardStatus, read_tcp_forward_open, read_tcp_forward_request,
    read_tcp_forward_status, write_tcp_forward_open, write_tcp_forward_request,
    write_tcp_forward_status,
};
use iroh::{Endpoint, endpoint::presets};
use iroh_tickets::endpoint::EndpointTicket;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{proxy, publisher_descriptor::Descriptors, sync};

pub(crate) use attached_tunnel_protocol::TCP_FORWARD_ALPN as ALPN;
const SETUP_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_STREAMS: usize = 64;

/// Close uncommitted setup connections even when their future is cancelled.
struct SetupConnection(Option<iroh::endpoint::Connection>);

impl Drop for SetupConnection {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            connection.close(0u32.into(), b"TCP setup cancelled or failed");
        }
    }
}

pub(crate) async fn serve(
    connection: iroh::endpoint::Connection,
    path: PathBuf,
    capability: CapabilitySecret,
    cancellation: CancellationToken,
) -> Result<()> {
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => Ok(()),
        result = serve_inner(&connection, &path, &capability, cancellation.clone()) => result,
    };
    connection.close(0u32.into(), b"TCP forwarding ended");
    result
}

async fn serve_inner(
    connection: &iroh::endpoint::Connection,
    path: &Path,
    capability: &CapabilitySecret,
    cancellation: CancellationToken,
) -> Result<()> {
    let peer = connection.remote_id();
    sync::state::authorize_consumer(path, peer.as_bytes())?;
    let port = timeout(SETUP_TIMEOUT, async {
        let (mut send, mut receive) = connection.accept_bi().await?;
        let port = read_tcp_forward_request(&mut receive, capability).await?;
        write_tcp_forward_status(&mut send, TcpForwardStatus::Ready).await?;
        send.shutdown().await?;
        Ok::<_, anyhow::Error>(port)
    })
    .await
    .context("TCP forwarding authentication timed out")??;
    let mut tasks = JoinSet::new();
    let mut authorization = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            biased;
            _ = authorization.tick() => sync::state::authorize_consumer(path, peer.as_bytes())?,
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(Err(error))) = completed {
                    tracing::debug!(%error, "TCP forwarding stream ended");
                }
            }
            accepted = connection.accept_bi() => {
                let (send, receive) = accepted?;
                if tasks.len() >= MAX_STREAMS {
                    // Dropping unserved streams resets them without opening a socket.
                    continue;
                }
                let token = cancellation.child_token();
                tasks.spawn(async move {
                    tokio::select! {
                        _ = token.cancelled() => Ok(()),
                        result = serve_stream(send, receive, port) => result,
                    }
                });
            }
        }
    }
}

async fn connect_loopback(port: u16) -> Result<TcpStream> {
    // Do not resolve "localhost": hosts/DNS configuration must never make this
    // service a gateway to a non-loopback address. IPv6-only services work too.
    match timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        _ => timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((Ipv6Addr::LOCALHOST, port)),
        )
        .await
        .context("remote loopback TCP connection timed out")?
        .context("could not connect to the remote loopback TCP port"),
    }
}

async fn serve_stream(
    mut send: iroh::endpoint::SendStream,
    mut receive: iroh::endpoint::RecvStream,
    port: u16,
) -> Result<()> {
    let stream = timeout(SETUP_TIMEOUT, async {
        read_tcp_forward_open(&mut receive).await?;
        match connect_loopback(port).await {
            Ok(stream) => {
                write_tcp_forward_status(&mut send, TcpForwardStatus::Ready).await?;
                Ok(stream)
            }
            Err(error) => {
                write_tcp_forward_status(&mut send, TcpForwardStatus::ConnectionFailed).await?;
                send.shutdown().await?;
                Err(error)
            }
        }
    })
    .await
    .context("TCP stream setup timed out")??;
    stream.set_nodelay(true)?;
    let (read, write) = stream.into_split();
    proxy::copy_bidirectional_split(read, write, receive, send).await?;
    Ok(())
}

struct Client {
    endpoint: Endpoint,
    descriptors: Descriptors,
    account: sync::state::AccountCredentials,
    port: u16,
    connection: Mutex<Option<iroh::endpoint::Connection>>,
}

impl Client {
    async fn open(
        &self,
        host: &sync::state_catalog::HostConnection,
    ) -> Result<iroh::endpoint::Connection> {
        ensure!(
            sync::utc_now_seconds() < host.expires_at,
            "publisher descriptor expired"
        );
        let ticket = EndpointTicket::from_str(&host.endpoint_ticket)?;
        ensure!(
            ticket.endpoint_addr().id.as_bytes() == &host.endpoint_identity,
            "publisher ticket identity mismatch"
        );
        let connection = self.endpoint.connect(ticket.endpoint_addr().clone(), ALPN).await
            .context("publisher does not support TCP forwarding or is unavailable; update Attached and run `attached serve` on the publisher")?;
        let mut pending = SetupConnection(Some(connection.clone()));
        {
            let (mut send, mut receive) = connection.open_bi().await?;
            write_tcp_forward_request(
                &mut send,
                &CapabilitySecret::from_bytes(host.attach_capability),
                self.port,
            )
            .await?;
            ensure!(
                read_tcp_forward_status(&mut receive).await? == TcpForwardStatus::Ready,
                "publisher rejected TCP forwarding"
            );
            // Setup ends here; no application bytes are ever sent on this stream.
            ensure!(
                receive.read_to_end(0).await?.is_empty(),
                "trailing TCP setup response bytes"
            );
        }
        pending.0 = None;
        Ok(connection)
    }

    /// Single-flight connection setup. Reconnect only for new TCP connections;
    /// never replay application bytes or try to resurrect an interrupted stream.
    async fn connection(&self) -> Result<iroh::endpoint::Connection> {
        let mut current = self.connection.lock().await;
        if let Some(connection) = &*current
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
        let connection = timeout(SETUP_TIMEOUT, async {
            let host = self.descriptors.get(&self.account, None).await?;
            match self.open(&host).await {
                Ok(connection) => Ok(connection),
                Err(error) => {
                    let refreshed = self.descriptors.get(&self.account, Some(&host)).await?;
                    if refreshed == host {
                        return Err(error);
                    }
                    self.open(&refreshed).await
                }
            }
        })
        .await
        .context("TCP publisher setup or discovery refresh timed out")??;
        *current = Some(connection.clone());
        Ok(connection)
    }

    async fn forward_stream(&self, stream: TcpStream) -> Result<()> {
        let connection = self.connection().await?;
        let (send, receive) = timeout(SETUP_TIMEOUT, async {
            let (mut send, mut receive) = connection.open_bi().await?;
            write_tcp_forward_open(&mut send).await?;
            if read_tcp_forward_status(&mut receive).await? != TcpForwardStatus::Ready {
                bail!(
                    "could not connect to remote loopback port {} (is the service running?)",
                    self.port
                );
            }
            Ok::<_, anyhow::Error>((send, receive))
        })
        .await
        .context("TCP stream setup timed out")??;
        stream.set_nodelay(true)?;
        let (read, write) = stream.into_split();
        proxy::copy_bidirectional_split(read, write, receive, send).await?;
        Ok(())
    }
}

async fn listen(listener: TcpListener, client: Arc<Client>, target: &str) -> Result<()> {
    // Fail before announcing readiness if the publisher is old or unauthorized.
    client.connection().await?;
    eprintln!(
        "Forwarding {} -> {target}:{} (remote loopback, TCP only). Keep this process running; Ctrl-C stops forwarding. Interrupted connections must be reopened.",
        listener.local_addr()?,
        client.port
    );
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                if tasks.len() >= MAX_STREAMS {
                    eprintln!("TCP forwarding connection limit reached; connection rejected");
                    continue;
                }
                let client = client.clone();
                tasks.spawn(async move { client.forward_stream(stream).await });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(Err(error))) = completed {
                    eprintln!("TCP forwarding connection failed: {error:#}");
                }
            }
        }
    }
}

pub(crate) async fn forward(
    path: &Path,
    target: &str,
    local: u16,
    remote: u16,
    no_cache: bool,
) -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let shutdown = async {
        tokio::select! {
            _ = interrupt.recv() => {}, _ = terminate.recv() => {}, _ = hangup.recv() => {},
        }
    };
    tokio::pin!(shutdown);
    // Signals interrupt initial discovery/handshake too, not just active traffic.
    let initialize = async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, local))
            .await
            .with_context(|| format!("could not bind local TCP port 127.0.0.1:{local}"))?;
        let account = sync::state::load_account(path, ApiKeyScope::Download)?;
        let host = sync::refresh::ssh_host(path, &account, target, no_cache).await?;
        let key = iroh::SecretKey::from_bytes(
            account
                .consumer_identity_secret()
                .context("download bundle has no consumer identity")?,
        );
        let ticket = EndpointTicket::from_str(&host.endpoint_ticket)?;
        let mut builder = Endpoint::builder(presets::N0).secret_key(key);
        let loopback_only = !ticket.endpoint_addr().addrs.is_empty()
            && ticket.endpoint_addr().addrs.iter().all(|address| {
                matches!(address, iroh::TransportAddr::Ip(socket) if socket.ip().is_loopback())
            });
        if loopback_only {
            builder = builder
                .relay_mode(iroh::RelayMode::Disabled)
                .clear_address_lookup();
        }
        let endpoint = builder.bind().await?;
        let client = Arc::new(Client {
            endpoint: endpoint.clone(),
            descriptors: Descriptors::new(host),
            account,
            port: remote,
            connection: Mutex::new(None),
        });
        Ok::<_, anyhow::Error>((listener, endpoint, client))
    };
    let (listener, endpoint, client) = tokio::select! {
        result = initialize => result?,
        _ = &mut shutdown => return Ok(0),
    };
    let result = tokio::select! {
        result = listen(listener, client, target) => result,
        _ = &mut shutdown => Ok(()),
    };
    // A disappearing peer must not prevent local shutdown indefinitely.
    let _ = timeout(Duration::from_secs(3), endpoint.close()).await;
    result?;
    Ok(0)
}

#[cfg(test)]
#[path = "forward_tests.rs"]
mod tests;
