//! A process-independent Iroh endpoint. Per-command leases own connections;
//! terminating an exporter/forwarder never closes another command's transports.
use std::{
    collections::HashMap,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, ensure};
use fs4::FileExt;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    client_ipc::{self as ipc, Operation, Request, Response, Token},
    proxy,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(2);
const RESUME_GAP: Duration = Duration::from_secs(30);
const MAX_LEASES: usize = 32;
const MAX_CONNECTIONS: usize = 128;
const MAX_IPC_CONNECTIONS: usize = 1024;

struct Lease {
    cancellation: CancellationToken,
    connections: Mutex<HashMap<Token, iroh::endpoint::Connection>>,
}

struct Broker {
    identity: iroh::EndpointId,
    endpoint: Mutex<Option<Endpoint>>,
    leases: Mutex<HashMap<Token, Arc<Lease>>>,
}

impl Broker {
    async fn lease(&self, token: &Token) -> Result<Arc<Lease>> {
        let lease = self
            .leases
            .lock()
            .await
            .get(token)
            .cloned()
            .context("client lease ended")?;
        ensure!(!lease.cancellation.is_cancelled(), "client lease ended");
        Ok(lease)
    }

    async fn handle(&self, stream: &mut UnixStream, ready: &mut bool) -> Result<()> {
        ipc::check_peer(stream)?;
        let request: Request = timeout(SETUP_TIMEOUT, ipc::read(stream))
            .await
            .context("local broker request timed out")??;
        ensure!(
            request.version == ipc::VERSION,
            "incompatible local broker protocol; restart Attached client commands"
        );
        match request.operation {
            Operation::Lease { identity } => {
                ensure!(identity == self.identity, "local broker identity mismatch");
                let token = ipc::token()?;
                let lease = Arc::new(Lease {
                    cancellation: CancellationToken::new(),
                    connections: Mutex::new(HashMap::new()),
                });
                {
                    let mut leases = self.leases.lock().await;
                    ensure!(
                        leases.len() < MAX_LEASES,
                        "too many Attached client commands"
                    );
                    leases.insert(token, lease.clone());
                }
                let result = async {
                    ipc::write(
                        stream,
                        &Response::Lease {
                            identity,
                            lease: token,
                            pid: std::process::id(),
                        },
                    )
                    .await?;
                    *ready = true;
                    let _ = stream.read_u8().await; // EOF, a byte, or a killed client ends its lease.
                    Ok(())
                }
                .await;
                lease.cancellation.cancel();
                self.leases.lock().await.remove(&token);
                result
            }
            Operation::Connect {
                lease,
                address,
                alpn,
            } => {
                ensure!(
                    [
                        crate::ssh::ALPN,
                        crate::forward::ALPN,
                        attached_tunnel_protocol::ATTACHED_UPDATE_ALPN
                    ]
                    .contains(&alpn.as_slice()),
                    "unsupported local broker service"
                );
                let lease = self.lease(&lease).await?;
                let connection = tokio::select! {
                    _ = lease.cancellation.cancelled() => anyhow::bail!("client lease ended"),
                    _ = stream.read_u8() => anyhow::bail!("client cancelled connection setup"),
                    result = timeout(SETUP_TIMEOUT, async {
                        let endpoint = self.endpoint.lock().await.as_ref().context("network broker is restarting")?.clone();
                        Ok::<_, anyhow::Error>(endpoint.connect(address, &alpn).await?)
                    }) => result.context("publisher connection timed out")??,
                };
                let token = ipc::token()?;
                {
                    let mut connections = lease.connections.lock().await;
                    if connections.len() >= MAX_CONNECTIONS {
                        connection.close(0u32.into(), b"client connection limit");
                        anyhow::bail!("too many client connections");
                    }
                    connections.insert(token, connection.clone());
                }
                let result = async {
                    ipc::write(stream, &Response::Connected { connection: token }).await?;
                    *ready = true;
                    tokio::select! {
                        _ = lease.cancellation.cancelled() => {},
                        _ = connection.closed() => {},
                        _ = stream.read_u8() => {},
                    }
                    Ok(())
                }
                .await;
                connection.close(0u32.into(), b"client connection ended");
                lease.connections.lock().await.remove(&token);
                result
            }
            Operation::Open { lease, connection } => {
                let lease = self.lease(&lease).await?;
                let connection = lease
                    .connections
                    .lock()
                    .await
                    .get(&connection)
                    .cloned()
                    .context("client connection ended")?;
                let (send, receive) = tokio::select! {
                    _ = lease.cancellation.cancelled() => anyhow::bail!("client lease ended"),
                    result = timeout(SETUP_TIMEOUT, connection.open_bi()) => result.context("publisher stream setup timed out")??,
                };
                ipc::write(stream, &Response::Open).await?;
                *ready = true;
                let (read, write) = stream.split();
                proxy::copy_until_cancelled(read, write, receive, send, lease.cancellation.clone())
                    .await?;
                Ok(())
            }
        }
    }
}

pub(crate) async fn run(path: PathBuf) -> Result<i32> {
    // A finite inherited pipe, never argv/environment/disk, supplies the key.
    let mut secret = zeroize::Zeroizing::new([0; 32]);
    timeout(
        Duration::from_secs(5),
        tokio::io::stdin().read_exact(&mut *secret),
    )
    .await
    .context("broker key pipe timed out")??;
    let key = SecretKey::from_bytes(&secret);
    ensure!(
        path == ipc::runtime(key.public())?,
        "invalid local broker runtime path"
    );
    let directory = ipc::directory(&path)?;
    let owner = directory
        .open_private_lock_file("owner.lock", true)?
        .context("missing broker owner lock")?;
    // The lock is held until the endpoint is fully closed, not merely until the
    // socket disappears. Losing a startup race can never bind a second identity.
    FileExt::try_lock(&owner)
        .context("another local broker already owns this consumer identity")?;
    directory.verify_locked_file(&path, "owner.lock", &owner)?;
    let socket = ipc::socket(&path);
    match std::fs::remove_file(&socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let result = serve(listener, || {
        Endpoint::builder(presets::N0).secret_key(key.clone())
    })
    .await;
    let _ = std::fs::remove_file(socket);
    drop(owner);
    result?;
    Ok(0)
}

async fn serve(listener: UnixListener, build: impl Fn() -> iroh::endpoint::Builder) -> Result<()> {
    let endpoint = build().bind().await?;
    let broker = Arc::new(Broker {
        identity: endpoint.id(),
        endpoint: Mutex::new(Some(endpoint)),
        leases: Mutex::new(HashMap::new()),
    });
    let mut tasks = JoinSet::new();
    let limit = Arc::new(Semaphore::new(MAX_IPC_CONNECTIONS));
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut idle_since = Instant::now();
    let mut last_tick = SystemTime::now();
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                    let broker = broker.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let mut ready = false;
                        if let Err(error) = broker.handle(&mut stream, &mut ready).await && !ready {
                            // Never insert a JSON error into an already-open raw stream.
                            let message: String = error.to_string().chars().take(512).collect();
                            let _ = ipc::write(&mut stream, &Response::Error { message }).await;
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                _ = tick.tick() => {
                    if tasks.is_empty() && broker.leases.lock().await.is_empty() {
                        if idle_since.elapsed() >= IDLE_TIMEOUT { break Ok::<_, anyhow::Error>(()); }
                    } else {
                        idle_since = Instant::now();
                    }
                    let now = SystemTime::now();
                    let resumed = now.duration_since(last_tick).unwrap_or_default() >= RESUME_GAP;
                    last_tick = now;
                    if resumed {
                        // Only this process may rebuild the endpoint. All clients
                        // keep their leases and reconnect NEW streams, never replay.
                        let mut endpoint = broker.endpoint.lock().await;
                        if let Some(old) = endpoint.take() {
                            let _ = timeout(Duration::from_secs(3), old.close()).await;
                            drop(old); // Even a timed-out close cannot overlap the new relay registration.
                        }
                        *endpoint = Some(build().bind().await?);
                    }
                }
            }
        }
    }.await;
    for lease in broker.leases.lock().await.values() {
        lease.cancellation.cancel();
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let endpoint = broker.endpoint.lock().await;
    if let Some(endpoint) = &*endpoint {
        let _ = timeout(Duration::from_secs(3), endpoint.close()).await;
    }
    result
}

#[cfg(test)]
#[path = "client_broker_tests.rs"]
mod tests;
