//! Commands share a detached, reference-counted network broker, not an Iroh
//! identity bound independently in each process. Only the broker opens endpoints.
use std::{
    io::ErrorKind,
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use fs4::{FileExt, TryLockError};
use iroh::{EndpointAddr, EndpointId, SecretKey, endpoint::VarInt};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    sync::Mutex,
    time::{Instant, sleep, timeout},
};

use crate::client_ipc::{self as ipc, Operation, Response, Token};

pub(crate) type SendStream = Box<dyn AsyncWrite + Unpin + Send>;
pub(crate) type RecvStream = Box<dyn AsyncRead + Unpin + Send>;
const START_TIMEOUT: Duration = Duration::from_secs(15);
const RPC_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub(crate) struct ClientEndpoint(Arc<EndpointKind>);

enum EndpointKind {
    Shared {
        key: Box<SecretKey>,
        lease: Mutex<Option<Arc<Lease>>>,
    },
    #[cfg(test)]
    Direct(iroh::Endpoint),
}

struct Lease {
    stream: UnixStream,
    token: Token,
    identity: EndpointId,
    closed: AtomicBool,
}

impl Lease {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || socket_closed(&self.stream)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Any control byte means close. This also wakes the broker immediately;
        // dropping the control socket provides the crash/kill cleanup path.
        let _ = self.stream.try_write(&[0]);
    }
}

fn socket_closed(stream: &UnixStream) -> bool {
    !matches!(stream.try_read(&mut [0; 1]), Err(error) if error.kind() == ErrorKind::WouldBlock)
}

impl ClientEndpoint {
    pub(crate) async fn new(key: SecretKey) -> Result<Self> {
        let endpoint = Self(Arc::new(EndpointKind::Shared {
            key: Box::new(key),
            lease: Mutex::new(None),
        }));
        endpoint.lease().await?;
        Ok(endpoint)
    }

    #[cfg(test)]
    pub(crate) fn direct(endpoint: iroh::Endpoint) -> Self {
        Self(Arc::new(EndpointKind::Direct(endpoint)))
    }

    async fn lease(&self) -> Result<Arc<Lease>> {
        let (key, lease) = match &*self.0 {
            EndpointKind::Shared { key, lease } => (key, lease),
            #[cfg(test)]
            EndpointKind::Direct(_) => unreachable!("native test endpoints have no IPC lease"),
        };
        let mut current = lease.lock().await;
        if let Some(lease) = &*current
            && !lease.is_closed()
        {
            return Ok(lease.clone());
        }
        let next = Arc::new(acquire(key).await?);
        *current = Some(next.clone());
        Ok(next)
    }

    pub(crate) async fn connect(&self, address: EndpointAddr, alpn: &[u8]) -> Result<Connection> {
        #[cfg(test)]
        if let EndpointKind::Direct(endpoint) = &*self.0 {
            return Ok(Connection(Arc::new(ConnectionKind::Direct(
                endpoint.connect(address, alpn).await?,
            ))));
        }
        timeout(RPC_TIMEOUT, async {
            let lease = self.lease().await?;
            let path = ipc::socket(&ipc::runtime(lease.identity)?);
            let mut stream = UnixStream::connect(path).await?;
            let peer = address.id;
            let response = ipc::request(
                &mut stream,
                Operation::Connect {
                    lease: lease.token,
                    address,
                    alpn: alpn.to_vec(),
                },
            )
            .await?;
            let Response::Connected { connection } = response else {
                bail!("invalid local broker connect response");
            };
            Ok(Connection(Arc::new(ConnectionKind::Shared {
                stream,
                lease,
                token: connection,
                peer,
                closed: AtomicBool::new(false),
            })))
        })
        .await
        .context("local broker connection setup timed out")?
    }

    pub(crate) async fn status(&self) -> Result<(u32, usize, usize)> {
        let lease = self.lease().await?;
        timeout(RPC_TIMEOUT, async {
            let mut stream =
                UnixStream::connect(ipc::socket(&ipc::runtime(lease.identity)?)).await?;
            let Response::Status {
                identity,
                pid,
                leases,
                connections,
            } = ipc::request(
                &mut stream,
                Operation::Status {
                    identity: lease.identity,
                },
            )
            .await?
            else {
                bail!("incompatible local broker; restart Attached client commands");
            };
            ensure!(identity == lease.identity, "local broker identity mismatch");
            Ok((pid, leases, connections))
        })
        .await
        .context("local broker status timed out")?
    }

    /// Releases this command's lease only. Other commands' tunnels and the shared
    /// endpoint remain alive; the broker exits automatically after the last lease.
    pub(crate) async fn close(&self) {
        match &*self.0 {
            EndpointKind::Shared { lease, .. } => {
                if let Some(lease) = lease.lock().await.take() {
                    lease.close();
                }
            }
            #[cfg(test)]
            EndpointKind::Direct(endpoint) => endpoint.close().await,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Connection(Arc<ConnectionKind>);

enum ConnectionKind {
    Shared {
        stream: UnixStream,
        lease: Arc<Lease>,
        token: Token,
        peer: EndpointId,
        closed: AtomicBool,
    },
    #[cfg(test)]
    Direct(iroh::endpoint::Connection),
}

impl Connection {
    pub(crate) fn remote_id(&self) -> EndpointId {
        match &*self.0 {
            ConnectionKind::Shared { peer, .. } => *peer,
            #[cfg(test)]
            ConnectionKind::Direct(connection) => connection.remote_id(),
        }
    }

    pub(crate) fn close_reason(&self) -> Option<String> {
        match &*self.0 {
            ConnectionKind::Shared {
                stream,
                lease,
                closed,
                ..
            } => (closed.load(Ordering::SeqCst) || lease.is_closed() || socket_closed(stream))
                .then(|| "local broker connection ended".to_owned()),
            #[cfg(test)]
            ConnectionKind::Direct(connection) => {
                connection.close_reason().map(|reason| reason.to_string())
            }
        }
    }

    pub(crate) fn close(&self, code: VarInt, reason: &[u8]) {
        match &*self.0 {
            ConnectionKind::Shared { stream, closed, .. } => {
                let _ = (code, reason);
                closed.store(true, Ordering::SeqCst);
                let _ = stream.try_write(&[0]);
            }
            #[cfg(test)]
            ConnectionKind::Direct(connection) => connection.close(code, reason),
        }
    }

    pub(crate) async fn info(&self) -> Result<ipc::ConnectionInfo> {
        match &*self.0 {
            ConnectionKind::Shared { lease, token, .. } => timeout(RPC_TIMEOUT, async {
                let mut stream =
                    UnixStream::connect(ipc::socket(&ipc::runtime(lease.identity)?)).await?;
                let Response::Inspected { info } = ipc::request(
                    &mut stream,
                    Operation::Inspect {
                        lease: lease.token,
                        connection: *token,
                    },
                )
                .await?
                else {
                    bail!("incompatible local broker; restart Attached client commands");
                };
                Ok(info)
            })
            .await
            .context("local broker inspection timed out")?,
            #[cfg(test)]
            ConnectionKind::Direct(connection) => Ok(ipc::ConnectionInfo::measure(connection)),
        }
    }

    pub(crate) async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        match &*self.0 {
            ConnectionKind::Shared { lease, token, .. } => {
                ensure!(
                    self.close_reason().is_none(),
                    "local broker connection ended"
                );
                timeout(RPC_TIMEOUT, async {
                    let mut stream =
                        UnixStream::connect(ipc::socket(&ipc::runtime(lease.identity)?)).await?;
                    ensure!(
                        matches!(
                            ipc::request(
                                &mut stream,
                                Operation::Open {
                                    lease: lease.token,
                                    connection: *token,
                                }
                            )
                            .await?,
                            Response::Open
                        ),
                        "invalid local broker stream response"
                    );
                    let (read, write) = stream.into_split();
                    Ok((Box::new(write) as SendStream, Box::new(read) as RecvStream))
                })
                .await
                .context("local broker stream setup timed out")?
            }
            #[cfg(test)]
            ConnectionKind::Direct(connection) => {
                let (send, receive) = connection.open_bi().await?;
                Ok((Box::new(send), Box::new(receive)))
            }
        }
    }
}

async fn attach(path: &Path, identity: EndpointId) -> Result<Lease> {
    timeout(Duration::from_secs(2), async {
        let mut stream = UnixStream::connect(ipc::socket(path)).await?;
        let Response::Lease {
            identity: actual,
            lease,
            ..
        } = ipc::request(&mut stream, Operation::Lease { identity }).await?
        else {
            bail!("invalid local broker lease response");
        };
        ensure!(identity == actual, "local broker identity mismatch");
        Ok(Lease {
            stream,
            token: lease,
            identity,
            closed: AtomicBool::new(false),
        })
    })
    .await
    .context("local broker handshake timed out")?
}

async fn acquire(key: &SecretKey) -> Result<Lease> {
    let path = ipc::runtime(key.public())?;
    let directory = ipc::directory(&path)?;
    if let Ok(lease) = attach(&path, key.public()).await {
        return Ok(lease);
    }
    // Serialize starters across processes, without blocking the async runtime or
    // holding an endpoint under the same identity in any frontend process.
    let startup = directory
        .open_private_lock_file("startup.lock", true)?
        .context("missing broker startup lock")?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match FileExt::try_lock(&startup) {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) => {
                ensure!(
                    Instant::now() < deadline,
                    "local broker startup lock timed out"
                );
                sleep(Duration::from_millis(20)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    directory.verify_locked_file(&path, "startup.lock", &startup)?;
    let _startup = startup; // The stable inode is unlocked on close, never unlinked.
    let owner = directory
        .open_private_lock_file("owner.lock", true)?
        .context("missing broker owner lock")?;
    let mut started = false;
    loop {
        if let Ok(lease) = attach(&path, key.public()).await {
            return Ok(lease);
        }
        ensure!(
            Instant::now() < deadline,
            "local broker did not become ready; stop any older Attached client commands and retry"
        );
        if !started {
            match FileExt::try_lock(&owner) {
                Ok(()) => {
                    FileExt::unlock(&owner)?;
                    spawn(&path, key).await?;
                    started = true;
                }
                Err(TryLockError::WouldBlock) => {} // A live broker is starting/draining.
                Err(error) => return Err(error.into()),
            }
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn spawn(path: &Path, key: &SecretKey) -> Result<()> {
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .arg("__client-broker")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_remove("ATTACHED_ENCRYPTION_PASSWORD")
        .env_remove("ATTACHED_PUBLISH_BUNDLE")
        .process_group(0)
        .kill_on_drop(false)
        .spawn()
        .context("could not start the local Attached network broker")?;
    // No private key in argv, a socket discovery file, or on disk. Detach from the
    // initiating terminal's signals; client lease EOF determines the lifetime.
    let mut stdin = child.stdin.take().context("missing broker key pipe")?;
    if let Err(error) = stdin.write_all(&key.to_bytes()).await
        && error.kind() != ErrorKind::BrokenPipe
    {
        return Err(error.into());
    }
    let _ = stdin.shutdown().await;
    Ok(())
}
