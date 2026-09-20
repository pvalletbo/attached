//! In-process consumer transport for iOS/macOS. Blocking entry points must be
//! called off the UI thread. Swift owns SSH, key signing and persistent trust;
//! Rust owns discovery, Iroh and the other end of each transferred socket.
mod discovery;

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::canonical::HostAccessDescriptor;
use attached_tunnel_protocol::ssh::{Request, Response, read_frame, write_frame};
use iroh::{Endpoint, endpoint::presets};
use iroh_tickets::endpoint::EndpointTicket;
use std::{
    fmt,
    os::{fd::IntoRawFd, unix::net::UnixStream as StdUnixStream},
    str::FromStr,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::{net::UnixStream, runtime::Runtime};
use tokio_util::sync::CancellationToken;

uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Error)]
pub enum MobileError {
    InvalidDownloadBundle,
    DiscoveryFailed,
    HostUnavailable,
    ConnectionFailed,
    Closed,
}
impl fmt::Display for MobileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MobileError {}

/// Cancellation of one pending discovery or connection, without disrupting
/// other Hosts using the same account endpoint.
#[derive(uniffi::Object)]
pub struct AttachedCancellation {
    token: CancellationToken,
}
#[uniffi::export]
impl AttachedCancellation {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            token: CancellationToken::new(),
        })
    }
    pub fn cancel(&self) {
        self.token.cancel();
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AttachedHost {
    pub endpoint_id: String,
    pub label: String,
    pub version: String,
}

// One runtime per process; dropping an FFI object never blocks the Swift main
// thread waiting for a Tokio runtime to shut down.
fn runtime() -> Result<&'static Runtime> {
    static RUNTIME: OnceLock<std::io::Result<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("attached-mobile")
                .build()
        })
        .as_ref()
        .map_err(|_| anyhow::anyhow!("could not start transport runtime"))
}

#[derive(uniffi::Object)]
pub struct AttachedClient {
    account: discovery::Account,
    http: reqwest::Client,
    endpoint: tokio::sync::Mutex<Option<Endpoint>>,
    cancellation: CancellationToken,
}

#[uniffi::export]
impl AttachedClient {
    #[uniffi::constructor]
    pub fn new(download_bundle: String) -> std::result::Result<Arc<Self>, MobileError> {
        let account = discovery::Account::parse(download_bundle)
            .map_err(|_| MobileError::InvalidDownloadBundle)?;
        let http = discovery::http_client().map_err(|_| MobileError::DiscoveryFailed)?;
        Ok(Arc::new(Self {
            account,
            http,
            endpoint: tokio::sync::Mutex::new(None),
            cancellation: CancellationToken::new(),
        }))
    }

    pub fn account_id(&self) -> String {
        self.account.id.to_string()
    }

    pub fn hosts(
        &self,
        cancellation: Arc<AttachedCancellation>,
    ) -> std::result::Result<Vec<AttachedHost>, MobileError> {
        let rt = runtime().map_err(|_| MobileError::DiscoveryFailed)?;
        rt.block_on(async {
            tokio::select! {
                _ = self.cancellation.cancelled() => Err(MobileError::Closed),
                _ = cancellation.token.cancelled() => Err(MobileError::Closed),
                result = tokio::time::timeout(Duration::from_secs(30), discovery::discover(&self.http, &self.account)) => {
                    let records = result.map_err(|_| MobileError::DiscoveryFailed)?.map_err(|_| MobileError::DiscoveryFailed)?;
                    let mut hosts = records.iter().map(|r| r.descriptor()).filter(|d| d.ssh_enabled()).map(|d| AttachedHost {
                        endpoint_id: iroh::EndpointId::from_bytes(&d.endpoint_identity()).expect("validated endpoint").to_string(),
                        label: d.host_label().to_owned(), version: format!("{}.{}.{}", d.attached_version().major, d.attached_version().minor, d.attached_version().patch),
                    }).collect::<Vec<_>>();
                    hosts.sort_by(|a,b| a.endpoint_id.cmp(&b.endpoint_id));
                    hosts.dedup_by(|a,b| a.endpoint_id == b.endpoint_id);
                    Ok(hosts)
                }
            }
        })
    }

    /// Always resolve by stable identity, never by a mutable Host label. Pass
    /// only the public Ed25519 key; the app keeps its private key in Keychain.
    pub fn connect(
        &self,
        endpoint_id: String,
        public_key: String,
        cancellation: Arc<AttachedCancellation>,
    ) -> std::result::Result<Arc<AttachedTunnel>, MobileError> {
        let id = endpoint_id
            .parse::<iroh::EndpointId>()
            .map_err(|_| MobileError::HostUnavailable)?;
        let public_key = canonical_key(&public_key).map_err(|_| MobileError::ConnectionFailed)?;
        let rt = runtime().map_err(|_| MobileError::ConnectionFailed)?;
        rt.block_on(async {
            tokio::select! {
                _ = self.cancellation.cancelled() => Err(MobileError::Closed),
                _ = cancellation.token.cancelled() => Err(MobileError::Closed),
                result = tokio::time::timeout(Duration::from_secs(40), async {
                    // A fresh lookup on each connection avoids reusing capabilities
                    // rotated by a publisher restart. Commands are never replayed.
                    let records = discovery::discover(&self.http, &self.account).await.map_err(|_| MobileError::DiscoveryFailed)?;
                    let mut matches = records.iter().map(|r| r.descriptor()).filter(|d| d.endpoint_identity() == *id.as_bytes() && d.ssh_enabled());
                    let descriptor = matches.next().ok_or(MobileError::HostUnavailable)?;
                    if matches.next().is_some() { return Err(MobileError::HostUnavailable); }
                    let endpoint = self.endpoint(descriptor).await.map_err(|_| MobileError::ConnectionFailed)?;
                    open(&endpoint, descriptor, &public_key, self.cancellation.child_token()).await.map(Arc::new).map_err(|_| MobileError::ConnectionFailed)
                }) => result.map_err(|_| MobileError::ConnectionFailed)?,
            }
        })
    }

    /// Cancels discovery, setup and all open SSH streams immediately.
    pub fn close(&self) {
        self.cancellation.cancel();
    }
}

impl AttachedClient {
    async fn endpoint(&self, descriptor: &HostAccessDescriptor) -> Result<Endpoint> {
        let mut slot = self.endpoint.lock().await;
        if let Some(endpoint) = &*slot {
            return Ok(endpoint.clone());
        }
        let ticket = EndpointTicket::from_str(descriptor.endpoint_ticket())?;
        let mut builder = Endpoint::builder(presets::N0)
            .secret_key(iroh::SecretKey::from_bytes(&self.account.consumer));
        let address = ticket.endpoint_addr();
        if !address.addrs.is_empty()
            && address
                .addrs
                .iter()
                .all(|a| matches!(a, iroh::TransportAddr::Ip(s) if s.ip().is_loopback()))
        {
            builder = builder
                .relay_mode(iroh::RelayMode::Disabled)
                .clear_address_lookup();
        }
        let endpoint = builder.bind().await?;
        let retained = endpoint.clone();
        let cancelled = self.cancellation.clone();
        tokio::spawn(async move {
            cancelled.cancelled().await;
            retained.close().await;
        });
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }
}
impl Drop for AttachedClient {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(uniffi::Object)]
pub struct AttachedTunnel {
    socket: Mutex<Option<StdUnixStream>>,
    username: String,
    host_key: String,
    cancellation: CancellationToken,
}

#[uniffi::export]
impl AttachedTunnel {
    pub fn username(&self) -> String {
        self.username.clone()
    }
    /// Authenticated by the encrypted descriptor's Iroh identity. The SSH
    /// handshake must match this key in addition to the app's persistent pin.
    pub fn host_key(&self) -> String {
        self.host_key.clone()
    }
    /// One-time ownership transfer. The caller MUST close this descriptor,
    /// even if SSH setup fails. No TCP port or network listener is exposed.
    pub fn take_socket(&self) -> std::result::Result<i32, MobileError> {
        if self.cancellation.is_cancelled() {
            return Err(MobileError::Closed);
        }
        self.socket
            .lock()
            .map_err(|_| MobileError::Closed)?
            .take()
            .map(IntoRawFd::into_raw_fd)
            .ok_or(MobileError::Closed)
    }
    pub fn close(&self) {
        self.cancellation.cancel();
    }
}
impl Drop for AttachedTunnel {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn canonical_key(text: &str) -> Result<String> {
    ensure!(text.len() <= 1024, "key too long");
    let key = ssh_key::PublicKey::from_openssh(text)?;
    ensure!(
        key.algorithm() == ssh_key::Algorithm::Ed25519,
        "Ed25519 required"
    );
    Ok(ssh_key::PublicKey::new(key.key_data().clone(), "").to_openssh()?)
}

async fn open(
    endpoint: &Endpoint,
    descriptor: &HostAccessDescriptor,
    key: &str,
    cancellation: CancellationToken,
) -> Result<AttachedTunnel> {
    ensure!(
        chrono::Utc::now() < descriptor.expires_at(),
        "descriptor expired"
    );
    let ticket = EndpointTicket::from_str(descriptor.endpoint_ticket())?;
    let connection = endpoint
        .connect(
            ticket.endpoint_addr().clone(),
            attached_tunnel_protocol::SSH_ALPN,
        )
        .await?;
    // Close even when a setup future is cancelled or metadata is rejected.
    let guard = ConnectionGuard(connection);
    let (mut send, mut receive) = guard.0.open_bi().await?;
    write_frame(
        &mut send,
        &Request {
            capability: descriptor.attach_capability_bytes(),
            public_key: key.to_owned(),
        },
    )
    .await?;
    let metadata: Response = read_frame(&mut receive).await?;
    ensure!(
        !metadata.username.is_empty()
            && metadata.username.len() <= 256
            && metadata
                .username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "invalid username"
    );
    let host_key = canonical_key(&metadata.host_key)?;
    let (socket, proxy) = StdUnixStream::pair()?;
    socket.set_nonblocking(true)?;
    proxy.set_nonblocking(true)?;
    let mut proxy = UnixStream::from_std(proxy).context("register proxy socket")?;
    let cancelled = cancellation.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let mut remote = tokio::io::join(receive, send);
        tokio::select! {
            _ = cancelled.cancelled() => {},
            _ = tokio::io::copy_bidirectional(&mut proxy, &mut remote) => {},
        }
        cancelled.cancel();
    });
    Ok(AttachedTunnel {
        socket: Mutex::new(Some(socket)),
        username: metadata.username,
        host_key,
        cancellation,
    })
}

struct ConnectionGuard(iroh::endpoint::Connection);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"mobile SSH stream ended");
    }
}

#[cfg(test)]
mod tests;
