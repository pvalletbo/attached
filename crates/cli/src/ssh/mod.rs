//! Account-authorized SSH over a versioned Iroh ALPN.
//! russh implements SSH; Attached implements the deliberately limited exec/shell service.
mod account;
mod client;
mod descriptor;
mod exec;
mod state;

use anyhow::{Context, Result, ensure};
use attached_tunnel_protocol::CapabilitySecret;
use russh::keys::PublicKey;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub(crate) use attached_tunnel_protocol::SSH_ALPN as ALPN;
pub(crate) use client::{connect, local_proxy};
pub(crate) use state::set_access;
const SETUP_TIMEOUT: Duration = Duration::from_secs(20);

/// Discovery advertises only explicit consent for the configured consumer and OS account.
/// Invalid, missing, or inaccessible policy files fail closed, just as connection admission does.
pub(crate) fn access_enabled(path: &Path, consumer: &[u8; 32]) -> bool {
    state::policy(path, consumer).is_ok()
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Request {
    capability: [u8; 32],
    public_key: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    username: String,
    host_key: String,
}

async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    ensure!(bytes.len() <= 8192, "SSH setup frame too large");
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
async fn read_frame<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T> {
    let length = reader.read_u32().await? as usize;
    ensure!(length <= 8192, "SSH setup frame too large");
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) async fn serve(
    connection: iroh::endpoint::Connection,
    path: PathBuf,
    capability: CapabilitySecret,
    cancellation: CancellationToken,
    master_key: std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>,
) -> Result<()> {
    let result = serve_inner(&connection, &path, capability, cancellation, &master_key).await;
    connection.close(0u32.into(), b"SSH connection ended");
    result
}
async fn serve_inner(
    connection: &iroh::endpoint::Connection,
    path: &Path,
    capability: CapabilitySecret,
    cancellation: CancellationToken,
    master_key: &[u8; 32],
) -> Result<()> {
    // Endpoint hooks have already checked this identity; consent is checked again here,
    // and every second for the entire lifetime. No capability can register a key alone.
    let peer = connection.remote_id();
    let permission = state::policy(path, peer.as_bytes())?;
    let host_key = state::host_key(path, master_key)?;
    let (send, receive, public_key) = tokio::time::timeout(SETUP_TIMEOUT, async {
        let (mut send, mut receive) = connection.accept_bi().await?;
        let request: Request = read_frame(&mut receive).await?;
        ensure!(
            CapabilitySecret::from_bytes(request.capability) == capability,
            "SSH tunnel authentication denied"
        );
        let public_key = PublicKey::from_openssh(&request.public_key)?;
        ensure!(
            public_key.algorithm() == russh::keys::Algorithm::Ed25519,
            "only Ed25519 session keys are supported"
        );
        write_frame(
            &mut send,
            &Response {
                username: permission.username.clone(),
                host_key: host_key.public_key().to_openssh()?,
            },
        )
        .await?;
        Ok::<_, anyhow::Error>((send, receive, public_key))
    })
    .await
    .context("SSH tunnel setup timed out")??;
    let session_cancel = cancellation.child_token();
    let service = exec::serve_stream(
        tokio::io::join(receive, send),
        host_key,
        public_key,
        permission.clone(),
        session_cancel.clone(),
    );
    tokio::pin!(service);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            result = &mut service => return result,
            _ = cancellation.cancelled() => { session_cancel.cancel(); return service.await; }
            _ = tick.tick() => {
                if state::policy(path, peer.as_bytes()).ok().as_ref() != Some(&permission) {
                    session_cancel.cancel();
                    return service.await;
                }
            }
        }
    }
}

#[cfg(test)]
mod iroh_tests;
#[cfg(test)]
mod tests;
