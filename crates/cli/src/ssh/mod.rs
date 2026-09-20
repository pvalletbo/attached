//! Account-authorized SSH over a versioned Iroh ALPN.
//! russh implements SSH; Attached implements the deliberately limited exec/shell service.
mod account;
mod client;
mod configuration;
mod descriptor;
mod exec;
mod export;
mod forward;
mod pty;
mod state;

use anyhow::{Context, Result, ensure};
use attached_tunnel_protocol::CapabilitySecret;
use attached_tunnel_protocol::ssh::{Request, Response, read_frame, write_frame};
use russh::keys::PublicKey;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub(crate) use attached_tunnel_protocol::SSH_ALPN as ALPN;
pub(crate) use client::{connect, local_proxy};
pub(crate) use export::export;
const SETUP_TIMEOUT: Duration = Duration::from_secs(20);

/// Serving a publish bundle enables SSH for its consumer as the effective OS account.
/// Invalid, missing, or inaccessible account credentials fail closed at admission too.
pub(crate) fn access_enabled(path: &Path, consumer: &[u8; 32]) -> bool {
    state::policy(path, consumer).is_ok()
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
    // Endpoint hooks have already checked this identity; authorization is checked again here,
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
                // Recheck credentials without spawning an OS directory lookup on every tick.
                if state::authorize(path, peer.as_bytes()).is_err()
                    || permission.uid != rustix::process::geteuid().as_raw()
                {
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
