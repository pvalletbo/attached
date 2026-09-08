use std::{future::Future, time::Duration};

use anyhow::{Context, Result};
use attached_tunnel_protocol::{
    CapabilitySecret, EVENTS_ALPN, HerdrVersion, authenticate_server, read_auth_response,
    write_auth_request,
};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, RecvStream},
};
use tokio::{io::AsyncReadExt, time::timeout};
use tokio_util::sync::CancellationToken;

use crate::session::Session;

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

pub struct EventConnection {
    connection: Connection,
}

impl Drop for EventConnection {
    fn drop(&mut self) {
        self.connection
            .close(0_u32.into(), b"event watcher disconnected");
    }
}

// A watcher uses an ephemeral transport identity so it can coexist with regular
// `attached attach` processes. Two endpoints using the same identity displace
// each other at Iroh relays. Prove the authorized consumer identity instead by
// signing fresh TLS-exported key material, scoped exclusively to this ALPN.
fn identity_proof_message(connection: &Connection) -> Result<Vec<u8>> {
    let mut material = [0u8; 32];
    connection
        .export_keying_material(&mut material, b"attached-events-consumer-v1", b"")
        .map_err(|_| anyhow::anyhow!("event channel binding is unavailable"))?;
    let mut message = b"attached/events/consumer-proof/v1\0".to_vec();
    message.extend_from_slice(&material);
    Ok(message)
}

pub(crate) async fn authorize_identity(
    connection: &Connection,
    authorized: &[u8; 32],
) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let (mut send, mut receive) = connection.accept_bi().await?;
        let mut signature = [0u8; 64];
        receive.read_exact(&mut signature).await?;
        iroh::PublicKey::from_bytes(authorized)?
            .verify(
                &identity_proof_message(connection)?,
                &iroh::Signature::from_bytes(&signature),
            )
            .context("event consumer identity proof rejected")?;
        send.write_all(&[0]).await?;
        send.finish()?;
        Ok(())
    })
    .await
    .context("event consumer identity proof timed out")?
}

pub async fn connect(
    endpoint: &Endpoint,
    identity: &iroh::SecretKey,
    address: EndpointAddr,
    session: &str,
    capability: &CapabilitySecret,
) -> Result<(EventConnection, RecvStream)> {
    timeout(SETUP_TIMEOUT, async {
        let connection = EventConnection { connection: endpoint.connect(address, EVENTS_ALPN).await.context("event tunnel unavailable; the serving host needs Attached with notification support")? };
        let (mut proof_send, mut proof_receive) = connection.connection.open_bi().await?;
        let signature = identity.sign(&identity_proof_message(&connection.connection)?);
        proof_send.write_all(&signature.to_bytes()).await?;
        proof_send.finish()?;
        anyhow::ensure!(proof_receive.read_u8().await? == 0, "event consumer identity rejected");
        let (mut send, mut receive) = connection.connection.open_bi().await?;
        // JSON API parsing is independent of the local Herdr TUI binary version.
        write_auth_request(&mut send, session, capability, None).await?;
        read_auth_response(&mut receive, None).await?;
        let events = connection.connection.accept_uni().await?;
        Ok((connection, events))
    }).await.context("event tunnel setup timed out")?
}

pub async fn serve<R, Fut, A, Admission>(
    connection: Connection,
    capability: &CapabilitySecret,
    version: HerdrVersion,
    cancellation: CancellationToken,
    resolve: R,
    admit: A,
) -> Result<()>
where
    R: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<Session>>,
    A: FnOnce() -> Result<Admission>,
{
    let guard = EventConnection { connection };
    let connection = &guard.connection;
    let operation = async {
        let (session, _admission) = timeout(SETUP_TIMEOUT, async {
            let (mut send, mut receive) = connection.accept_bi().await?;
            let result =
                authenticate_server(&mut receive, &mut send, capability, version, resolve, admit)
                    .await;
            if result.is_err() {
                let _ = timeout(Duration::from_secs(1), send.stopped()).await;
            }
            result
        })
        .await
        .context("event authentication timed out")??;
        // Open only the discovered session's API socket, only after authentication.
        // The sole application stream is server->client. No raw API access exists.
        let path = session.validated_api_socket()?;
        let mut send = connection.open_uni().await?;
        super::protocol::bridge(path, &mut send).await
    };
    tokio::select! {
        result = operation => result,
        _ = cancellation.cancelled() => Ok(()),
        _ = connection.closed() => Ok(()),
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
