//! Authenticate without opening a shell/channel, changing host trust, or using OpenSSH.
use std::{path::Path, str::FromStr, sync::Arc};

use iroh_tickets::endpoint::EndpointTicket;
use russh::keys::{PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use serde::Serialize;

use super::{ALPN, Request, Response, client::canonical_host_key, read_frame, state, write_frame};
use crate::{
    client_ipc::ConnectionInfo,
    client_transport::{ClientEndpoint, Connection},
    sync::{self, state_catalog::HostConnection},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbeFailure {
    Unreachable,
    AccessDenied,
    IdentityMismatch,
    AuthenticationFailed,
    TimedOut,
    Unavailable,
}

impl ProbeFailure {
    pub(crate) fn advice(self) -> &'static str {
        match self {
            Self::Unreachable => {
                "Check that attached serve is running and the publisher can reach the network."
            }
            Self::AccessDenied => {
                "Publisher rejected tunnel setup; verify its publish bundle and restart attached serve."
            }
            Self::IdentityMismatch => {
                "SSH identity differs from existing trust; independently verify the publisher before using attached ssh --trust-new-host-key."
            }
            Self::AuthenticationFailed => {
                "SSH authentication failed; check the publisher's OS account and Attached version."
            }
            Self::TimedOut => {
                "Live probe timed out; check publisher connectivity or increase --timeout."
            }
            Self::Unavailable => {
                "Descriptor, broker, or local trust store is unavailable; check local state ownership and resolve failed checks."
            }
        }
    }
}

struct CloseOnDrop(Connection);
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"diagnostic probe ended");
    }
}

struct VerifyHost(PublicKey);
impl russh::client::Handler for VerifyHost {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(key.public_key().key_data() == self.0.key_data())
    }
}

pub(crate) async fn probe(
    endpoint: &ClientEndpoint,
    path: &Path,
    host: &HostConnection,
) -> Result<ConnectionInfo, ProbeFailure> {
    use ProbeFailure::*;
    if sync::utc_now_seconds() >= host.expires_at {
        return Err(Unavailable);
    }
    let ticket = EndpointTicket::from_str(&host.endpoint_ticket).map_err(|_| Unavailable)?;
    if ticket.endpoint_addr().id.as_bytes() != &host.endpoint_identity {
        return Err(IdentityMismatch);
    }
    let connection = CloseOnDrop(
        endpoint
            .connect(ticket.endpoint_addr().clone(), ALPN)
            .await
            .map_err(|_| Unreachable)?,
    );
    let key = state::ephemeral_key().map_err(|_| AuthenticationFailed)?;
    let (mut send, mut receive) = connection.0.open_bi().await.map_err(|_| AccessDenied)?;
    write_frame(
        &mut send,
        &Request {
            capability: host.attach_capability,
            public_key: key
                .public_key()
                .to_openssh()
                .map_err(|_| AuthenticationFailed)?,
        },
    )
    .await
    .map_err(|_| AccessDenied)?;
    let response: Response = read_frame(&mut receive).await.map_err(|_| AccessDenied)?;
    let host_key = canonical_host_key(&response.host_key).map_err(|_| IdentityMismatch)?;
    if !state::check_host_pin(
        path,
        &connection.0.remote_id(),
        &response.username,
        &host_key,
    )
    .map_err(|_| Unavailable)?
    {
        return Err(IdentityMismatch);
    }
    let expected = PublicKey::from_openssh(&host_key).map_err(|_| IdentityMismatch)?;
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        tokio::io::join(receive, send),
        VerifyHost(expected),
    )
    .await
    .map_err(|_| AuthenticationFailed)?;
    if !client
        .authenticate_publickey(
            response.username,
            PrivateKeyWithHashAlg::new(Arc::new(key), None),
        )
        .await
        .map_err(|_| AuthenticationFailed)?
        .success()
    {
        return Err(AuthenticationFailed);
    }
    let info = connection.0.info().await.map_err(|_| Unavailable)?;
    let _ = client
        .disconnect(russh::Disconnect::ByApplication, "diagnostic complete", "")
        .await;
    Ok(info)
}
