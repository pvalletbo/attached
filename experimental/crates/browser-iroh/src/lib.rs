//! Browser-facing Iroh transport for synchronized Herdr sessions.

use std::{
    future::Future,
    str::FromStr as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use attached_tunnel_protocol::{
    CapabilitySecret, TUNNEL_ALPN, read_auth_response, write_auth_request, write_stream_header,
};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use iroh_tickets::endpoint::EndpointTicket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

/// Maximum opaque Herdr payload returned to JavaScript by one receive call.
const MAX_RECEIVE_CHUNK: usize = 64 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns a stable operation failure that cannot contain internal context.
fn sanitize_error(operation: &str) -> String {
    match operation {
        "connect" => "unable to connect to the Herdr tunnel".to_owned(),
        "send" => "unable to send Herdr tunnel data".to_owned(),
        "receive" => "unable to receive Herdr tunnel data".to_owned(),
        _ => "Herdr tunnel operation failed".to_owned(),
    }
}

struct TunnelInner {
    endpoint: Endpoint,
    connection: Connection,
    send: Mutex<Option<SendStream>>,
    receive: Mutex<Option<RecvStream>>,
    closed: AtomicBool,
}

/// An authenticated TUI stream over an Iroh connection.
#[derive(Clone)]
struct Tunnel {
    inner: Arc<TunnelInner>,
}

impl Tunnel {
    /// Sends opaque Herdr protocol bytes over the authenticated TUI stream.
    async fn send(&self, bytes: &[u8]) -> Result<(), String> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err("tunnel is closed".to_owned());
        }
        let mut guard = self.inner.send.lock().await;
        let send = guard
            .as_mut()
            .ok_or_else(|| "tunnel send stream is closed".to_owned())?;
        send.write_all(bytes)
            .await
            .map_err(|error| error.to_string())
    }

    /// Receives one bounded chunk of opaque Herdr protocol bytes.
    async fn receive(&self) -> Result<Option<Vec<u8>>, String> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Ok(None);
        }
        let mut guard = self.inner.receive.lock().await;
        let receive = guard
            .as_mut()
            .ok_or_else(|| "tunnel receive stream is closed".to_owned())?;
        receive
            .read_chunk(MAX_RECEIVE_CHUNK)
            .await
            .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
            .map_err(|error| error.to_string())
    }

    /// Closes the TUI stream, Iroh connection, and endpoint once.
    async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner
            .connection
            .close(0_u32.into(), b"browser client closed");
        if let Some(mut send) = self.inner.send.lock().await.take() {
            let _ = send.finish();
        }
        self.inner.receive.lock().await.take();
        self.inner.endpoint.close().await;
    }
}

async fn connect_tunnel_controlled(
    endpoint_addr: EndpointAddr,
    consumer_identity_secret: Zeroizing<[u8; 32]>,
    session: String,
    capability: CapabilitySecret,
    cancellation: CancellationToken,
) -> Result<Tunnel, String> {
    connect_with_controls(
        CONNECTION_TIMEOUT,
        cancellation,
        connect_tunnel_inner(endpoint_addr, consumer_identity_secret, session, capability),
    )
    .await
}

async fn connect_with_controls<T, F>(
    duration: Duration,
    cancellation: CancellationToken,
    future: F,
) -> Result<T, String>
where
    F: Future<Output = Result<T, String>>,
{
    tokio::select! {
        result = n0_future::time::timeout(duration, future) => {
            result.map_err(|_| "connection timed out".to_owned())?
        }
        () = cancellation.cancelled() => Err("connection cancelled".to_owned()),
    }
}

async fn connect_tunnel_inner(
    endpoint_addr: EndpointAddr,
    consumer_identity_secret: Zeroizing<[u8; 32]>,
    session: String,
    capability: CapabilitySecret,
) -> Result<Tunnel, String> {
    let endpoint = bind_client_endpoint(&consumer_identity_secret).await?;
    let connection = endpoint
        .connect(endpoint_addr, TUNNEL_ALPN)
        .await
        .map_err(|error| error.to_string())?;

    let (mut auth_send, mut auth_receive) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    write_auth_request(&mut auth_send, &session, &capability, None)
        .await
        .map_err(|error| error.to_string())?;
    read_auth_response(&mut auth_receive, None)
        .await
        .map_err(|error| error.to_string())?;

    let (mut send, receive) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    write_stream_header(&mut send)
        .await
        .map_err(|error| error.to_string())?;

    Ok(Tunnel {
        inner: Arc::new(TunnelInner {
            endpoint,
            connection,
            send: Mutex::new(Some(send)),
            receive: Mutex::new(Some(receive)),
            closed: AtomicBool::new(false),
        }),
    })
}

async fn bind_client_endpoint(consumer_identity_secret: &[u8; 32]) -> Result<Endpoint, String> {
    Endpoint::builder(presets::N0)
        .secret_key(iroh::SecretKey::from_bytes(consumer_identity_secret))
        .bind()
        .await
        .map_err(|_| "unable to bind the provisioned consumer identity".to_owned())
}

type ParsedTarget = (EndpointAddr, Zeroizing<[u8; 32]>, String, CapabilitySecret);

fn parse_target(
    endpoint_ticket: &str,
    session: String,
    capability_source: &mut Zeroizing<Vec<u8>>,
    mut consumer_identity_secret: Zeroizing<Vec<u8>>,
) -> Result<ParsedTarget, String> {
    let capability: Result<[u8; 32], _> = capability_source.as_slice().try_into();
    capability_source.zeroize();
    let capability = CapabilitySecret::from_bytes(
        capability.map_err(|_| "invalid tunnel capability".to_owned())?,
    );
    let endpoint = EndpointTicket::from_str(endpoint_ticket).map_err(|error| error.to_string())?;
    let consumer_identity_secret = parse_consumer_identity(&mut consumer_identity_secret)?;
    Ok((
        endpoint.endpoint_addr().clone(),
        consumer_identity_secret,
        session,
        capability,
    ))
}

fn parse_consumer_identity(input: &mut Vec<u8>) -> Result<Zeroizing<[u8; 32]>, String> {
    let parsed: Result<[u8; 32], _> = input.as_slice().try_into();
    input.zeroize();
    parsed
        .map(Zeroizing::new)
        .map_err(|_| "invalid consumer identity".to_owned())
}

/// JavaScript-facing owner of an authenticated browser Iroh tunnel.
#[wasm_bindgen]
pub struct BrowserTunnel {
    tunnel: Tunnel,
}

/// Cancellable owner of one in-progress browser connection attempt.
#[wasm_bindgen]
pub struct BrowserConnector {
    cancellation: CancellationToken,
}

impl Default for BrowserConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl BrowserConnector {
    #[wasm_bindgen(constructor)]
    pub fn new() -> BrowserConnector {
        Self {
            cancellation: CancellationToken::new(),
        }
    }

    /// Establishes a tunnel using a verified synchronized catalog entry.
    pub async fn connect(
        &self,
        endpoint_ticket: String,
        session: String,
        capability: Vec<u8>,
        consumer_identity_secret: Vec<u8>,
    ) -> Result<BrowserTunnel, JsValue> {
        let mut capability = Zeroizing::new(capability);
        let consumer_identity_secret = Zeroizing::new(consumer_identity_secret);
        let (endpoint_addr, consumer_identity_secret, session, capability) = parse_target(
            &endpoint_ticket,
            session,
            &mut capability,
            consumer_identity_secret,
        )
        .map_err(|_| JsValue::from_str(&sanitize_error("connect")))?;
        let tunnel = connect_tunnel_controlled(
            endpoint_addr,
            consumer_identity_secret,
            session,
            capability,
            self.cancellation.clone(),
        )
        .await
        .map_err(|_| JsValue::from_str(&sanitize_error("connect")))?;
        Ok(BrowserTunnel { tunnel })
    }

    /// Cancels a pending connection attempt. Calling this repeatedly is safe.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
}

#[wasm_bindgen]
impl BrowserTunnel {
    /// Sends opaque Herdr protocol bytes.
    pub async fn send(&self, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.tunnel
            .send(&bytes)
            .await
            .map_err(|_| JsValue::from_str(&sanitize_error("send")))
    }

    /// Receives one bounded opaque chunk, or `undefined` after EOF.
    pub async fn receive(&self) -> Result<Option<Vec<u8>>, JsValue> {
        self.tunnel
            .receive()
            .await
            .map_err(|_| JsValue::from_str(&sanitize_error("receive")))
    }

    /// Closes all transport resources. Calling this more than once is safe.
    pub async fn close(&self) {
        self.tunnel.close().await;
    }
}

#[cfg(test)]
mod tests;
