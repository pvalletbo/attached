use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Current application tunnel protocol version.
pub const PROTOCOL_VERSION: u8 = 3;
/// ALPN used by the interactive-only Herdr tunnel protocol.
pub const TUNNEL_ALPN: &[u8] = b"herdr-tunnel/3";
/// Magic prefix for interactive stream headers.
const STREAM_MAGIC: [u8; 4] = *b"HDRS";
/// Magic prefix for authentication requests and responses.
const AUTH_MAGIC: [u8; 4] = *b"HDRA";
/// ALPN used only for authenticated, fixed-operation remote Herdr updates.
pub const UPGRADE_ALPN: &[u8] = b"herdr-upgrade/1";
const UPGRADE_MAGIC: [u8; 4] = *b"HDUP";
const MAX_UPGRADE_MESSAGE_LEN: usize = 512;

const MAX_SESSION_NAME_LEN: usize = 255;
const AUTH_OK: u8 = 0;
const AUTH_DENIED: u8 = 1;
const AUTH_INCOMPATIBLE_HERDR: u8 = 2;
const AUTH_UNSUPPORTED_TUNNEL: u8 = 3;
const AUTH_CAPACITY_EXHAUSTED: u8 = 4;
const MAX_VERSION_WIRE_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HerdrVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl HerdrVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u32 {
        self.major
    }

    pub const fn minor(self) -> u32 {
        self.minor
    }

    pub const fn patch(self) -> u32 {
        self.patch
    }
}

impl fmt::Display for HerdrVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn ensure_herdr_compatible(local: HerdrVersion, remote: HerdrVersion) -> Result<()> {
    if local != remote {
        bail!(
            "incompatible Herdr versions: local Herdr {local}, remote Herdr {remote}; versions must match exactly"
        );
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CapabilitySecret([u8; 32]);

impl CapabilitySecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn generate() -> Self {
        Self(iroh::SecretKey::generate().to_bytes())
    }
}

impl fmt::Debug for CapabilitySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilitySecret(REDACTED)")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct UpgradeRequest {
    pub session: String,
    pub requested_version: HerdrVersion,
}

#[derive(Debug, Eq, PartialEq)]
pub enum UpgradeResponse {
    Updated(HerdrVersion),
    Failed(String),
    Busy,
}

pub async fn write_upgrade_request<W>(
    writer: &mut W,
    session: &str,
    secret: &CapabilitySecret,
    requested_version: HerdrVersion,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    validate_session_name(session)?;
    writer.write_all(&UPGRADE_MAGIC).await?;
    writer.write_u8(1).await?;
    writer.write_u16(session.len() as u16).await?;
    writer.write_all(session.as_bytes()).await?;
    writer.write_all(&secret.0).await?;
    write_herdr_version(writer, Some(requested_version)).await?;
    writer.shutdown().await?;
    Ok(())
}

pub async fn read_upgrade_request<R>(
    reader: &mut R,
    expected_secret: &CapabilitySecret,
) -> Result<UpgradeRequest>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0; 4];
    reader.read_exact(&mut magic).await?;
    ensure!(magic == UPGRADE_MAGIC, "invalid upgrade request magic");
    ensure!(
        reader.read_u8().await? == 1,
        "unsupported upgrade protocol version"
    );
    let length = usize::from(reader.read_u16().await?);
    ensure!(
        length <= MAX_SESSION_NAME_LEN,
        "upgrade session name is too long"
    );
    let mut session = vec![0; length];
    reader.read_exact(&mut session).await?;
    let session = String::from_utf8(session).context("upgrade session name is not UTF-8")?;
    validate_session_name(&session)?;
    let mut supplied = [0; 32];
    reader.read_exact(&mut supplied).await?;
    ensure!(
        expected_secret == &CapabilitySecret(supplied),
        "upgrade authentication denied"
    );
    let requested_version = read_herdr_version(reader)
        .await?
        .context("upgrade request omitted the requested version")?;
    ensure_frame_end(reader, "upgrade request").await?;
    Ok(UpgradeRequest {
        session,
        requested_version,
    })
}

pub async fn write_upgrade_response<W>(writer: &mut W, response: UpgradeResponse) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&UPGRADE_MAGIC).await?;
    writer.write_u8(1).await?;
    match response {
        UpgradeResponse::Updated(version) => {
            writer.write_u8(0).await?;
            write_herdr_version(writer, Some(version)).await?;
        }
        UpgradeResponse::Failed(message) => {
            ensure!(
                message.len() <= MAX_UPGRADE_MESSAGE_LEN,
                "upgrade response is too long"
            );
            writer.write_u8(1).await?;
            writer.write_u16(message.len() as u16).await?;
            writer.write_all(message.as_bytes()).await?;
        }
        UpgradeResponse::Busy => writer.write_u8(2).await?,
    }
    writer.shutdown().await?;
    Ok(())
}

pub async fn read_upgrade_response<R>(reader: &mut R) -> Result<UpgradeResponse>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0; 4];
    reader.read_exact(&mut magic).await?;
    ensure!(magic == UPGRADE_MAGIC, "invalid upgrade response magic");
    ensure!(
        reader.read_u8().await? == 1,
        "unsupported upgrade protocol version"
    );
    let response = match reader.read_u8().await? {
        0 => UpgradeResponse::Updated(
            read_herdr_version(reader)
                .await?
                .context("upgrade response omitted installed version")?,
        ),
        1 => {
            let length = usize::from(reader.read_u16().await?);
            ensure!(
                length <= MAX_UPGRADE_MESSAGE_LEN,
                "upgrade response is too long"
            );
            let mut message = vec![0; length];
            reader.read_exact(&mut message).await?;
            UpgradeResponse::Failed(
                String::from_utf8(message).context("upgrade response is not UTF-8")?,
            )
        }
        2 => UpgradeResponse::Busy,
        status => bail!("unknown upgrade response status {status}"),
    };
    ensure_frame_end(reader, "upgrade response").await?;
    Ok(response)
}

async fn ensure_frame_end<R>(reader: &mut R, frame: &str) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut trailing = [0_u8; 1];
    ensure!(
        reader.read(&mut trailing).await? == 0,
        "trailing bytes after {frame}"
    );
    Ok(())
}

fn validate_session_name(session: &str) -> Result<()> {
    ensure!(!session.is_empty(), "session name cannot be empty");
    ensure!(
        session.len() <= MAX_SESSION_NAME_LEN,
        "session name is too long"
    );
    ensure!(
        !session.as_bytes().contains(&0),
        "session name contains NUL"
    );
    Ok(())
}

pub async fn write_stream_header<W>(writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[
            STREAM_MAGIC[0],
            STREAM_MAGIC[1],
            STREAM_MAGIC[2],
            STREAM_MAGIC[3],
            PROTOCOL_VERSION,
        ])
        .await
        .context("failed to write interactive stream header")
}

pub async fn read_stream_header<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 5];
    reader
        .read_exact(&mut header)
        .await
        .context("truncated interactive stream header")?;
    ensure!(header[..4] == STREAM_MAGIC, "invalid stream magic");
    ensure!(
        header[4] == PROTOCOL_VERSION,
        "unsupported tunnel protocol version {}",
        header[4]
    );
    Ok(())
}

pub async fn write_auth_request<W>(
    writer: &mut W,
    session: &str,
    secret: &CapabilitySecret,
    herdr_version: Option<HerdrVersion>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    validate_session_name(session)?;
    let length = u16::try_from(session.len()).expect("validated session length fits in u16");
    writer.write_all(&AUTH_MAGIC).await?;
    writer.write_u8(PROTOCOL_VERSION).await?;
    writer.write_u16(length).await?;
    writer.write_all(session.as_bytes()).await?;
    writer.write_all(&secret.0).await?;
    write_herdr_version(writer, herdr_version).await?;
    writer.shutdown().await?;
    Ok(())
}

struct AuthRequest {
    session: String,
    secret: CapabilitySecret,
    herdr_version: Option<HerdrVersion>,
}

async fn read_auth_preamble<R>(reader: &mut R) -> Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic).await?;
    ensure!(magic == AUTH_MAGIC, "invalid authentication magic");
    Ok(reader.read_u8().await?)
}

async fn read_auth_request_body<R>(reader: &mut R) -> Result<AuthRequest>
where
    R: AsyncRead + Unpin,
{
    let length = usize::from(reader.read_u16().await?);
    ensure!(
        length <= MAX_SESSION_NAME_LEN,
        "authentication session name is too long"
    );
    let mut session = vec![0_u8; length];
    reader.read_exact(&mut session).await?;
    let session = String::from_utf8(session).context("session name is not UTF-8")?;
    validate_session_name(&session)?;
    let mut secret = [0_u8; 32];
    reader.read_exact(&mut secret).await?;
    let herdr_version = read_herdr_version(reader).await?;
    Ok(AuthRequest {
        session,
        secret: CapabilitySecret(secret),
        herdr_version,
    })
}

async fn write_herdr_version<W>(writer: &mut W, version: Option<HerdrVersion>) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = postcard::to_stdvec(&version)?;
    ensure!(
        encoded.len() <= MAX_VERSION_WIRE_LEN,
        "Herdr version metadata is too long"
    );
    writer.write_u8(encoded.len() as u8).await?;
    writer.write_all(&encoded).await?;
    Ok(())
}

async fn read_herdr_version<R>(reader: &mut R) -> Result<Option<HerdrVersion>>
where
    R: AsyncRead + Unpin,
{
    let length = usize::from(reader.read_u8().await?);
    ensure!(
        length <= MAX_VERSION_WIRE_LEN,
        "Herdr version metadata is too long"
    );
    let mut encoded = vec![0_u8; length];
    reader.read_exact(&mut encoded).await?;
    postcard::from_bytes(&encoded).context("invalid Herdr version metadata")
}

async fn write_auth_response<W>(
    writer: &mut W,
    status: u8,
    herdr_version: HerdrVersion,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&AUTH_MAGIC).await?;
    writer.write_u8(PROTOCOL_VERSION).await?;
    writer.write_u8(status).await?;
    write_herdr_version(writer, Some(herdr_version)).await?;
    writer.shutdown().await?;
    Ok(())
}

/// Authenticates a host-wide capability, resolves its selected session before
/// acknowledging authentication, and finally applies the connection admission
/// limit. Resolution failures are denied without launching a client against a
/// session that disappeared after discovery.
pub async fn authenticate_server<R, W, Resolve, ResolveFuture, S, Admit, Admission>(
    reader: &mut R,
    writer: &mut W,
    expected_secret: &CapabilitySecret,
    server_herdr_version: HerdrVersion,
    resolve: Resolve,
    admit: Admit,
) -> Result<(S, Admission)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Resolve: FnOnce(String) -> ResolveFuture,
    ResolveFuture: std::future::Future<Output = Result<S>>,
    Admit: FnOnce() -> Result<Admission>,
{
    let version = read_auth_preamble(reader).await?;
    if version != PROTOCOL_VERSION {
        write_auth_response(writer, AUTH_UNSUPPORTED_TUNNEL, server_herdr_version).await?;
        bail!("unsupported tunnel protocol version {version}");
    }
    let request = read_auth_request_body(reader).await?;
    if expected_secret != &request.secret {
        write_auth_response(writer, AUTH_DENIED, server_herdr_version).await?;
        bail!("authentication denied");
    }
    if let Some(client_version) = request.herdr_version
        && let Err(error) = ensure_herdr_compatible(client_version, server_herdr_version)
    {
        write_auth_response(writer, AUTH_INCOMPATIBLE_HERDR, server_herdr_version).await?;
        return Err(error);
    }
    let session = match resolve(request.session).await {
        Ok(session) => session,
        Err(error) => {
            write_auth_response(writer, AUTH_DENIED, server_herdr_version).await?;
            return Err(error.context("requested session is unavailable"));
        }
    };
    let admission = match admit() {
        Ok(admission) => admission,
        Err(error) => {
            write_auth_response(writer, AUTH_CAPACITY_EXHAUSTED, server_herdr_version).await?;
            return Err(error.context("authenticated connection capacity exhausted"));
        }
    };
    write_auth_response(writer, AUTH_OK, server_herdr_version).await?;
    Ok((session, admission))
}

pub async fn read_auth_response<R>(
    reader: &mut R,
    local_herdr_version: Option<HerdrVersion>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut response = [0_u8; 6];
    reader
        .read_exact(&mut response)
        .await
        .context("truncated authentication response")?;
    ensure!(
        response[..4] == AUTH_MAGIC,
        "invalid authentication response"
    );
    ensure!(
        response[4] == PROTOCOL_VERSION,
        "server uses unsupported tunnel protocol version {}",
        response[4]
    );
    let remote_herdr_version = read_herdr_version(reader).await?;
    match response[5] {
        AUTH_OK => match (local_herdr_version, remote_herdr_version) {
            (Some(local), Some(remote)) => ensure_herdr_compatible(local, remote),
            _ => Ok(()),
        },
        AUTH_DENIED => bail!("server rejected tunnel authentication"),
        AUTH_INCOMPATIBLE_HERDR => match (local_herdr_version, remote_herdr_version) {
            (Some(local), Some(remote)) => {
                bail!("server rejected incompatible Herdr versions: local {local}, server {remote}")
            }
            _ => bail!("server rejected incompatible Herdr versions"),
        },
        AUTH_UNSUPPORTED_TUNNEL => bail!("server rejected an unsupported tunnel protocol version"),
        AUTH_CAPACITY_EXHAUSTED => {
            bail!("server rejected the connection because authenticated capacity is exhausted")
        }
        status => bail!("unknown authentication response status {status}"),
    }
}

#[cfg(test)]
mod tests;
