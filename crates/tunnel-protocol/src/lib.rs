pub mod ssh;

use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Account-authorized SSH service over Iroh.
pub const SSH_ALPN: &[u8] = b"attached-ssh/1";
/// ALPN used for authenticated Attached self-update handoffs.
pub const ATTACHED_UPDATE_ALPN: &[u8] = b"attached-update/2";
const ATTACHED_UPDATE_MAGIC: [u8; 4] = *b"ATUP";
const ATTACHED_UPDATE_PROTOCOL_VERSION: u8 = 2;
const MAX_ATTACHED_UPDATE_MESSAGE_LEN: usize = 512;
const UPDATE_OPERATION_ID_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AttachedVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl AttachedVersion {
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

impl fmt::Display for AttachedVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UpdateOperationId([u8; UPDATE_OPERATION_ID_BYTES]);

impl UpdateOperationId {
    pub const fn from_bytes(bytes: [u8; UPDATE_OPERATION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; UPDATE_OPERATION_ID_BYTES] {
        self.0
    }
}

impl fmt::Debug for UpdateOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "UpdateOperationId({self})")
    }
}

impl fmt::Display for UpdateOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
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
pub enum AttachedUpdateRequest {
    Start,
    Confirm {
        operation_id: UpdateOperationId,
        observed_version: AttachedVersion,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum AttachedUpdateResponse {
    Restarting {
        operation_id: UpdateOperationId,
        version: AttachedVersion,
        reconnect_timeout_secs: u16,
    },
    Committed(AttachedVersion),
    Current(AttachedVersion),
    Failed(String),
    Busy,
    Waiting,
}

pub async fn write_attached_update_start_request<W>(
    writer: &mut W,
    secret: &CapabilitySecret,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_attached_update_request_prefix(writer, 0, secret).await?;
    writer.shutdown().await?;
    Ok(())
}

pub async fn write_attached_update_confirm_request<W>(
    writer: &mut W,
    secret: &CapabilitySecret,
    operation_id: UpdateOperationId,
    observed_version: AttachedVersion,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_attached_update_request_prefix(writer, 1, secret).await?;
    writer.write_all(&operation_id.0).await?;
    write_attached_version(writer, observed_version).await?;
    writer.shutdown().await?;
    Ok(())
}

async fn write_attached_update_request_prefix<W>(
    writer: &mut W,
    operation: u8,
    secret: &CapabilitySecret,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&ATTACHED_UPDATE_MAGIC).await?;
    writer.write_u8(ATTACHED_UPDATE_PROTOCOL_VERSION).await?;
    writer.write_u8(operation).await?;
    writer.write_all(&secret.0).await?;
    Ok(())
}

pub async fn read_attached_update_request<R>(
    reader: &mut R,
    expected_secret: &CapabilitySecret,
) -> Result<AttachedUpdateRequest>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0; 4];
    reader.read_exact(&mut magic).await?;
    ensure!(
        magic == ATTACHED_UPDATE_MAGIC,
        "invalid Attached update request magic"
    );
    ensure!(
        reader.read_u8().await? == ATTACHED_UPDATE_PROTOCOL_VERSION,
        "unsupported Attached update protocol version"
    );
    let operation = reader.read_u8().await?;
    let mut supplied = [0; 32];
    reader.read_exact(&mut supplied).await?;
    ensure!(
        expected_secret == &CapabilitySecret(supplied),
        "Attached update authentication denied"
    );
    let request = match operation {
        0 => AttachedUpdateRequest::Start,
        1 => {
            let mut operation_id = [0; UPDATE_OPERATION_ID_BYTES];
            reader.read_exact(&mut operation_id).await?;
            AttachedUpdateRequest::Confirm {
                operation_id: UpdateOperationId(operation_id),
                observed_version: read_attached_version(reader).await?,
            }
        }
        operation => bail!("unknown Attached update operation {operation}"),
    };
    ensure_frame_end(reader, "Attached update request").await?;
    Ok(request)
}

pub async fn write_attached_update_response<W>(
    writer: &mut W,
    response: AttachedUpdateResponse,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&ATTACHED_UPDATE_MAGIC).await?;
    writer.write_u8(ATTACHED_UPDATE_PROTOCOL_VERSION).await?;
    match response {
        AttachedUpdateResponse::Restarting {
            operation_id,
            version,
            reconnect_timeout_secs,
        } => {
            writer.write_u8(0).await?;
            writer.write_all(&operation_id.0).await?;
            write_attached_version(writer, version).await?;
            writer.write_u16(reconnect_timeout_secs).await?;
        }
        AttachedUpdateResponse::Committed(version) => {
            writer.write_u8(1).await?;
            write_attached_version(writer, version).await?;
        }
        AttachedUpdateResponse::Current(version) => {
            writer.write_u8(2).await?;
            write_attached_version(writer, version).await?;
        }
        AttachedUpdateResponse::Failed(message) => {
            ensure!(
                message.len() <= MAX_ATTACHED_UPDATE_MESSAGE_LEN,
                "Attached update response is too long"
            );
            writer.write_u8(3).await?;
            writer.write_u16(message.len() as u16).await?;
            writer.write_all(message.as_bytes()).await?;
        }
        AttachedUpdateResponse::Busy => writer.write_u8(4).await?,
        AttachedUpdateResponse::Waiting => writer.write_u8(5).await?,
    }
    writer.shutdown().await?;
    Ok(())
}

pub async fn read_attached_update_response<R>(reader: &mut R) -> Result<AttachedUpdateResponse>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0; 4];
    reader.read_exact(&mut magic).await?;
    ensure!(
        magic == ATTACHED_UPDATE_MAGIC,
        "invalid Attached update response magic"
    );
    ensure!(
        reader.read_u8().await? == ATTACHED_UPDATE_PROTOCOL_VERSION,
        "unsupported Attached update protocol version"
    );
    let response = match reader.read_u8().await? {
        0 => {
            let mut operation_id = [0; UPDATE_OPERATION_ID_BYTES];
            reader.read_exact(&mut operation_id).await?;
            AttachedUpdateResponse::Restarting {
                operation_id: UpdateOperationId(operation_id),
                version: read_attached_version(reader).await?,
                reconnect_timeout_secs: reader.read_u16().await?,
            }
        }
        1 => AttachedUpdateResponse::Committed(read_attached_version(reader).await?),
        2 => AttachedUpdateResponse::Current(read_attached_version(reader).await?),
        3 => {
            let length = usize::from(reader.read_u16().await?);
            ensure!(
                length <= MAX_ATTACHED_UPDATE_MESSAGE_LEN,
                "Attached update response is too long"
            );
            let mut message = vec![0; length];
            reader.read_exact(&mut message).await?;
            AttachedUpdateResponse::Failed(
                String::from_utf8(message).context("Attached update response is not UTF-8")?,
            )
        }
        4 => AttachedUpdateResponse::Busy,
        5 => AttachedUpdateResponse::Waiting,
        status => bail!("unknown Attached update response status {status}"),
    };
    ensure_frame_end(reader, "Attached update response").await?;
    Ok(response)
}

async fn write_attached_version<W>(writer: &mut W, version: AttachedVersion) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u32(version.major).await?;
    writer.write_u32(version.minor).await?;
    writer.write_u32(version.patch).await?;
    Ok(())
}

async fn read_attached_version<R>(reader: &mut R) -> Result<AttachedVersion>
where
    R: AsyncRead + Unpin,
{
    Ok(AttachedVersion::new(
        reader.read_u32().await?,
        reader.read_u32().await?,
        reader.read_u32().await?,
    ))
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

#[cfg(test)]
mod tests;
