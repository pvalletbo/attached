//! Private, bounded IPC for the one network broker per OS user/consumer identity.
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
};

pub(super) const VERSION: u8 = 1;
pub(super) const MAX_FRAME: usize = 16 * 1024;
pub(super) type Token = [u8; 16];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub version: u8,
    pub operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub(super) enum Operation {
    Lease {
        identity: EndpointId,
    },
    Connect {
        lease: Token,
        address: EndpointAddr,
        alpn: Vec<u8>,
    },
    Open {
        lease: Token,
        connection: Token,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", deny_unknown_fields)]
pub(super) enum Response {
    Lease {
        identity: EndpointId,
        lease: Token,
        pid: u32,
    },
    Connected {
        connection: Token,
    },
    Open,
    Error {
        message: String,
    },
}

pub(super) fn runtime(identity: EndpointId) -> Result<PathBuf> {
    // Deliberately independent of HOME, config_directory, and TMPDIR: two copies
    // of the same consumer key must never create competing relay registrations.
    Ok(std::fs::canonicalize("/tmp")?
        .join(format!(
            "attached-client-{}",
            rustix::process::geteuid().as_raw()
        ))
        .join(identity.to_string()))
}

pub(super) fn directory(path: &Path) -> Result<crate::secure_state::StateDir> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("broker runtime has no private parent"))?;
    let _parent = crate::secure_state::StateDir::open(parent)?;
    crate::secure_state::StateDir::open(path)
}

pub(super) fn socket(path: &Path) -> PathBuf {
    path.join("s")
}

pub(super) fn check_peer(stream: &UnixStream) -> Result<()> {
    ensure!(
        stream.peer_cred()?.uid() == rustix::process::geteuid().as_raw(),
        "local Attached broker belongs to another OS user"
    );
    Ok(())
}

pub(super) fn token() -> Result<Token> {
    let mut token = [0; 16];
    getrandom::fill(&mut token)?;
    Ok(token)
}

pub(super) async fn write<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_FRAME, "local broker frame too large");
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub(super) async fn read<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let length = reader.read_u32().await? as usize;
    ensure!(length <= MAX_FRAME, "local broker frame too large");
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) async fn request(stream: &mut UnixStream, operation: Operation) -> Result<Response> {
    check_peer(stream)?;
    write(
        stream,
        &Request {
            version: VERSION,
            operation,
        },
    )
    .await?;
    let response = read(stream).await?;
    if let Response::Error { message } = response {
        anyhow::bail!("local Attached broker: {message}");
    }
    Ok(response)
}
