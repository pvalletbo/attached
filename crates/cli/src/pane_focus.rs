//! One bounded, authenticated initial-focus request, not a generic API tunnel.
//! Herdr focus is shared session state. Never invoke this from the event watcher.
use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::UnixStream,
    time::timeout,
};

use crate::{notifications::protocol::Lines, session::Session};

const MAX_REQUEST: usize = 1024;
const API_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(clap::Args, Debug, Default)]
pub struct FocusArgs {
    /// Focus this pane on attachment (changes shared session focus).
    #[arg(long, requires = "target", allow_hyphen_values = true)]
    pub pane: Option<String>,
    /// Expected terminal occupant; stale notification clicks attach without focusing.
    #[arg(long, requires = "pane", hide = true, allow_hyphen_values = true)]
    pub pane_terminal: Option<String>,
}

impl FocusArgs {
    pub fn resolve(self) -> Result<Option<PaneFocus>> {
        self.pane
            .map(|pane_id| {
                let pane = PaneFocus {
                    pane_id,
                    terminal_id: self.pane_terminal,
                };
                pane.validate()?;
                Ok(pane)
            })
            .transpose()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaneFocus {
    pub pane_id: String,
    pub terminal_id: Option<String>,
}

impl PaneFocus {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.pane_id, 128)?;
        if let Some(id) = &self.terminal_id {
            validate_id(id, 256)?;
        }
        Ok(())
    }

    pub fn append_args(&self, args: &mut Vec<std::ffi::OsString>) {
        args.extend(["--pane".into(), self.pane_id.clone().into()]);
        if let Some(id) = &self.terminal_id {
            args.extend(["--pane-terminal".into(), id.into()]);
        }
    }
}

pub fn validate_id(id: &str, limit: usize) -> Result<()> {
    ensure!(
        !id.is_empty() && id.len() <= limit && !id.chars().any(char::is_control),
        "invalid pane routing identifier"
    );
    Ok(())
}

pub async fn write_request(writer: &mut (impl AsyncWrite + Unpin), pane: &PaneFocus) -> Result<()> {
    pane.validate()?;
    let bytes = serde_json::to_vec(pane)?;
    ensure!(
        bytes.len() <= MAX_REQUEST,
        "pane focus request exceeds limit"
    );
    writer.write_u16(bytes.len() as u16).await?;
    writer.write_all(&bytes).await?;
    Ok(())
}

async fn read_request(reader: &mut (impl AsyncRead + Unpin)) -> Result<PaneFocus> {
    let len = reader.read_u16().await? as usize;
    ensure!(len <= MAX_REQUEST, "pane focus request exceeds limit");
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    let pane: PaneFocus = serde_json::from_slice(&bytes)?;
    pane.validate()?;
    Ok(pane)
}

pub async fn read_result(reader: &mut (impl AsyncRead + Unpin)) -> Result<bool> {
    match reader.read_u8().await? {
        0 => Ok(true),
        1 => Ok(false),
        _ => anyhow::bail!("invalid pane focus response"),
    }
}

// Called only after identity/capability authentication on the focused-attach ALPN.
// Malformed requests fail closed. A missing/stale pane or unavailable API is a
// best-effort focus failure, not a reason to prevent an authenticated attachment.
pub async fn serve(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    session: &Session,
) -> Result<()> {
    let pane = read_request(reader).await?;
    let focused = match focus(session, &pane).await {
        Ok(focused) => focused,
        Err(error) => {
            tracing::warn!(%error, "initial pane focus unavailable; continuing attachment");
            false
        }
    };
    writer.write_u8(if focused { 0 } else { 1 }).await?;
    Ok(())
}

pub(crate) async fn focus(session: &Session, pane: &PaneFocus) -> Result<bool> {
    pane.validate()?;
    timeout(API_TIMEOUT, async {
        let path = session.validated_api_socket()?;
        let current = api(path, "pane.get", &pane.pane_id).await?;
        let current = &current["pane"];
        if current["pane_id"].as_str() != Some(&pane.pane_id)
            || pane
                .terminal_id
                .as_ref()
                .is_some_and(|expected| current["terminal_id"].as_str() != Some(expected.as_str()))
        {
            return Ok(false);
        }
        // Herdr selects the owning workspace/tab as part of pane.focus. Its API
        // has no atomic compare-and-focus operation: this is a best-effort stale
        // occupant guard, not a guarantee against concurrent pane replacement.
        let _ = api(path, "pane.focus", &pane.pane_id).await?;
        Ok(true)
    })
    .await
    .context("Herdr pane focus timed out")?
}

async fn api(path: &Path, method: &str, pane_id: &str) -> Result<Value> {
    let mut socket = UnixStream::connect(path).await?;
    let mut bytes = serde_json::to_vec(&json!({
        "id": "attached-focus", "method": method, "params": {"pane_id": pane_id}
    }))?;
    bytes.push(b'\n');
    socket.write_all(&bytes).await?;
    let response: Value =
        serde_json::from_slice(&Lines::new(BufReader::new(socket)).next().await?)?;
    ensure!(
        response["id"] == "attached-focus",
        "unexpected pane focus API response"
    );
    ensure!(
        response.get("error").is_none(),
        "Herdr rejected the pane focus request"
    );
    response
        .get("result")
        .cloned()
        .context("missing pane focus API result")
}

#[cfg(test)]
#[path = "pane_focus_tests.rs"]
mod tests;
