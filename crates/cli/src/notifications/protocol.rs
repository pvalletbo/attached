//! Read-only JSON API bridge for official Herdr 0.8.2 (not the binary TUI protocol).
//! Only Attached chooses API requests; the remote peer cannot send API commands.
use std::{collections::BTreeSet, path::Path, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::UnixStream,
    time::{MissedTickBehavior, interval, timeout},
};

pub const MAX_LINE: usize = 1024 * 1024;
const MAX_PANES: usize = 256;
const API_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Working,
    Blocked,
    Idle,
    Done,
    #[default]
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Pane {
    pub pane_id: String,
    #[serde(default)]
    pub terminal_id: Option<String>,
    pub workspace_id: String,
    pub agent_status: Status,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
}

impl Pane {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.pane_id.is_empty() && self.pane_id.len() <= 128,
            "invalid event pane ID"
        );
        ensure!(
            !self.workspace_id.is_empty() && self.workspace_id.len() <= 128,
            "invalid event workspace ID"
        );
        ensure!(
            self.terminal_id.as_ref().is_none_or(|s| s.len() <= 256),
            "event terminal ID exceeds limit"
        );
        ensure!(
            self.agent.as_ref().is_none_or(|s| s.len() <= 512),
            "event agent label exceeds limit"
        );
        ensure!(
            self.title.as_ref().is_none_or(|s| s.len() <= 1024),
            "event title exceeds limit"
        );
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    // The first snapshot is a baseline, never a notification. Subsequent snapshots
    // reconcile topology and recover state changes during subscription replacement.
    Snapshot { panes: Vec<Pane> },
    State { pane: Pane },
    Heartbeat,
}

pub fn decode_message(line: &[u8]) -> Result<Message> {
    ensure!(line.len() <= MAX_LINE, "event frame exceeds limit");
    let message: Message = serde_json::from_slice(line)?;
    if let Message::Snapshot { panes } = &message {
        ensure!(panes.len() <= MAX_PANES, "too many panes in event snapshot");
        ensure!(
            pane_ids(panes).len() == panes.len(),
            "duplicate pane in event snapshot"
        );
        for pane in panes {
            pane.validate()?;
        }
    } else if let Message::State { pane } = &message {
        pane.validate()?;
    }
    Ok(message)
}

// Keep partial lines in the reader, not in the next() future. Selecting a timer
// or shutdown while a frame is fragmented must not lose its prefix.
pub struct Lines<R> {
    reader: R,
    partial: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> Lines<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            partial: Vec::new(),
        }
    }

    pub async fn next(&mut self) -> Result<Vec<u8>> {
        loop {
            let available = self.reader.fill_buf().await?;
            ensure!(!available.is_empty(), "event stream ended");
            let newline = available.iter().position(|b| *b == b'\n');
            let count = newline.map_or(available.len(), |i| i + 1);
            ensure!(
                self.partial.len() + count <= MAX_LINE,
                "event frame exceeds limit"
            );
            self.partial.extend_from_slice(&available[..count]);
            self.reader.consume(count);
            if newline.is_some() {
                return Ok(std::mem::take(&mut self.partial));
            }
        }
    }
}

pub async fn write_message(
    writer: &mut (impl AsyncWrite + Unpin),
    message: &Message,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(message)?;
    ensure!(bytes.len() < MAX_LINE, "event frame exceeds limit");
    bytes.push(b'\n');
    timeout(API_TIMEOUT, writer.write_all(&bytes))
        .await
        .context("slow event consumer")??;
    Ok(())
}

async fn request(path: &Path, method: &str, params: Value) -> Result<Lines<BufReader<UnixStream>>> {
    let mut socket = UnixStream::connect(path)
        .await
        .context("Herdr API socket unavailable")?;
    let mut bytes =
        serde_json::to_vec(&json!({"id":"attached-events", "method":method, "params":params}))?;
    bytes.push(b'\n');
    socket.write_all(&bytes).await?;
    Ok(Lines::new(BufReader::new(socket)))
}

async fn response(lines: &mut Lines<BufReader<UnixStream>>) -> Result<Value> {
    let value: Value = serde_json::from_slice(&lines.next().await?)?;
    // Do not relay arbitrary error text, pane output, or other API responses.
    ensure!(
        value.get("error").is_none(),
        "Herdr rejected the read-only event request"
    );
    ensure!(
        value["id"] == "attached-events",
        "unexpected Herdr API response"
    );
    value
        .get("result")
        .cloned()
        .context("missing Herdr API result")
}

async fn list_panes(path: &Path) -> Result<Vec<Pane>> {
    timeout(API_TIMEOUT, async {
        let mut lines = request(path, "pane.list", json!({})).await?;
        let result = response(&mut lines).await?;
        let panes: Vec<Pane> = serde_json::from_value(result["panes"].clone())
            .context("unsupported Herdr pane.list response")?;
        ensure!(
            panes.len() <= MAX_PANES,
            "too many panes for event subscription (limit {MAX_PANES})"
        );
        for pane in &panes {
            pane.validate()?;
        }
        Ok(panes)
    })
    .await
    .context("Herdr pane discovery timed out")?
}

fn pane_ids(panes: &[Pane]) -> BTreeSet<String> {
    panes.iter().map(|pane| pane.pane_id.clone()).collect()
}

fn occupants(panes: &[Pane]) -> BTreeSet<(String, Option<String>)> {
    panes
        .iter()
        .map(|pane| (pane.pane_id.clone(), pane.terminal_id.clone()))
        .collect()
}

async fn subscribe(path: &Path, ids: &BTreeSet<String>) -> Result<Lines<BufReader<UnixStream>>> {
    timeout(API_TIMEOUT, async {
        // Herdr's status subscriptions are per-pane, not wildcard subscriptions.
        // Omitting agent_status disables the API's matching-current-state replay.
        let subscriptions: Vec<_> = ids
            .iter()
            .map(|id| {
                json!({
                    "type":"pane.agent_status_changed", "pane_id":id
                })
            })
            .collect();
        let mut lines = request(
            path,
            "events.subscribe",
            json!({"subscriptions":subscriptions}),
        )
        .await?;
        ensure!(
            response(&mut lines).await?["type"] == "subscription_started",
            "unsupported Herdr subscription response"
        );
        Ok(lines)
    })
    .await
    .context("Herdr subscription timed out")?
}

pub fn parse_event(line: &[u8]) -> Result<Pane> {
    let value: Value = serde_json::from_slice(line)?;
    ensure!(
        value["event"] == "pane.agent_status_changed",
        "unexpected Herdr event"
    );
    let pane: Pane =
        serde_json::from_value(value["data"].clone()).context("unsupported Herdr agent event")?;
    pane.validate()?;
    Ok(pane)
}

pub async fn bridge(path: &Path, writer: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
    let panes = list_panes(path).await?;
    let mut ids = pane_ids(&panes);
    let mut current_occupants = occupants(&panes);
    let mut subscription = subscribe(path, &ids).await?;
    write_message(writer, &Message::Snapshot { panes }).await?;
    let mut discovery = interval(Duration::from_secs(5));
    discovery.set_missed_tick_behavior(MissedTickBehavior::Skip);
    discovery.tick().await;
    loop {
        tokio::select! {
            line = subscription.next() => {
                let pane = parse_event(&line?)?;
                if !ids.contains(&pane.pane_id) { bail!("unexpected pane in event subscription"); }
                write_message(writer, &Message::State { pane }).await?;
            }
            _ = discovery.tick() => {
                let panes = list_panes(path).await?;
                let next_ids = pane_ids(&panes);
                let next_occupants = occupants(&panes);
                if current_occupants != next_occupants {
                    // New, closed, or moved panes require a new fixed subscription.
                    // No API/TUI control input ever comes from the tunnel.
                    subscription = subscribe(path, &next_ids).await?;
                    ids = next_ids;
                    current_occupants = next_occupants;
                    write_message(writer, &Message::Snapshot { panes }).await?;
                } else {
                    // A polling snapshot can be newer than queued live events.
                    // Do not interleave it with the live stream and regress state.
                    write_message(writer, &Message::Heartbeat).await?;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "official_herdr_tests.rs"]
mod official_herdr_tests;
