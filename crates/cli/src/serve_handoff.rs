use std::{
    net::SocketAddr,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use attached_tunnel_protocol::{AttachedVersion, UpdateOperationId};
use rustix::process::{Pid, Signal, kill_process_group};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{mpsc, watch},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize as _;

pub(crate) const INTERNAL_COMMAND: &str = "__handoff-serve";
const MAX_IPC_MESSAGE_BYTES: usize = 16 * 1024;
const CANDIDATE_PREPARE_TIMEOUT: Duration = Duration::from_secs(10);
const CANDIDATE_EXIT_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServeConfig {
    pub(crate) state_dir: PathBuf,
    pub(crate) herdr_bin: PathBuf,
    pub(crate) host_label: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateConfig {
    pub(crate) serve: ServeConfig,
    pub(crate) operation_id: UpdateOperationId,
    pub(crate) session: String,
    pub(crate) expected_version: AttachedVersion,
    pub(crate) expected_endpoint_identity: [u8; 32],
    pub(crate) capability: [u8; 32],
    pub(crate) master_key: [u8; 32],
    pub(crate) bind_sockets: Vec<SocketAddr>,
}

impl Drop for CandidateConfig {
    fn drop(&mut self) {
        self.capability.zeroize();
        self.master_key.zeroize();
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ParentCommand {
    Activate,
    Commit,
    Abort,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum CandidateEvent {
    Prepared { version: AttachedVersion },
    Ready { version: AttachedVersion },
    ConsumerConnected,
    ClientSucceeded,
    Failed { reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateDisposition {
    Pending,
    Committed,
    Aborted,
}

pub(crate) struct CandidateProcess {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    terminate_on_drop: bool,
}

impl CandidateProcess {
    pub(crate) async fn spawn(executable: &Path, config: &CandidateConfig) -> Result<Self> {
        let mut command = Command::new(executable);
        command
            .arg(INTERNAL_COMMAND)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        command.as_std_mut().process_group(0);
        let mut child = command.spawn().with_context(|| {
            format!(
                "could not start updated Attached candidate {}",
                executable.display()
            )
        })?;
        let input = child
            .stdin
            .take()
            .context("could not open candidate control input")?;
        let output = child
            .stdout
            .take()
            .context("could not open candidate control output")?;
        let mut candidate = Self {
            child,
            input,
            output: BufReader::new(output),
            terminate_on_drop: true,
        };
        if let Err(error) = candidate.write(config).await {
            candidate.abort().await;
            return Err(error.context("could not send candidate handoff configuration"));
        }
        let event = match timeout(CANDIDATE_PREPARE_TIMEOUT, candidate.next_event()).await {
            Ok(Ok(event)) => event,
            Ok(Err(error)) => {
                candidate.abort().await;
                return Err(error.context("updated Attached candidate did not prepare"));
            }
            Err(error) => {
                candidate.abort().await;
                return Err(error).context("updated Attached candidate preparation timed out");
            }
        };
        match event {
            CandidateEvent::Prepared { version } if version == config.expected_version => {
                Ok(candidate)
            }
            CandidateEvent::Prepared { version } => {
                candidate.abort().await;
                bail!(
                    "updated Attached candidate reported version {version}, expected {}",
                    config.expected_version
                )
            }
            CandidateEvent::Failed { reason } => {
                candidate.abort().await;
                bail!("updated Attached candidate preparation failed: {reason}")
            }
            event => {
                candidate.abort().await;
                bail!("updated Attached candidate sent unexpected event {event:?}")
            }
        }
    }

    pub(crate) async fn send(&mut self, command: &ParentCommand) -> Result<()> {
        self.write(command).await
    }

    pub(crate) async fn next_event(&mut self) -> Result<CandidateEvent> {
        read_message(&mut self.output)
            .await?
            .context("updated Attached candidate closed its control channel")
    }

    async fn write<T: Serialize>(&mut self, message: &T) -> Result<()> {
        write_message(&mut self.input, message).await
    }

    pub(crate) async fn abort(&mut self) {
        let _ = self.send(&ParentCommand::Abort).await;
        if !matches!(
            timeout(CANDIDATE_EXIT_GRACE, self.child.wait()).await,
            Ok(Ok(_))
        ) {
            if let Some(id) = self.child.id() {
                crate::bounded_process::terminate_process_group(id);
            }
            let _ = self.child.start_kill();
            let _ = self.child.wait().await;
        }
        self.terminate_on_drop = self.child.id().is_some();
    }

    pub(crate) async fn supervise(mut self) -> Result<ExitStatus> {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("could not listen for termination while supervising updated Attached")?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .context("could not listen for terminal closure while supervising updated Attached")?;
        let signal = tokio::select! {
            status = self.child.wait() => {
                self.terminate_on_drop = self.child.id().is_some();
                return status.context("could not wait for updated Attached");
            }
            result = tokio::signal::ctrl_c() => {
                result.context("could not listen for interruption while supervising updated Attached")?;
                Signal::INT
            }
            _ = terminate.recv() => Signal::TERM,
            _ = hangup.recv() => Signal::HUP,
        };
        if let Some(id) = self.child.id() {
            signal_process_group(id, signal);
        }
        let status = match timeout(CANDIDATE_EXIT_GRACE, self.child.wait()).await {
            Ok(status) => status.context("could not wait for updated Attached after signalling it"),
            Err(_) => {
                if let Some(id) = self.child.id() {
                    crate::bounded_process::terminate_process_group(id);
                }
                let _ = self.child.start_kill();
                self.child
                    .wait()
                    .await
                    .context("could not reap updated Attached after signalling it")
            }
        };
        self.terminate_on_drop = self.child.id().is_some();
        status
    }
}

impl Drop for CandidateProcess {
    fn drop(&mut self) {
        if self.terminate_on_drop {
            if let Some(id) = self.child.id() {
                crate::bounded_process::terminate_process_group(id);
            }
            let _ = self.child.start_kill();
        }
    }
}

fn signal_process_group(child_id: u32, signal: Signal) {
    let Ok(raw_pid) = i32::try_from(child_id) else {
        return;
    };
    let Some(process_group) = Pid::from_raw(raw_pid) else {
        return;
    };
    let _ = kill_process_group(process_group, signal);
}

pub(crate) struct CandidateIpc {
    input: BufReader<tokio::io::Stdin>,
    events: mpsc::UnboundedSender<CandidateEvent>,
}

pub(crate) struct ActivatedCandidateIpc {
    pub(crate) events: mpsc::UnboundedSender<CandidateEvent>,
    pub(crate) disposition: watch::Receiver<CandidateDisposition>,
    pub(crate) abort: CancellationToken,
}

impl CandidateIpc {
    pub(crate) async fn receive() -> Result<(CandidateConfig, Self)> {
        let mut input = BufReader::new(tokio::io::stdin());
        let config = read_message(&mut input)
            .await?
            .context("candidate handoff configuration is missing")?;
        let (events, mut queued_events) = mpsc::unbounded_channel::<CandidateEvent>();
        tokio::spawn(async move {
            let mut output = tokio::io::stdout();
            while let Some(event) = queued_events.recv().await {
                if write_message(&mut output, &event).await.is_err() {
                    return;
                }
            }
        });
        Ok((config, Self { input, events }))
    }

    pub(crate) fn send(&self, event: CandidateEvent) -> Result<()> {
        self.events
            .send(event)
            .map_err(|_| anyhow::anyhow!("candidate event channel is unavailable"))
    }

    pub(crate) async fn activate(mut self) -> Result<ActivatedCandidateIpc> {
        match read_message::<_, ParentCommand>(&mut self.input)
            .await?
            .context("candidate activation command is missing")?
        {
            ParentCommand::Activate => {}
            ParentCommand::Abort => bail!("candidate handoff was aborted before activation"),
            ParentCommand::Commit => bail!("candidate received commit before activation"),
        }

        let (disposition_tx, disposition) = watch::channel(CandidateDisposition::Pending);
        let abort = CancellationToken::new();
        let reader_abort = abort.clone();
        tokio::spawn(async move {
            let command = read_message::<_, ParentCommand>(&mut self.input).await;
            match command {
                Ok(Some(ParentCommand::Commit)) => {
                    disposition_tx.send_replace(CandidateDisposition::Committed);
                }
                Ok(Some(ParentCommand::Abort))
                | Ok(None)
                | Err(_)
                | Ok(Some(ParentCommand::Activate)) => {
                    disposition_tx.send_replace(CandidateDisposition::Aborted);
                    reader_abort.cancel();
                }
            }
        });
        Ok(ActivatedCandidateIpc {
            events: self.events,
            disposition,
            abort,
        })
    }
}

async fn write_message<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    let mut encoded =
        serde_json::to_vec(message).context("could not encode handoff IPC message")?;
    ensure!(
        encoded.len() <= MAX_IPC_MESSAGE_BYTES,
        "handoff IPC message is too large"
    );
    encoded.push(b'\n');
    writer
        .write_all(&encoded)
        .await
        .context("could not write handoff IPC message")?;
    writer
        .flush()
        .await
        .context("could not flush handoff IPC message")
}

async fn read_message<R, T>(reader: &mut R) -> Result<Option<T>>
where
    R: tokio::io::AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    let mut encoded = Vec::new();
    let read = reader
        .read_until(b'\n', &mut encoded)
        .await
        .context("could not read handoff IPC message")?;
    if read == 0 {
        return Ok(None);
    }
    ensure!(
        encoded.len() <= MAX_IPC_MESSAGE_BYTES + 1,
        "handoff IPC message is too large"
    );
    ensure!(
        encoded.last() == Some(&b'\n'),
        "truncated handoff IPC message"
    );
    encoded.pop();
    serde_json::from_slice(&encoded)
        .context("could not decode handoff IPC message")
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn candidate_process_uses_private_ipc_for_the_handoff() {
        use std::{fs, os::unix::fs::PermissionsExt as _};

        let root = crate::test_support::canonical_tempdir();
        let executable = root.path().join("attached");
        let arguments = root.path().join("arguments");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > '{}'\nIFS= read -r config\nprintf '%s\\n' '{{\"type\":\"prepared\",\"version\":{{\"major\":9,\"minor\":8,\"patch\":7}}}}'\nIFS= read -r activate\nprintf '%s\\n' '{{\"type\":\"ready\",\"version\":{{\"major\":9,\"minor\":8,\"patch\":7}}}}' '{{\"type\":\"consumer_connected\"}}'\nIFS= read -r commit\nprintf '%s\\n' '{{\"type\":\"client_succeeded\"}}'\n",
                arguments.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let config = CandidateConfig {
            serve: ServeConfig {
                state_dir: root.path().join("state"),
                herdr_bin: PathBuf::from("herdr"),
                host_label: "office".to_owned(),
            },
            operation_id: UpdateOperationId::from_bytes([0x41; 16]),
            session: "work".to_owned(),
            expected_version: AttachedVersion::new(9, 8, 7),
            expected_endpoint_identity: [0x51; 32],
            capability: [0x61; 32],
            master_key: [0x71; 32],
            bind_sockets: vec!["127.0.0.1:4242".parse().unwrap()],
        };

        let mut candidate = CandidateProcess::spawn(&executable, &config).await.unwrap();
        assert_eq!(
            fs::read_to_string(arguments).unwrap(),
            format!("{}\n", INTERNAL_COMMAND)
        );
        candidate.send(&ParentCommand::Activate).await.unwrap();
        assert_eq!(
            candidate.next_event().await.unwrap(),
            CandidateEvent::Ready {
                version: AttachedVersion::new(9, 8, 7)
            }
        );
        assert_eq!(
            candidate.next_event().await.unwrap(),
            CandidateEvent::ConsumerConnected
        );
        candidate.send(&ParentCommand::Commit).await.unwrap();
        assert_eq!(
            candidate.next_event().await.unwrap(),
            CandidateEvent::ClientSucceeded
        );
        assert!(candidate.supervise().await.unwrap().success());
    }

    #[tokio::test]
    async fn ipc_messages_are_line_framed_and_bounded() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        let writing = write_message(&mut writer, &ParentCommand::Activate);
        let reading = read_message::<_, ParentCommand>(&mut reader);
        let ((), decoded) = tokio::try_join!(writing, reading).unwrap();
        assert!(matches!(decoded, Some(ParentCommand::Activate)));

        let oversized = "x".repeat(MAX_IPC_MESSAGE_BYTES + 1);
        assert!(
            write_message(&mut tokio::io::sink(), &oversized)
                .await
                .unwrap_err()
                .to_string()
                .contains("too large")
        );
    }
}
