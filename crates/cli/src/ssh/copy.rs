//! A name-resolving wrapper around OpenSSH's SFTP-mode scp client.
use std::{path::Path, process::Stdio};

use anyhow::{Context, Result, ensure};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

#[derive(Debug, PartialEq, Eq)]
enum Operand {
    Local(String),
    Remote { target: String, path: String },
}

impl Operand {
    fn parse(value: &str) -> Result<Self> {
        ensure!(
            !value.is_empty() && !value.contains('\0'),
            "copy operands must be nonempty and contain no NUL"
        );
        // Like scp, a slash before a colon disambiguates a local path. Use
        // './file:name' when a local filename contains a colon.
        if let Some((target, path)) = value.split_once(':')
            && !target.contains('/')
        {
            ensure!(
                !target.is_empty() && !path.is_empty(),
                "remote operands must be HOST:PATH"
            );
            Ok(Self::Remote {
                target: target.into(),
                path: path.into(),
            })
        } else {
            Ok(Self::Local(value.into()))
        }
    }

    fn argument(&self, alias: &str, source: bool) -> String {
        match self {
            Self::Local(path) if Path::new(path).is_absolute() => path.clone(),
            Self::Local(path) => format!("./{path}"),
            Self::Remote { path, .. } => {
                // scp performs remote source globbing even without a shell.
                // cp operands are literal: escape glob metacharacters so a
                // quoted filename cannot accidentally copy unrelated files.
                let path = if source {
                    path.chars()
                        .flat_map(|c| {
                            if matches!(c, '\\' | '*' | '?' | '[' | ']') {
                                vec!['\\', c]
                            } else {
                                vec![c]
                            }
                        })
                        .collect::<String>()
                } else {
                    path.clone()
                };
                format!("{alias}:{path}")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Copy {
    source: Operand,
    destination: Operand,
    recursive: bool,
}

impl Copy {
    pub(super) fn parse(source: &str, destination: &str, recursive: bool) -> Result<Self> {
        let source = Operand::parse(source)?;
        let destination = Operand::parse(destination)?;
        match (&source, &destination) {
            (Operand::Local(_), Operand::Local(_)) => {
                anyhow::bail!("exactly one operand must be HOST:PATH; use cp for local copies")
            }
            (Operand::Remote { .. }, Operand::Remote { .. }) => {
                anyhow::bail!("remote-to-remote copies are not supported; copy via this machine")
            }
            _ => Ok(Self {
                source,
                destination,
                recursive,
            }),
        }
    }

    pub(super) fn target(&self) -> &str {
        match (&self.source, &self.destination) {
            (Operand::Remote { target, .. }, _) | (_, Operand::Remote { target, .. }) => target,
            _ => unreachable!("validated copy has one remote operand"),
        }
    }

    pub(super) fn command(&self, config: &Path, alias: &str) -> Command {
        let mut command = Command::new("scp");
        // Explicitly select SFTP even with OpenSSH versions before 9.0. Do not
        // fall back to legacy SCP or interpret any remote operand in a shell.
        command.args(["-s", "-F"]).arg(config);
        if self.recursive {
            command.arg("-r");
        }
        command
            .arg("--")
            .arg(self.source.argument(alias, true))
            .arg(self.destination.argument(alias, false));
        command
    }
}

pub(crate) async fn copy(
    path: &Path,
    source: &str,
    destination: &str,
    recursive: bool,
    no_cache: bool,
    trust_new_host_key: bool,
) -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};
    let copy = Copy::parse(source, destination, recursive)?;
    // Install handlers before discovery/setup, including for noninteractive
    // transfers. Cancellation waits for broker/key and child-process cleanup.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let cancel = CancellationToken::new();
    let run = super::client::copy(path, copy, no_cache, trust_new_host_key, cancel.clone());
    tokio::pin!(run);
    tokio::select! {
        result = &mut run => result,
        code = async {
            tokio::select! {
                _ = interrupt.recv() => 130,
                _ = terminate.recv() => 143,
                _ = hangup.recv() => 129,
            }
        } => {
            cancel.cancel();
            let _ = run.await;
            Ok(code)
        }
    }
}

struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        crate::bounded_process::terminate_process_group(self.0);
    }
}

pub(super) async fn run_client(mut command: Command, cancel: CancellationToken) -> Result<i32> {
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command
        .spawn()
        .context("system OpenSSH client `scp` with SFTP support is required")?;
    let group = ProcessGroup(child.id().context("missing scp PID")?);
    tokio::select! {
        result = child.wait() => Ok(result?.code().unwrap_or(255)),
        _ = cancel.cancelled() => {
            drop(group);
            let _ = child.wait().await;
            Ok(130)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_terminates_scp_and_its_ssh_descendants() {
        let root = crate::test_support::canonical_tempdir();
        let marker = root.path().join("child.pid");
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30 & echo $! > \"$1\"; wait", "fixture"])
            .arg(&marker);
        let cancel = CancellationToken::new();
        let run = tokio::spawn(run_client(command, cancel.clone()));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !marker.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid = std::fs::read_to_string(marker)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        cancel.cancel();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), run)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            130
        );
        // On Linux an orphaned killed process can briefly be a zombie; it must
        // not still be executing. Other platforms can report ESRCH directly.
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if rustix::process::test_kill_process(pid).is_err() {
                    break;
                }
                #[cfg(target_os = "linux")]
                if std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_pid()))
                    .is_ok_and(|stat| stat.split_whitespace().nth(2) == Some("Z"))
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn validates_direction_before_loading_credentials() {
        for (source, destination) in [
            ("a", "b"),
            ("a:/x", "b:/y"),
            ("", "a:x"),
            ("a:", "."),
            (":x", "."),
            ("a:x\0", "."),
        ] {
            assert!(Copy::parse(source, destination, false).is_err());
        }
        assert_eq!(
            Copy::parse("office:/tmp/x", ".", false).unwrap().target(),
            "office"
        );
        assert_eq!(
            Copy::parse("./file:name", "office:x", false)
                .unwrap()
                .target(),
            "office"
        );
        assert!(Copy::parse("/tmp/file:name", "office:x", false).is_ok());
    }

    #[test]
    fn arguments_are_literal_and_cannot_become_ssh_options_or_shell_commands() {
        let copy = Copy::parse("office:a *[?]\\'$(touch hacked)", "-destination", true).unwrap();
        let command = copy.command(Path::new("/tmp/private config"), "attached-stable-id");
        let args = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "-s",
                "-F",
                "/tmp/private config",
                "-r",
                "--",
                "attached-stable-id:a \\*\\[\\?\\]\\\\'$(touch hacked)",
                "./-destination"
            ]
        );
    }
}
