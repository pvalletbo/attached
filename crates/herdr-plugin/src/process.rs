//! Bounded, noninteractive subprocesses. Dropping a request kills its entire group.
use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, ensure};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
};

const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;

pub(crate) struct ChildGroup {
    pub child: Child,
    pid: Pid,
}

impl ChildGroup {
    pub fn spawn(command: &mut Command) -> Result<Self> {
        let child = command
            .stdin(Stdio::null())
            .env("SSH_ASKPASS_REQUIRE", "never")
            .env("GIT_TERMINAL_PROMPT", "0")
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .context("could not start plugin subprocess")?;
        let pid = Pid::from_raw(child.id().context("missing child PID")? as i32)
            .context("invalid child PID")?;
        Ok(Self { child, pid })
    }

    pub async fn stop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = kill_process_group(self.pid, Signal::TERM);
            // Attached must get a chance to remove its managed SSH Include/keys.
            if tokio::time::timeout(Duration::from_secs(8), self.child.wait())
                .await
                .is_err()
            {
                let _ = kill_process_group(self.pid, Signal::KILL);
                let _ = self.child.wait().await;
            }
        }
    }
}

impl Drop for ChildGroup {
    fn drop(&mut self) {
        // Descendants can hold capture pipes open even after the parent exits.
        let _ = kill_process_group(self.pid, Signal::KILL);
    }
}

pub(crate) async fn output(mut command: Command, deadline: Duration) -> Result<String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut group = ChildGroup::spawn(&mut command)?;
    let stdout = group.child.stdout.take().context("missing stdout")?;
    let stderr = group.child.stderr.take().context("missing stderr")?;
    let run = async {
        let (stdout, stderr, status) =
            tokio::try_join!(read_bounded(stdout), read_bounded(stderr), async {
                group
                    .child
                    .wait()
                    .await
                    .context("could not wait for subprocess")
            },)?;
        ensure!(
            status.success(),
            "command failed ({status}): {}",
            diagnostic(&String::from_utf8_lossy(&stderr))
        );
        String::from_utf8(stdout).context("command returned non-UTF-8 output")
    };
    tokio::time::timeout(deadline, run)
        .await
        .context("plugin command timed out")?
}

async fn read_bounded(reader: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() as u64 <= OUTPUT_LIMIT,
        "plugin command output exceeded limit"
    );
    Ok(bytes)
}

pub(crate) fn diagnostic(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(2000)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[tokio::test]
    async fn commands_have_no_stdin_and_propagate_failure() {
        let result = output(
            shell("read value && exit 9; printf ok"),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(result, "ok");
        let error = output(shell("printf failure >&2; exit 4"), Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("failure"));
    }

    #[tokio::test]
    async fn timeouts_and_output_overflow_terminate_inherited_pipes() {
        let start = std::time::Instant::now();
        let error = output(shell("sleep 60 & wait"), Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(3));
        let error = output(shell("yes x"), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("output exceeded"));
    }
}
