//! Linux PTY driver for the real password prompts. `script` allocates the PTY;
//! all interaction, deadlines, assertions and redaction live in Rust. This avoids
//! unsafe terminal/session setup code and additional PTY library dependencies.
use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::Instant,
};

const LIMIT: usize = 64 * 1024;
const CREATE: &str = "Create Attached encryption password: ";
const CONFIRM: &str = "Confirm Attached encryption password: ";
const UNLOCK: &str = "Attached encryption password: ";

pub(crate) fn shell_word(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

pub(crate) struct Terminal {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    pending: Vec<u8>,
    captured: Vec<u8>,
    password: String,
    pub deadline: Instant,
}

impl Terminal {
    pub fn spawn(args: &[String], password: String, duration: Duration) -> Result<Self> {
        let command = format!(
            "exec {}",
            args.iter()
                .map(|s| shell_word(s))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let mut child = Command::new("script")
            .args([
                "--quiet",
                "--return",
                "--flush",
                "--echo",
                "never",
                "--command",
                &command,
                "/dev/null",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("could not start the Linux PTY helper (script)")?;
        Ok(Self {
            input: child.stdin.take().context("missing PTY stdin")?,
            output: child.stdout.take().context("missing PTY stdout")?,
            child,
            pending: Vec::new(),
            captured: Vec::new(),
            password,
            deadline: Instant::now() + duration,
        })
    }

    fn diagnostic(&self) -> String {
        let mut bytes = self.captured.clone();
        bytes.extend_from_slice(&self.pending);
        // Redact before truncating so a secret straddling the tail is not leaked.
        let text = String::from_utf8_lossy(&bytes).replace(&self.password, "[redacted]");
        text.chars()
            .rev()
            .take(4000)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    async fn read(&mut self) -> Result<bool> {
        let mut bytes = [0; 4096];
        let count = match tokio::time::timeout_at(self.deadline, self.output.read(&mut bytes)).await
        {
            Ok(result) => result?,
            Err(_) => bail!("CLI timed out; output: {}", self.diagnostic()),
        };
        ensure!(
            self.pending.len() + self.captured.len() + count <= LIMIT,
            "CLI output exceeded its bound"
        );
        self.pending.extend_from_slice(&bytes[..count]);
        Ok(count != 0)
    }

    pub async fn expect(&mut self, marker: &str) -> Result<()> {
        loop {
            if let Some(index) = self
                .pending
                .windows(marker.len())
                .position(|s| s == marker.as_bytes())
            {
                self.captured.extend_from_slice(&self.pending[..index]);
                self.pending.drain(..index + marker.len());
                return Ok(());
            }
            ensure!(
                self.read().await?,
                "CLI exited before the expected prompt; output: {}",
                self.diagnostic()
            );
        }
    }

    pub async fn unlock(&mut self, create: bool) -> Result<()> {
        let prompts: &[&str] = if create {
            &[CREATE, CONFIRM]
        } else {
            &[UNLOCK]
        };
        for prompt in prompts {
            self.expect(prompt).await?;
            // rpassword prints before changing terminal mode; allow that change
            // to finish so its input flush cannot discard the password.
            tokio::time::sleep(Duration::from_millis(50)).await;
            tokio::time::timeout_at(self.deadline, async {
                self.input.write_all(self.password.as_bytes()).await?;
                self.input.write_all(b"\n").await
            })
            .await
            .context("password input timed out")??;
        }
        Ok(())
    }

    pub async fn finish(&mut self, expected: i32) -> Result<String> {
        while self.read().await? {}
        let status = tokio::time::timeout_at(self.deadline, self.child.wait())
            .await
            .context("CLI exit timed out")??;
        ensure!(
            status.code() == Some(expected),
            "CLI exit status {:?}, expected {expected}; output: {}",
            status.code(),
            self.diagnostic()
        );
        self.captured.append(&mut self.pending);
        Ok(String::from_utf8_lossy(&self.captured)
            .replace(&self.password, "[redacted]")
            .replace("\r\n", "\n")
            .trim()
            .to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_words_preserve_quotes_and_do_not_expand_commands() {
        assert_eq!(shell_word("a'b; $HOME"), "'a'\\''b; $HOME'");
    }

    // The machine driver always runs in Linux Docker, including on macOS hosts.
    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use crate::process::strings;

        #[tokio::test]
        async fn real_tty_creation_confirmation_and_exit_status() {
            let script = "test -t 0 && test -t 2 || exit 99; printf 'Create Attached encryption password: '; read -r a; printf 'Confirm Attached encryption password: '; read -r b; test \"$a\" = test-secret && test \"$b\" = test-secret || exit 98; printf 'remote output'; exit 37";
            let mut terminal = Terminal::spawn(
                &strings(&["sh", "-c", script]),
                "test-secret".into(),
                Duration::from_secs(5),
            )
            .unwrap();
            terminal.unlock(true).await.unwrap();
            assert_eq!(terminal.finish(37).await.unwrap(), "remote output");
        }

        #[tokio::test]
        async fn wrong_status_fails_and_password_is_never_reported() {
            let script =
                "printf 'Attached encryption password: '; read -r a; printf '%s' \"$a\"; exit 255";
            let mut terminal = Terminal::spawn(
                &strings(&["sh", "-c", script]),
                "test-secret".into(),
                Duration::from_secs(5),
            )
            .unwrap();
            terminal.unlock(false).await.unwrap();
            let error = terminal.finish(0).await.unwrap_err().to_string();
            assert!(error.contains("255"));
            assert!(error.contains("[redacted]"));
            assert!(!error.contains("test-secret"));
        }

        #[tokio::test]
        async fn early_exit_and_hung_prompts_fail() {
            for script in ["printf test-secret; exit 1", "exec sleep 60"] {
                let mut terminal = Terminal::spawn(
                    &strings(&["sh", "-c", script]),
                    "test-secret".into(),
                    Duration::from_millis(200),
                )
                .unwrap();
                let error = terminal.unlock(false).await.unwrap_err().to_string();
                assert!(!error.contains("test-secret"));
                assert!(error.contains("CLI exited") || error.contains("timed out"));
            }
        }
    }
}
