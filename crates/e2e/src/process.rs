//! Bounded subprocess execution. Never include stdin or captured stdout in errors.
use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};

const OUTPUT_LIMIT: usize = 128 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct Reply {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(crate) async fn read_bounded(reader: Option<impl AsyncRead + Unpin>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if let Some(reader) = reader {
        reader
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= OUTPUT_LIMIT,
            "subprocess output exceeded its bound"
        );
    }
    Ok(bytes)
}

pub(crate) async fn run(
    program: &str,
    args: &[String],
    input: Option<Vec<u8>>,
    stream: bool,
    deadline: Duration,
) -> Result<Reply> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if stream {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .stderr(if stream {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("could not start {program}"))?;
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    tokio::time::timeout(deadline, async {
        let writer = async {
            if let (Some(mut stdin), Some(input)) = (stdin, input) {
                stdin.write_all(&input).await?;
                stdin.shutdown().await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
        let (stdout, stderr, (), status) =
            tokio::try_join!(read_bounded(stdout), read_bounded(stderr), writer, wait,)?;
        Ok(Reply {
            code: status.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    })
    .await
    .with_context(|| {
        format!(
            "{program} exceeded its {}-second deadline",
            deadline.as_secs()
        )
    })?
}

pub(crate) fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_streams_status_and_stdin_without_shell_interpolation() {
        let result = run(
            "sh",
            &strings(&["-c", "cat; printf error >&2; exit 37"]),
            Some(b"input;$HOME".to_vec()),
            false,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(result.code, 37);
        assert_eq!(result.stdout, b"input;$HOME");
        assert_eq!(result.stderr, b"error");
    }

    #[tokio::test]
    async fn hung_process_times_out_without_leaking_stdin() {
        let error = run(
            "sh",
            &strings(&["-c", "exec sleep 60"]),
            Some(b"secret".to_vec()),
            false,
            Duration::from_millis(20),
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("deadline"));
        assert!(!format!("{error:#}").contains("secret"));
    }
}
