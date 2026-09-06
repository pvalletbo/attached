use std::{
    ffi::OsStr,
    io::Read,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use rustix::process::{Pid, Signal, kill_process_group};

pub struct BoundedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

// Linux can briefly reject execution with ETXTBSY immediately after an updater atomically
// replaces a binary. Keep the retry window short and bounded so a genuinely writable executable
// still fails instead of consuming the command's much longer runtime limit.
const EXECUTABLE_BUSY_RETRY_LIMIT: usize = 100;
const EXECUTABLE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(10);

pub fn run(
    executable: &Path,
    args: &[&OsStr],
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<BoundedOutput> {
    let mut command = Command::new(executable);
    command.args(args);
    run_command(command, runtime_limit, capture_limit)
}

pub fn run_command(
    mut command: Command,
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<BoundedOutput> {
    let command_display = format_command(&command);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = spawn_with_executable_busy_retry(&mut command)
        .with_context(|| format!("failed to run {command_display}"))?;
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("failed to capture stdout from {command_display}"))?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("failed to capture stderr from {command_display}"))?;
    let stdout_reader = bounded_reader(stdout, capture_limit);
    let stderr_reader = bounded_reader(stderr, capture_limit);

    let deadline = Instant::now() + runtime_limit;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("failed to poll {command_display}"))?
        {
            terminate_process_group(child.id());
            break status;
        }
        if Instant::now() >= deadline {
            terminate_process_group(child.id());
            let status = child
                .wait()
                .with_context(|| format!("failed to reap timed-out {command_display}"))?;
            timed_out = true;
            break status;
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout = join_reader(stdout_reader, "stdout", &command_display)?;
    let stderr = join_reader(stderr_reader, "stderr", &command_display)?;
    if timed_out {
        bail!(
            "{command_display} timed out after {} seconds",
            runtime_limit.as_secs()
        );
    }
    ensure!(
        stdout.len() <= capture_limit as usize && stderr.len() <= capture_limit as usize,
        "{command_display} produced more than {capture_limit} bytes on stdout or stderr"
    );
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

fn spawn_with_executable_busy_retry(command: &mut Command) -> std::io::Result<Child> {
    retry_executable_busy(
        || command.spawn(),
        EXECUTABLE_BUSY_RETRY_LIMIT,
        EXECUTABLE_BUSY_RETRY_DELAY,
    )
}

fn retry_executable_busy<T>(
    mut operation: impl FnMut() -> std::io::Result<T>,
    retry_limit: usize,
    retry_delay: Duration,
) -> std::io::Result<T> {
    let mut retries = 0;
    loop {
        match operation() {
            Err(error)
                if error.raw_os_error() == Some(rustix::io::Errno::TXTBSY.raw_os_error())
                    && retries < retry_limit =>
            {
                retries += 1;
                thread::sleep(retry_delay);
            }
            result => return result,
        }
    }
}

pub(crate) async fn retry_executable_busy_async<T>(
    operation: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    retry_executable_busy_async_with(
        operation,
        EXECUTABLE_BUSY_RETRY_LIMIT,
        EXECUTABLE_BUSY_RETRY_DELAY,
    )
    .await
}

async fn retry_executable_busy_async_with<T>(
    mut operation: impl FnMut() -> std::io::Result<T>,
    retry_limit: usize,
    retry_delay: Duration,
) -> std::io::Result<T> {
    let mut retries = 0;
    loop {
        match operation() {
            Err(error)
                if error.raw_os_error() == Some(rustix::io::Errno::TXTBSY.raw_os_error())
                    && retries < retry_limit =>
            {
                retries += 1;
                tokio::time::sleep(retry_delay).await;
            }
            result => return result,
        }
    }
}

fn bounded_reader<R>(reader: R, capture_limit: u64) -> thread::JoinHandle<std::io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.take(capture_limit + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn join_reader(
    reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
    command_display: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("{command_display} {stream} reader panicked"))?
        .with_context(|| format!("failed to read {stream} from {command_display}"))
}

pub(crate) fn terminate_process_group(child_id: u32) {
    let Ok(raw_pid) = i32::try_from(child_id) else {
        return;
    };
    let Some(process_group) = Pid::from_raw(raw_pid) else {
        return;
    };
    let _ = kill_process_group(process_group, Signal::KILL);
}

fn format_command(command: &Command) -> String {
    let executable = Path::new(command.get_program());
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    if args.is_empty() {
        format!("{}", executable.display())
    } else {
        format!("{} {args}", executable.display())
    }
}

pub fn diagnostic(bytes: &[u8]) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 256;
    let truncated = bytes.len() > MAX_DIAGNOSTIC_BYTES;
    let bytes = &bytes[..bytes.len().min(MAX_DIAGNOSTIC_BYTES)];
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if truncated {
        text.push('…');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_busy_retries_are_selective_and_bounded() {
        let busy = rustix::io::Errno::TXTBSY.raw_os_error();
        let mut attempts = 0;
        let value = retry_executable_busy(
            || {
                attempts += 1;
                if attempts <= 2 {
                    Err(std::io::Error::from_raw_os_error(busy))
                } else {
                    Ok(17)
                }
            },
            2,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(value, 17);
        assert_eq!(attempts, 3);

        attempts = 0;
        let error = retry_executable_busy::<()>(
            || {
                attempts += 1;
                Err(std::io::Error::from_raw_os_error(busy))
            },
            2,
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(busy));
        assert_eq!(attempts, 3);

        attempts = 0;
        let error = retry_executable_busy::<()>(
            || {
                attempts += 1;
                Err(std::io::Error::from_raw_os_error(
                    rustix::io::Errno::ACCESS.raw_os_error(),
                ))
            },
            2,
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn asynchronous_executable_busy_retries_are_selective_and_bounded() {
        let busy = rustix::io::Errno::TXTBSY.raw_os_error();
        let mut attempts = 0;
        let value = retry_executable_busy_async_with(
            || {
                attempts += 1;
                if attempts <= 2 {
                    Err(std::io::Error::from_raw_os_error(busy))
                } else {
                    Ok(17)
                }
            },
            2,
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert_eq!(value, 17);
        assert_eq!(attempts, 3);

        attempts = 0;
        let error = retry_executable_busy_async_with::<()>(
            || {
                attempts += 1;
                Err(std::io::Error::from_raw_os_error(busy))
            },
            2,
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(busy));
        assert_eq!(attempts, 3);

        attempts = 0;
        let error = retry_executable_busy_async_with::<()>(
            || {
                attempts += 1;
                Err(std::io::Error::from_raw_os_error(
                    rustix::io::Errno::ACCESS.raw_os_error(),
                ))
            },
            2,
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(attempts, 1);
    }
}
