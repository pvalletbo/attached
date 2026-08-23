use std::{
    ffi::OsStr,
    io::Read,
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, ExitStatus, Stdio},
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

pub fn run(
    executable: &Path,
    args: &[&OsStr],
    runtime_limit: Duration,
    capture_limit: u64,
) -> Result<BoundedOutput> {
    let command_display = format_command(executable, args);
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
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

fn format_command(executable: &Path, args: &[&OsStr]) -> String {
    let args = args
        .iter()
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
