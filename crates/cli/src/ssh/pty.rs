//! Interactive SSH sessions share the exec service's identity and environment.
use super::{
    exec::{ProcessGroup, reject_request},
    state::Policy,
};
use anyhow::{Result, bail, ensure};
use russh::{
    Channel, ChannelMsg,
    server::{Handle, Msg},
};
use std::{
    ffi::OsStr,
    os::unix::{ffi::OsStrExt, process::ExitStatusExt},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub(super) struct Terminal {
    master: pty_process::Pty,
    slave: pty_process::Pts,
}

fn size(columns: u32, rows: u32) -> Result<pty_process::Size> {
    ensure!(
        (1..=65535).contains(&columns) && (1..=65535).contains(&rows),
        "invalid terminal size"
    );
    Ok(pty_process::Size::new(rows as u16, columns as u16))
}

pub(super) fn allocate(
    term: &str,
    columns: u32,
    rows: u32,
    modes: &[(russh::Pty, u32)],
) -> Result<Terminal> {
    ensure!(
        !term.is_empty()
            && term.len() <= 128
            && term
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b)),
        "invalid terminal name"
    );
    let dimensions = size(columns, rows)?;
    let (master, slave) = pty_process::open()?;
    master.resize(dimensions)?;
    // Standard line discipline flags used by SSH clients. Unsupported terminal
    // opcodes leave the OS default unchanged, as do absent modes from libssh2.
    use rustix::termios::{self, InputModes, LocalModes, OutputModes};
    let mut attrs = termios::tcgetattr(&master)?;
    for &(mode, value) in modes {
        match mode {
            russh::Pty::ECHO => attrs.local_modes.set(LocalModes::ECHO, value != 0),
            russh::Pty::ICANON => attrs.local_modes.set(LocalModes::ICANON, value != 0),
            russh::Pty::ISIG => attrs.local_modes.set(LocalModes::ISIG, value != 0),
            russh::Pty::IEXTEN => attrs.local_modes.set(LocalModes::IEXTEN, value != 0),
            russh::Pty::ICRNL => attrs.input_modes.set(InputModes::ICRNL, value != 0),
            russh::Pty::INLCR => attrs.input_modes.set(InputModes::INLCR, value != 0),
            russh::Pty::IGNCR => attrs.input_modes.set(InputModes::IGNCR, value != 0),
            russh::Pty::IXON => attrs.input_modes.set(InputModes::IXON, value != 0),
            russh::Pty::OPOST => attrs.output_modes.set(OutputModes::OPOST, value != 0),
            russh::Pty::ONLCR => attrs.output_modes.set(OutputModes::ONLCR, value != 0),
            _ => {}
        }
    }
    termios::tcsetattr(&master, termios::OptionalActions::Now, &attrs)?;
    Ok(Terminal { master, slave })
}

pub(super) async fn run(
    channel: Channel<Msg>,
    handle: &Handle,
    policy: Policy,
    cancellation: CancellationToken,
    terminal: Terminal,
    term: String,
    request: (Option<Vec<u8>>, bool),
) -> Result<()> {
    let id = channel.id();
    let mut command = pty_process::Command::new(&policy.shell)
        .env_clear()
        .env("HOME", &policy.home)
        .env("USER", &policy.username)
        .env("LOGNAME", &policy.username)
        .env("SHELL", &policy.shell)
        .env("TERM", term)
        .env(
            "PATH",
            "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .current_dir(&policy.home)
        .kill_on_drop(true);
    if let Some(bytes) = &request.0 {
        ensure!(
            bytes.len() <= 32768 && !bytes.contains(&0),
            "invalid SSH command"
        );
        command = command.arg("-c").arg(OsStr::from_bytes(bytes));
    }
    let Terminal { master, slave } = terminal;
    let mut child = command.spawn(slave)?;
    let guard = ProcessGroup(
        child
            .id()
            .ok_or_else(|| anyhow::anyhow!("missing child PID"))?,
    );
    if request.1 {
        handle
            .channel_success(id)
            .await
            .map_err(|_| anyhow::anyhow!("SSH session closed"))?;
    }
    let (mut reader, writer) = channel.split();
    let result = {
        let (mut read_pty, mut write_pty) = master.into_split();
        let input = async {
            let mut eof = false;
            loop {
                match reader.wait().await {
                    Some(ChannelMsg::Data { data }) if !eof => write_pty.write_all(&data).await?,
                    Some(ChannelMsg::WindowChange {
                        col_width,
                        row_height,
                        ..
                    }) => {
                        if let Ok(size) = size(col_width, row_height) {
                            write_pty.resize(size)?;
                        }
                    }
                    Some(ChannelMsg::Eof) if !eof => {
                        // EOF is transport state, not a Ctrl-D keystroke. Herdr
                        // puts the PTY into raw mode: injecting 0x04 here could
                        // log out the persistent remote shell when iOS detaches.
                        eof = true;
                    }
                    Some(ChannelMsg::Close) | None => bail!("SSH terminal closed"),
                    Some(msg) => reject_request(&msg, handle, id).await?,
                }
            }
        };
        let output = async {
            let mut output = writer.make_writer();
            let mut bytes = [0; 16 * 1024];
            loop {
                let count = match read_pty.read(&mut bytes).await {
                    Ok(n) => n,
                    // Linux reports EIO when the last slave descriptor closes.
                    Err(e) if e.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) => {
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };
                if count == 0 {
                    break;
                }
                output.write_all(&bytes[..count]).await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::pin!(input, output);
        tokio::select! {
            _ = cancellation.cancelled() => Err(anyhow::anyhow!("SSH terminal cancelled")),
            result = &mut input => result.map(|()| unreachable!()),
            result = async {
                let status = tokio::select! {
                    result = &mut output => { result?; child.wait().await? },
                    status = child.wait() => {
                        let status = status?;
                        crate::bounded_process::terminate_process_group(guard.0);
                        // Keep draining after exit, but a daemon retaining the
                        // slave must not hold the SSH channel indefinitely.
                        if let Ok(result) = tokio::time::timeout(std::time::Duration::from_secs(2), &mut output).await { result?; }
                        status
                    },
                };
                Ok::<_, anyhow::Error>(status)
            } => result,
        }
        // Dropping both master halves hangs up the terminal, including its
        // foreground job. Reads use AsyncFd, so cancellation cannot strand threads.
    };
    drop(guard);
    let _ = child.wait().await;
    let status = result?;
    tokio::select! {
        _ = cancellation.cancelled() => Ok(()),
        result = async {
            writer.exit_status(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1)) as u32).await?;
            writer.eof().await?;
            writer.close().await?;
            Ok(())
        } => result,
    }
}
