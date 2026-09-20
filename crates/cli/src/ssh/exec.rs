use std::{
    collections::HashMap,
    ffi::OsStr,
    os::unix::{ffi::OsStrExt, process::ExitStatusExt},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use russh::{
    Channel, ChannelId, ChannelMsg,
    keys::PublicKey,
    server::{self, Auth, Handler, Msg, Session},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    process::Command,
    sync::Semaphore,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::state::Policy;

pub(super) struct Service {
    pub policy: Policy,
    pub key: PublicKey,
    pub authenticated: CancellationToken,
    pub cancellation: CancellationToken,
    pub tasks: TaskTracker,
    pub channels: Arc<Semaphore>,
    pub forwarding: Arc<Semaphore>,
    pub channel_cancellations: HashMap<ChannelId, CancellationToken>,
}

impl Handler for Service {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(&mut self, user: &str, key: &PublicKey) -> Result<Auth> {
        Ok(
            if user == self.policy.username && key.key_data() == self.key.key_data() {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }
    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth> {
        self.auth_publickey_offered(user, key).await
    }
    async fn auth_succeeded(&mut self, _: &mut Session) -> Result<()> {
        self.authenticated.cancel();
        Ok(())
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<()> {
        // Count channels awaiting the peer's CLOSE acknowledgement as well as
        // running tasks, so a peer cannot accumulate unacknowledged channel state.
        self.channel_cancellations
            .retain(|_, token| !token.is_cancelled());
        if self.channel_cancellations.len() >= 26 {
            return Ok(());
        }
        let Ok(permit) = self.channels.clone().try_acquire_owned() else {
            return Ok(());
        };
        let cancellation = self.cancellation.child_token();
        self.channel_cancellations
            .insert(channel.id(), cancellation.clone());
        let policy = self.policy.clone();
        let handle = session.handle();
        reply.accept().await;
        self.tasks.spawn(async move {
            let _permit = permit;
            let id = channel.id();
            if run_channel(channel, &handle, policy, cancellation.clone()).await.is_err() {
                tokio::select! {
                    _ = cancellation.cancelled() => {},
                    _ = async { let _ = handle.channel_failure(id).await; let _ = handle.close(id).await; } => {},
                }
            }
        });
        Ok(())
    }
    async fn channel_open_direct_streamlocal(
        &mut self,
        channel: Channel<Msg>,
        socket_path: &str,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<()> {
        // The authenticated consumer already has shell access as this OS user.
        // Socket permissions remain enforced by the OS; never accept abstract,
        // relative or NUL-containing paths and never run a privileged proxy.
        if !std::path::Path::new(socket_path).is_absolute()
            || socket_path.as_bytes().contains(&0)
            || socket_path.len() > 4096
        {
            return Ok(());
        }
        self.channel_cancellations
            .retain(|_, token| !token.is_cancelled());
        if self.channel_cancellations.len() >= 26 {
            return Ok(());
        }
        let Ok(permit) = self.forwarding.clone().try_acquire_owned() else {
            return Ok(());
        };
        let cancellation = self.cancellation.child_token();
        self.channel_cancellations
            .insert(channel.id(), cancellation.clone());
        let path = socket_path.to_owned();
        let handle = session.handle();
        self.tasks.spawn(async move {
            let _permit = permit;
            let id = channel.id();
            let connected = tokio::select! {
                _ = cancellation.cancelled() => return,
                result = tokio::time::timeout(Duration::from_secs(5), tokio::net::UnixStream::connect(path)) => result,
            };
            let Ok(Ok(socket)) = connected else {
                // A rejected open has no CLOSE exchange. Reclaim its map entry
                // at the next admission without freeing accepted channel state.
                cancellation.cancel();
                return;
            };
            reply.accept().await;
            tokio::select! {
                _ = cancellation.cancelled() => {},
                _ = super::forward::bridge(channel.into_stream(), socket) => {},
            }
            tokio::select! {
                _ = cancellation.cancelled() => {},
                _ = async { let _ = handle.eof(id).await; let _ = handle.close(id).await; } => {},
            }
        });
        Ok(())
    }
    async fn channel_close(&mut self, channel: ChannelId, _: &mut Session) -> Result<()> {
        if let Some(token) = self.channel_cancellations.remove(&channel) {
            token.cancel();
        }
        Ok(())
    }
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        _: &str,
        session: &mut Session,
    ) -> Result<()> {
        // russh 0.63 queues SetEnv with want_reply=true even when OpenSSH sent
        // false. Its Session tracks only the latest request's reply flag, so an
        // asynchronous denial can accidentally reject the following exec. Deny
        // here while the wire request is current; Session suppresses unasked replies.
        session.channel_failure(channel)?;
        Ok(())
    }
    // Process I/O remains in bounded channel tasks, never blocking the shared SSH
    // event loop. Other channel/global opens retain russh's deny-by-default policy.
}

impl Drop for Service {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn run_channel(
    mut channel: Channel<Msg>,
    handle: &server::Handle,
    policy: Policy,
    cancellation: CancellationToken,
) -> Result<()> {
    let id = channel.id();
    let mut terminal = None;
    let request = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => bail!("SSH channel cancelled"),
                msg = channel.wait() => match msg {
                    Some(ChannelMsg::RequestPty { term, col_width, row_height, want_reply, terminal_modes, .. }) if terminal.is_none() => {
                        match super::pty::allocate(&term, col_width, row_height, &terminal_modes) {
                            Ok(pty) => { terminal = Some((pty, term)); if want_reply { handle.channel_success(id).await.map_err(|_| anyhow::anyhow!("SSH session closed"))?; } },
                            Err(_) => { if want_reply { handle.channel_failure(id).await.map_err(|_| anyhow::anyhow!("SSH session closed"))?; } },
                        }
                    }
                    Some(ChannelMsg::Exec { command, want_reply }) => break Ok((Some(command), want_reply)),
                    Some(ChannelMsg::RequestShell { want_reply }) => break Ok((None, want_reply)),
                    Some(ChannelMsg::Eof | ChannelMsg::Close) | None => bail!("channel closed before command"),
                    Some(msg) => reject_request(&msg, handle, id).await?,
                }
            }
        }
    }).await??;
    if let Some((pty, term)) = terminal {
        return super::pty::run(channel, handle, policy, cancellation, pty, term, request).await;
    }
    let mut command = Command::new(&policy.shell);
    if let Some(ref bytes) = request.0 {
        anyhow::ensure!(
            bytes.len() <= 32768 && !bytes.contains(&0),
            "invalid SSH command"
        );
        command.arg("-c").arg(OsStr::from_bytes(bytes));
    }
    // Do not inherit publish bundles, encryption credentials, agent sockets, or
    // application routing variables from the Attached service process.
    command
        .env_clear()
        .env("HOME", &policy.home)
        .env("USER", &policy.username)
        .env("LOGNAME", &policy.username)
        .env("SHELL", &policy.shell)
        .env(
            "PATH",
            "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .current_dir(&policy.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command
        .spawn()
        .context("could not start publisher account shell")?;
    let guard = ProcessGroup(child.id().context("missing child PID")?);
    if request.1 {
        tokio::select! {
            _ = cancellation.cancelled() => bail!("SSH channel cancelled"),
            result = handle.channel_success(id) => result.map_err(|_| anyhow::anyhow!("SSH session closed"))?,
        }
    }
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (mut reader, writer) = channel.split();
    let mut output = writer.make_writer();
    let mut errors = writer.make_writer_ext(Some(1));
    let input = async {
        loop {
            match reader.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(pipe) = &mut stdin
                        && let Err(error) = pipe.write_all(&data).await
                    {
                        if error.kind() == std::io::ErrorKind::BrokenPipe {
                            stdin.take();
                        } else {
                            return Err(error.into());
                        }
                    }
                }
                Some(ChannelMsg::Eof) => {
                    stdin.take();
                }
                Some(ChannelMsg::Close) | None => bail!("SSH channel closed"),
                Some(msg) => reject_request(&msg, handle, id).await?,
            }
        }
    };
    let output_and_exit = async {
        let (status, _, _) = tokio::try_join!(
            child.wait(),
            tokio::io::copy(&mut stdout, &mut output),
            tokio::io::copy(&mut stderr, &mut errors)
        )?;
        Ok::<_, anyhow::Error>(status)
    };
    let result = tokio::select! {
        _ = cancellation.cancelled() => Err(anyhow::anyhow!("SSH channel cancelled")),
        result = input => result.map(|()| unreachable!()),
        result = output_and_exit => result,
    };
    // Killing the process group also cleans up children retaining pipe ends. This
    // is not containment: an authorized user can deliberately setsid/daemonize.
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

pub(super) struct ProcessGroup(pub(super) u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        crate::bounded_process::terminate_process_group(self.0);
    }
}

pub(super) async fn reject_request(
    msg: &ChannelMsg,
    handle: &server::Handle,
    id: ChannelId,
) -> Result<()> {
    let reply = match msg {
        ChannelMsg::Exec { want_reply, .. }
        | ChannelMsg::RequestShell { want_reply }
        | ChannelMsg::RequestPty { want_reply, .. }
        | ChannelMsg::RequestSubsystem { want_reply, .. }
        | ChannelMsg::RequestX11 { want_reply, .. }
        | ChannelMsg::AgentForward { want_reply } => *want_reply,
        // Already rejected synchronously in Handler::env_request.
        ChannelMsg::SetEnv { .. } => false,
        _ => false,
    };
    if reply {
        handle
            .channel_failure(id)
            .await
            .map_err(|_| anyhow::anyhow!("SSH session closed"))?;
    }
    Ok(())
}

pub(super) async fn serve_stream<S>(
    stream: S,
    host_key: russh::keys::PrivateKey,
    client_key: PublicKey,
    policy: Policy,
    cancellation: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tasks = TaskTracker::new();
    let authenticated = CancellationToken::new();
    let config = server::Config {
        keys: vec![host_key],
        methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
        max_auth_attempts: 3,
        auth_rejection_time: Duration::from_millis(500),
        auth_rejection_time_initial: Some(Duration::ZERO),
        window_size: 128 * 1024,
        channel_buffer_size: 8,
        event_buffer_size: 32,
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    };
    let handler = Service {
        policy,
        key: client_key,
        authenticated: authenticated.clone(),
        cancellation: cancellation.child_token(),
        tasks: tasks.clone(),
        channels: Arc::new(Semaphore::new(10)),
        forwarding: Arc::new(Semaphore::new(16)),
        channel_cancellations: HashMap::new(),
    };
    let running = tokio::time::timeout(
        Duration::from_secs(15),
        server::run_stream(Arc::new(config), stream, handler),
    )
    .await??;
    let handle = running.handle();
    tokio::pin!(running);
    let auth_deadline = async {
        tokio::select! { _ = authenticated.cancelled() => std::future::pending::<()>().await, _ = tokio::time::sleep(Duration::from_secs(15)) => {} }
    };
    let result = tokio::select! {
        result = &mut running => result,
        _ = auth_deadline => Err(anyhow::anyhow!("SSH authentication timed out")),
        _ = cancellation.cancelled() => Err(anyhow::anyhow!("SSH access cancelled")),
    };
    cancellation.cancel();
    // RunningSession owns a spawned task; dropping its future alone does not stop it.
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        handle.disconnect(
            russh::Disconnect::ByApplication,
            "SSH session ended".into(),
            "".into(),
        ),
    )
    .await;
    tasks.close();
    tasks.wait().await;
    result
}
