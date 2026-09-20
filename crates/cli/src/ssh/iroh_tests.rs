use super::*;
use iroh::{
    Endpoint, RelayMode,
    endpoint::{BindOpts, presets},
};
use russh::{
    ChannelMsg,
    keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate},
};
use std::{net::Ipv4Addr, sync::Arc};
use tokio::{io::AsyncWriteExt, time::timeout};

const DEADLINE: Duration = Duration::from_secs(20);

async fn endpoint(key: iroh::SecretKey) -> Endpoint {
    Endpoint::builder(presets::N0)
        .secret_key(key)
        .clear_ip_transports()
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_prefix_len(8),
        )
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

struct VerifyHost(PublicKey);
impl russh::client::Handler for VerifyHost {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(key.public_key().key_data() == self.0.key_data())
    }
}

struct Harness {
    root: tempfile::TempDir,
    publisher: Endpoint,
    consumer: Endpoint,
    connection: iroh::endpoint::Connection,
    capability: CapabilitySecret,
    client_key: PrivateKey,
    policy: state::Policy,
    cancel: CancellationToken,
    server: tokio::task::JoinHandle<Result<()>>,
}
impl Harness {
    async fn new(change_account: impl FnOnce(&Path)) -> Self {
        Self::with_consumer(iroh::SecretKey::from_bytes(&[0x43; 32]), change_account).await
    }

    async fn with_consumer(key: iroh::SecretKey, change_account: impl FnOnce(&Path)) -> Self {
        let root = crate::test_support::canonical_tempdir();
        crate::sync::state::test_support::create_publisher(root.path(), "https://sync.example")
            .unwrap();
        let publisher = endpoint(iroh::SecretKey::generate()).await;
        let consumer = endpoint(key).await;
        let authorized = iroh::SecretKey::from_bytes(&[0x43; 32]).public();
        let policy = state::policy(root.path(), authorized.as_bytes()).unwrap();
        assert!(!root.path().join("ssh-access.json").exists());
        change_account(root.path());
        let (connection, server_connection) = timeout(DEADLINE, async {
            tokio::join!(consumer.connect(publisher.addr(), ALPN), async {
                publisher.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        let connection = connection.unwrap();
        let capability = CapabilitySecret::generate();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve(
            server_connection.unwrap(),
            root.path().to_owned(),
            capability.clone(),
            cancel.clone(),
            Arc::new(zeroize::Zeroizing::new([9; 32])),
        ));
        Self {
            root,
            publisher,
            consumer,
            connection,
            capability,
            client_key: state::ephemeral_key().unwrap(),
            policy,
            cancel,
            server,
        }
    }
    async fn setup(
        &self,
        capability: &CapabilitySecret,
    ) -> Result<(
        iroh::endpoint::SendStream,
        iroh::endpoint::RecvStream,
        Response,
    )> {
        timeout(DEADLINE, async {
            let (mut send, mut receive) = self.connection.open_bi().await?;
            write_frame(
                &mut send,
                &Request {
                    capability: capability.to_bytes(),
                    public_key: self.client_key.public_key().to_openssh()?,
                },
            )
            .await?;
            let response = read_frame(&mut receive).await?;
            Ok((send, receive, response))
        })
        .await?
    }
    async fn ssh(&self) -> russh::client::Handle<VerifyHost> {
        let (send, receive, metadata) = self.setup(&self.capability).await.unwrap();
        timeout(
            DEADLINE,
            russh::client::connect_stream(
                Arc::new(russh::client::Config::default()),
                tokio::io::join(receive, send),
                VerifyHost(PublicKey::from_openssh(&metadata.host_key).unwrap()),
            ),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn authenticated(&self) -> russh::client::Handle<VerifyHost> {
        let mut client = self.ssh().await;
        assert!(
            client
                .authenticate_publickey(
                    self.policy.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(self.client_key.clone()), None)
                )
                .await
                .unwrap()
                .success()
        );
        client
    }
    async fn close(self) {
        self.cancel.cancel();
        self.connection.close(0u32.into(), b"test complete");
        timeout(DEADLINE, self.server).await.unwrap().unwrap().ok();
        self.consumer.close().await;
        self.publisher.close().await;
    }
}

async fn command_output(
    mut channel: russh::Channel<russh::client::Msg>,
) -> (Vec<u8>, Vec<u8>, Option<u32>) {
    timeout(DEADLINE, async {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
        (stdout, stderr, status)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn iroh_multiplexes_shell_commands_and_preserves_binary_eof() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let one = client.channel_open_session().await.unwrap();
    let two = client.channel_open_session().await.unwrap();
    one.exec(true, "cat; printf tail; printf stderr >&2; exit 7")
        .await
        .unwrap();
    two.request_shell(true).await.unwrap();
    one.data_bytes(b"binary\0\xff".to_vec()).await.unwrap();
    one.eof().await.unwrap();
    two.data_bytes(b"printf shell-ok\n".to_vec()).await.unwrap();
    two.eof().await.unwrap();
    let (one, two) = tokio::join!(command_output(one), command_output(two));
    assert_eq!(
        one,
        (b"binary\0\xfftail".to_vec(), b"stderr".to_vec(), Some(7))
    );
    assert_eq!(two, (b"shell-ok".to_vec(), vec![], Some(0)));
    harness.close().await;
}

#[tokio::test]
async fn iroh_rejects_wrong_consumer_missing_or_corrupt_account_and_capability() {
    for mutation in 0..4 {
        let key = if mutation == 0 {
            iroh::SecretKey::generate()
        } else {
            iroh::SecretKey::from_bytes(&[0x43; 32])
        };
        let harness = Harness::with_consumer(key, |path| match mutation {
            1 => std::fs::remove_file(path.join("sync-account.bundle")).unwrap(),
            2 => crate::secure_state::StateDir::open(path)
                .unwrap()
                .atomic_replace("sync-account.bundle", b"corrupt")
                .unwrap(),
            _ => {}
        })
        .await;
        let capability = if mutation == 3 {
            CapabilitySecret::generate()
        } else {
            harness.capability.clone()
        };
        assert!(harness.setup(&capability).await.is_err());
        harness.close().await;
    }
}

#[tokio::test]
async fn iroh_requires_registered_ssh_key_and_exact_username() {
    for wrong_user in [false, true] {
        let harness = Harness::new(|_| {}).await;
        let mut client = harness.ssh().await;
        assert!(
            !client
                .authenticate_none(&harness.policy.username)
                .await
                .unwrap()
                .success()
        );
        let key = if wrong_user {
            harness.client_key.clone()
        } else {
            state::ephemeral_key().unwrap()
        };
        assert!(
            !client
                .authenticate_publickey(
                    if wrong_user {
                        "not-the-publisher"
                    } else {
                        &harness.policy.username
                    },
                    PrivateKeyWithHashAlg::new(Arc::new(key), None)
                )
                .await
                .unwrap()
                .success()
        );
        harness.close().await;
    }
}

#[tokio::test]
async fn iroh_rejects_wrong_ssh_host_key() {
    let harness = Harness::new(|_| {}).await;
    let (send, receive, _) = harness.setup(&harness.capability).await.unwrap();
    let result = timeout(
        DEADLINE,
        russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            tokio::io::join(receive, send),
            VerifyHost(state::ephemeral_key().unwrap().public_key().clone()),
        ),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    harness.close().await;
}

#[tokio::test]
async fn iroh_rejects_invalid_pty_env_subsystems_and_tcp_forwarding() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    assert!(
        client
            .channel_open_direct_tcpip("localhost", 22, "localhost", 0)
            .await
            .is_err()
    );
    assert!(client.tcpip_forward("127.0.0.1", 0).await.is_err());
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 0, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(matches!(
        timeout(DEADLINE, channel.wait()).await.unwrap(),
        Some(ChannelMsg::Failure)
    ));
    channel
        .set_env(true, "LD_PRELOAD", "/tmp/nope")
        .await
        .unwrap();
    assert!(matches!(
        timeout(DEADLINE, channel.wait()).await.unwrap(),
        Some(ChannelMsg::Failure)
    ));
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(matches!(
        timeout(DEADLINE, channel.wait()).await.unwrap(),
        Some(ChannelMsg::Failure)
    ));
    channel.agent_forward(true).await.unwrap();
    assert!(matches!(
        timeout(DEADLINE, channel.wait()).await.unwrap(),
        Some(ChannelMsg::Failure)
    ));
    channel
        .exec(true, "printf '%s' \"${LD_PRELOAD-unset}\"")
        .await
        .unwrap();
    channel.eof().await.unwrap();
    assert_eq!(
        command_output(channel).await,
        (b"unset".to_vec(), vec![], Some(0))
    );
    harness.close().await;
}

#[tokio::test]
async fn pipelined_environment_denials_preserve_exec_reply_over_iroh() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    for want_reply in [false, true] {
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .set_env(want_reply, "ATTACHED_SSH_TEST_ENV", "forbidden")
            .await
            .unwrap();
        channel
            .set_env(false, "ATTACHED_SSH_TEST_ENV", "also-forbidden")
            .await
            .unwrap();
        channel
            .exec(true, "printf '%s' \"${ATTACHED_SSH_TEST_ENV-unset}\"")
            .await
            .unwrap();
        channel.eof().await.unwrap();
        if want_reply {
            assert!(matches!(
                timeout(DEADLINE, channel.wait()).await.unwrap(),
                Some(ChannelMsg::Failure)
            ));
        }
        assert!(matches!(
            timeout(DEADLINE, channel.wait()).await.unwrap(),
            Some(ChannelMsg::Success)
        ));
        assert_eq!(
            command_output(channel).await,
            (b"unset".to_vec(), vec![], Some(0))
        );
    }
    harness.close().await;
}

#[tokio::test]
async fn removing_publish_bundle_cancels_active_command_process_group() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .exec(
            true,
            format!(
                "printf ready; sleep 2; printf survived >'{}'",
                harness.root.path().join("should-not-exist").display()
            ),
        )
        .await
        .unwrap();
    timeout(DEADLINE, async {
        loop {
            if matches!(channel.wait().await, Some(ChannelMsg::Data { .. })) {
                break;
            }
        }
    })
    .await
    .unwrap();
    std::fs::remove_file(harness.root.path().join("sync-account.bundle")).unwrap();
    timeout(Duration::from_secs(5), harness.connection.closed())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!harness.root.path().join("should-not-exist").exists());
    harness.close().await;
}

#[tokio::test]
async fn corrupting_publish_bundle_stops_backpressured_output_without_hanging_shutdown() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let channel = client.channel_open_session().await.unwrap();
    channel
        .exec(true, "exec /usr/bin/yes output")
        .await
        .unwrap();
    // Deliberately never drain channel output.
    tokio::time::sleep(Duration::from_millis(500)).await;
    crate::secure_state::StateDir::open(harness.root.path())
        .unwrap()
        .atomic_replace("sync-account.bundle", b"corrupt")
        .unwrap();
    timeout(Duration::from_secs(5), harness.connection.closed())
        .await
        .unwrap();
    harness.close().await;
}

#[tokio::test]
async fn channel_close_cleans_up_child_without_interrupting_other_channels() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .exec(
            true,
            format!(
                "printf ready; sleep 2; printf survived >'{}'",
                harness.root.path().join("should-not-exist").display()
            ),
        )
        .await
        .unwrap();
    timeout(DEADLINE, async {
        loop {
            if matches!(channel.wait().await, Some(ChannelMsg::Data { .. })) {
                break;
            }
        }
    })
    .await
    .unwrap();
    channel.close().await.unwrap();
    let another = client.channel_open_session().await.unwrap();
    another.exec(true, "printf independent").await.unwrap();
    another.eof().await.unwrap();
    assert_eq!(command_output(another).await.0, b"independent");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!harness.root.path().join("should-not-exist").exists());
    harness.close().await;
}

#[tokio::test]
async fn system_openssh_exec_over_authenticated_iroh() {
    use std::process::Stdio;
    let harness = Harness::new(|_| {}).await;
    let (send, receive, response) = harness.setup(&harness.capability).await.unwrap();
    let directory = crate::secure_state::StateDir::open(harness.root.path()).unwrap();
    directory
        .atomic_replace(
            "key",
            harness
                .client_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    directory
        .atomic_replace(
            "known_hosts",
            format!("attached-test {}\n", response.host_key).as_bytes(),
        )
        .unwrap();
    // Only a test adapter; production uses owner-only Unix IPC to OpenSSH.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let bridge = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, write) = stream.into_split();
        crate::proxy::copy_bidirectional_split(read, write, receive, send).await
    });
    let mut child = tokio::process::Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "HostKeyAlias=attached-test",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
        ])
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            harness.root.path().join("known_hosts").display()
        ))
        .arg("-i")
        .arg(harness.root.path().join("key"))
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{}@127.0.0.1", response.username))
        .arg("cat; printf tail; printf error >&2; exit 7")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let bytes = (0..1024 * 1024)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let input = bytes.clone();
    let writer = tokio::spawn(async move {
        stdin.write_all(&input).await.unwrap();
        drop(stdin);
    });
    let output = timeout(DEADLINE, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    writer.await.unwrap();
    assert_eq!(output.status.code(), Some(7), "{:?}", output.stderr);
    assert_eq!(output.stderr, b"error");
    let mut expected = bytes;
    expected.extend_from_slice(b"tail");
    assert_eq!(output.stdout, expected);
    harness.close().await;
    let _ = timeout(DEADLINE, bridge).await.unwrap();
}

#[tokio::test]
async fn ssh_session_channel_limit_is_bounded() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let mut channels = Vec::new();
    for _ in 0..10 {
        channels.push(client.channel_open_session().await.unwrap());
    }
    assert!(client.channel_open_session().await.is_err());
    harness.close().await;
}

#[tokio::test]
async fn interactive_pty_resizes_and_executes_with_a_controlling_terminal() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .request_pty(
            true,
            "xterm-256color",
            80,
            24,
            0,
            0,
            &[(russh::Pty::ECHO, 0)],
        )
        .await
        .unwrap();
    assert!(matches!(
        timeout(DEADLINE, channel.wait()).await.unwrap(),
        Some(ChannelMsg::Success)
    ));
    channel.exec(true, "test -t 0 && test -t 1 && test -t 2 || exit 9; printf 'READY\n'; read answer; stty size; printf '%s:%s' \"$TERM\" \"$answer\"; exit 7").await.unwrap();
    let mut prefix = Vec::new();
    timeout(DEADLINE, async {
        while !prefix.windows(5).any(|s| s == b"READY") {
            if let Some(ChannelMsg::Data { data }) = channel.wait().await {
                prefix.extend_from_slice(&data);
            }
        }
    })
    .await
    .unwrap();
    channel.window_change(120, 40, 0, 0).await.unwrap();
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let (output, errors, status) = command_output(channel).await;
    assert!(
        String::from_utf8_lossy(&output).contains("40 120"),
        "{output:?}"
    );
    assert!(output.ends_with(b"xterm-256color:hello"));
    assert!(errors.is_empty());
    assert_eq!(status, Some(7));
    harness.close().await;
}

#[tokio::test]
async fn pty_output_larger_than_kernel_buffer_does_not_deadlock() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(matches!(
        timeout(DEADLINE, channel.wait()).await.unwrap(),
        Some(ChannelMsg::Success)
    ));
    channel
        .exec(true, "head -c 262144 /dev/zero")
        .await
        .unwrap();
    let (output, _, status) = command_output(channel).await;
    assert_eq!(output, vec![0; 262144]);
    assert_eq!(status, Some(0));
    harness.close().await;
}

#[tokio::test]
async fn pty_eof_does_not_type_ctrl_d_into_the_persistent_terminal() {
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(matches!(
        timeout(DEADLINE, channel.wait()).await.unwrap(),
        Some(ChannelMsg::Success)
    ));
    let input = harness.root.path().join("terminal-input");
    channel
        .exec(
            true,
            format!(
                "stty raw -echo; printf ready; dd bs=1 count=1 of='{}' 2>/dev/null",
                input.display()
            ),
        )
        .await
        .unwrap();
    timeout(DEADLINE, async {
        while !matches!(channel.wait().await, Some(ChannelMsg::Data { .. })) {}
    })
    .await
    .unwrap();
    channel.eof().await.unwrap();
    // Another round-trip ensures EOF was processed before observing the PTY.
    let probe = client.channel_open_session().await.unwrap();
    probe.exec(true, "printf alive").await.unwrap();
    assert_eq!(command_output(probe).await.0, b"alive");
    channel.close().await.unwrap();
    harness.cancel.cancel();
    timeout(DEADLINE, harness.connection.closed())
        .await
        .unwrap();
    assert!(
        std::fs::read(input).unwrap_or_default().is_empty(),
        "transport EOF was injected as keyboard input"
    );
    harness.close().await;
}

#[tokio::test]
async fn streamlocal_supports_rpc_eof_and_subscription_alongside_exec() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let socket = harness.root.path().join("herdr.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut input = [0; 5];
        stream.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"ping\n");
        stream.write_all(b"pong\nevent\n").await.unwrap();
        // One-shot API close must reach SSH even without client EOF.
    });
    let channel = client
        .channel_open_direct_streamlocal(socket.to_str().unwrap())
        .await
        .unwrap();
    channel.data_bytes(b"ping\n".to_vec()).await.unwrap();
    let command = client.channel_open_session().await.unwrap();
    command.exec(true, "printf concurrent").await.unwrap();
    let (stream, exec) = tokio::join!(command_output(channel), command_output(command));
    assert_eq!(stream.0, b"pong\nevent\n");
    assert_eq!(exec.0, b"concurrent");
    server.await.unwrap();
    assert!(
        client
            .channel_open_direct_streamlocal("relative.sock")
            .await
            .is_err()
    );
    assert!(
        client
            .channel_open_direct_streamlocal(socket.to_str().unwrap())
            .await
            .is_err()
    );
    harness.close().await;
}
