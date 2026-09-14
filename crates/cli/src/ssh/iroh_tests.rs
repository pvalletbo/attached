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
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(20);

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::N0)
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
    async fn new(change_policy: impl FnOnce(&mut state::Policy)) -> Self {
        let root = crate::test_support::canonical_tempdir();
        crate::secure_state::prepare_private_dir(root.path()).unwrap();
        let publisher = endpoint().await;
        let consumer = endpoint().await;
        let mut policy = state::Policy {
            consumer: *consumer.id().as_bytes(),
            uid: rustix::process::geteuid().as_raw(),
            username: "attached-test".into(),
            home: root.path().to_owned(),
            shell: "/bin/sh".into(),
            enabled: true,
            generation: [1; 32],
        };
        change_policy(&mut policy);
        crate::secure_state::StateDir::open(root.path())
            .unwrap()
            .atomic_replace("ssh-access.json", &serde_json::to_vec(&policy).unwrap())
            .unwrap();
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
                    "attached-test",
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
async fn iroh_rejects_wrong_consumer_revoked_policy_and_capability() {
    for mutation in 0..3 {
        let harness = Harness::new(|policy| match mutation {
            0 => policy.consumer = [0; 32],
            1 => policy.enabled = false,
            _ => {}
        })
        .await;
        let capability = if mutation == 2 {
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
                .authenticate_none("attached-test")
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
                    if wrong_user { "root" } else { "attached-test" },
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
async fn iroh_rejects_pty_env_subsystems_and_forwarding() {
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
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
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
async fn revocation_cancels_active_command_process_group() {
    let mut harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .exec(
            true,
            "printf ready; sleep 2; printf survived >should-not-exist",
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
    harness.policy.enabled = false;
    crate::secure_state::StateDir::open(harness.root.path())
        .unwrap()
        .atomic_replace(
            "ssh-access.json",
            &serde_json::to_vec(&harness.policy).unwrap(),
        )
        .unwrap();
    timeout(Duration::from_secs(5), harness.connection.closed())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!harness.root.path().join("should-not-exist").exists());
    harness.close().await;
}

#[tokio::test]
async fn revocation_stops_backpressured_output_without_hanging_shutdown() {
    let mut harness = Harness::new(|_| {}).await;
    let client = harness.authenticated().await;
    let channel = client.channel_open_session().await.unwrap();
    channel
        .exec(true, "exec /usr/bin/yes output")
        .await
        .unwrap();
    // Deliberately never drain channel output.
    tokio::time::sleep(Duration::from_millis(500)).await;
    harness.policy.enabled = false;
    crate::secure_state::StateDir::open(harness.root.path())
        .unwrap()
        .atomic_replace(
            "ssh-access.json",
            &serde_json::to_vec(&harness.policy).unwrap(),
        )
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
            "printf ready; sleep 2; printf survived >should-not-exist",
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
        .arg("attached-test@127.0.0.1")
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
    for _ in 0..8 {
        channels.push(client.channel_open_session().await.unwrap());
    }
    assert!(client.channel_open_session().await.is_err());
    harness.close().await;
}
