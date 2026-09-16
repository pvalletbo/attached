//! Black-box tests: only the public protocol crates are linked here. All CLI
//! behavior (including production encryption/KDF) runs in CARGO_BIN_EXE_attached.
#[path = "ssh/renewal.rs"]
mod ssh_renewal;
mod support;

use std::{fs, net::Ipv4Addr, time::Duration};

use attached_session_sync_protocol::{
    account::{
        AccountBundle, AccountId, AccountRootKey, ApiToken, ConsumerIdentitySecret, RecordId,
        ScopedAccountBundle, ServiceOrigin,
    },
    api::{Envelope, LiveRecordIndex, LiveRecordIndexEntry},
    canonical::{AttachedVersion, HerdrVersion, SessionAccessDescriptor},
    crypto::seal_session_access_descriptor,
};
use attached_tunnel_protocol::{
    CapabilitySecret, TUNNEL_ALPN, authenticate_server, read_stream_header,
};
use iroh::{
    Endpoint, RelayMode,
    endpoint::{BindOpts, presets},
};
use iroh_tickets::endpoint::EndpointTicket;
use support::{CliFixture, DEADLINE, assert_private, request, respond};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

const ACCOUNT: &str = "01900000-0000-7000-8000-000000000001";
const ROOT_KEY: [u8; 32] = [42; 32];
const TOKEN: [u8; 32] = [43; 32];
const IDENTITY: [u8; 32] = [44; 32];
const RECORD: RecordId = RecordId::from_bytes([45; 16]);

fn bundle(origin: &str, identity: [u8; 32]) -> String {
    AccountBundle::Scoped(
        ScopedAccountBundle::from_download_parts(
            ServiceOrigin::parse(origin).unwrap(),
            AccountId::parse(ACCOUNT).unwrap(),
            ApiToken::from_bytes(TOKEN),
            AccountRootKey::from_bytes(ROOT_KEY),
            ConsumerIdentitySecret::from_bytes(identity),
        )
        .unwrap(),
    )
    .encode()
}

async fn import(fixture: &CliFixture, origin: &str) -> String {
    import_with_identity(fixture, origin, IDENTITY).await
}

async fn import_with_identity(fixture: &CliFixture, origin: &str, identity: [u8; 32]) -> String {
    let encoded = bundle(origin, identity);
    fs::write(fixture.path("download.bundle"), format!("{encoded}\n")).unwrap();
    let output = fixture
        .run(&[
            "--use-1password",
            "account",
            "import",
            "--bundle-file",
            "download.bundle",
        ])
        .await;
    output.assert_code(0);
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.contains(&encoded), "bundle leaked to stderr");
    encoded
}

fn catalog(endpoint: &str, revision: u64) -> (Vec<u8>, Vec<u8>) {
    let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let descriptor = SessionAccessDescriptor::new(
        "remote".into(),
        now - Duration::from_secs(1),
        now + Duration::from_secs(300),
        endpoint.into(),
        CapabilitySecret::from_bytes([46; 32]),
        AttachedVersion::new(0, 2, 9),
        HerdrVersion::new(3, 2, 1),
        vec!["work".into()],
    )
    .unwrap();
    let (nonce, ciphertext) = seal_session_access_descriptor(
        &descriptor,
        &ROOT_KEY,
        AccountId::parse(ACCOUNT).unwrap().as_bytes(),
        RECORD.as_bytes(),
    )
    .unwrap()
    .into_parts();
    let record = serde_json::to_vec(&Envelope::new(nonce, ciphertext).unwrap()).unwrap();
    let index = serde_json::to_vec(
        &LiveRecordIndex::new(vec![LiveRecordIndexEntry {
            record_id: RECORD,
            revision,
        }])
        .unwrap(),
    )
    .unwrap();
    (index, record)
}

async fn checked_request(listener: &TcpListener, record: bool) -> tokio::net::TcpStream {
    let (mut stream, _) = listener.accept().await.unwrap();
    let headers = request(&mut stream).await;
    let path = format!(
        "/v1/accounts/{ACCOUNT}/records{}",
        if record {
            format!("/{RECORD}")
        } else {
            String::new()
        }
    );
    assert_eq!(
        headers.lines().next().unwrap(),
        format!("GET {path} HTTP/1.1")
    );
    let authorization = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .collect::<Vec<_>>();
    assert_eq!(
        authorization,
        [format!("Bearer {}", ApiToken::from_bytes(TOKEN).encode())]
    );
    stream
}

struct MockSsh {
    key: russh::keys::PublicKey,
}
impl russh::server::Handler for MockSsh {
    type Error = anyhow::Error;
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> anyhow::Result<russh::server::Auth> {
        Ok(
            if user == "ssh-test" && key.key_data() == self.key.key_data() {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            },
        )
    }
    async fn channel_open_session(
        &mut self,
        _: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut russh::server::Session,
    ) -> anyhow::Result<()> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        command: &[u8],
        session: &mut russh::server::Session,
    ) -> anyhow::Result<()> {
        assert_eq!(command, b"printf expected");
        session.channel_success(channel)?;
        session.data(channel, b"expected".to_vec())?;
        session.extended_data(channel, 1, b"expected-error".to_vec())?;
        session.exit_status_request(channel, 7)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

#[tokio::test]
async fn ssh_command_provisions_credentials_invokes_openssh_and_preserves_exit_status() {
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    let fixture = CliFixture::new();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", http.local_addr().unwrap());
    // Each fixture owns a relay identity. Reusing the attachment fixture's
    // identity would let parallel test processes displace one another at n0.
    let consumer_identity = iroh::SecretKey::generate().to_bytes();
    import_with_identity(&fixture, &origin, consumer_identity).await;
    let publisher = Endpoint::builder(presets::N0)
        .clear_ip_transports()
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_prefix_len(8),
        )
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![attached_tunnel_protocol::SSH_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let (index, record) = catalog(&EndpointTicket::new(publisher.addr()).to_string(), 1);
    let http_task = tokio::spawn(async move {
        respond(&mut checked_request(&http, false).await, &index, "").await;
        respond(
            &mut checked_request(&http, true).await,
            &record,
            "ETag: \"1\"\r\n",
        )
        .await;
    });
    let endpoint = publisher.clone();
    let ssh_task = tokio::spawn(async move {
        let key = russh::keys::PrivateKey::new(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[77; 32]).into(),
            "test",
        )
        .unwrap();
        for _ in 0..2 {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            assert_eq!(
                connection.remote_id(),
                iroh::SecretKey::from_bytes(&consumer_identity).public()
            );
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let length = receive.read_u32().await.unwrap() as usize;
            assert!(length <= 8192);
            let mut bytes = vec![0; length];
            receive.read_exact(&mut bytes).await.unwrap();
            let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(request["capability"], serde_json::json!([46; 32].to_vec()));
            let public_key =
                russh::keys::PublicKey::from_openssh(request["public_key"].as_str().unwrap())
                    .unwrap();
            let response = serde_json::to_vec(&serde_json::json!({ "username": "ssh-test", "host_key": key.public_key().to_openssh().unwrap() })).unwrap();
            send.write_u32(response.len() as u32).await.unwrap();
            send.write_all(&response).await.unwrap();
            let config = russh::server::Config {
                keys: vec![key.clone()],
                ..Default::default()
            };
            if let Ok(session) = russh::server::run_stream(
                Arc::new(config),
                tokio::io::join(receive, send),
                MockSsh { key: public_key },
            )
            .await
            {
                let _ = session.await;
            }
            connection.close(0u32.into(), b"test completed");
        }
    });
    let output = fixture
        .run(&[
            "--use-1password",
            "ssh",
            "--no-cache",
            "remote",
            "printf expected",
        ])
        .await;
    output.assert_code(7);
    assert_eq!(output.stdout, "expected");
    assert_eq!(output.stderr, "expected-error");
    timeout(DEADLINE, http_task).await.unwrap().unwrap();
    timeout(DEADLINE, ssh_task).await.unwrap().unwrap();
    publisher.close().await;
    assert_private(&fixture.path("home/.config/attached/ssh-pins.json"));
    assert!(!fs::read_dir(fixture.path("tmp")).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("attached-ssh-")
    }));
}

#[tokio::test]
async fn ssh_local_proxy_preserves_binary_and_half_close_without_loading_credentials() {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    let fixture = CliFixture::new();
    fs::create_dir_all(fixture.path("home/.config/attached")).unwrap();
    fs::write(
        fixture.path("home/.config/attached/config.toml"),
        "invalid = [",
    )
    .unwrap();
    let socket = fixture.path("ssh.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut command = fixture.command(&["__ssh-local-proxy", socket.to_str().unwrap()]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = (0..256 * 1024).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let input = payload.clone();
    let mut stdin = child.stdin.take().unwrap();
    let writer = tokio::spawn(async move {
        stdin.write_all(&input).await.unwrap();
        drop(stdin);
    });
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        bytes.extend_from_slice(b"after-eof");
        stream.write_all(&bytes).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let output = timeout(DEADLINE, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    writer.await.unwrap();
    server.await.unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(output.stderr.is_empty());
    let mut expected = payload;
    expected.extend_from_slice(b"after-eof");
    assert_eq!(output.stdout, expected);
}

#[tokio::test]
async fn ssh_local_proxy_exits_on_peer_eof_even_when_openssh_keeps_stdin_open() {
    use std::process::Stdio;
    let fixture = CliFixture::new();
    let socket = fixture.path("ssh.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut command = fixture.command(&["__ssh-local-proxy", socket.to_str().unwrap()]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep the write end alive through process exit, as OpenSSH does while waiting
    // for ProxyCommand stdout EOF after a remote disconnect.
    let held_stdin = child.stdin.take().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"final-output").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let output = timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    drop(held_stdin);
    server.await.unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(output.stdout, b"final-output");
    assert!(output.stderr.is_empty());
}

#[tokio::test]
async fn help_version_completions_and_usage_errors_are_real_process_contracts() {
    let fixture = CliFixture::new();
    // These commands must bypass even invalid user configuration.
    fs::create_dir_all(fixture.path("home/.config/attached")).unwrap();
    fs::write(
        fixture.path("home/.config/attached/config.toml"),
        "not valid = [",
    )
    .unwrap();
    let help = fixture.run(&["--help"]).await;
    help.assert_code(0);
    assert!(help.stdout.contains("sessions"));
    assert!(!help.stdout.contains("__handoff-serve"));
    assert!(help.stderr.is_empty());
    let version = fixture.run(&["--version"]).await;
    version.assert_code(0);
    assert_eq!(
        version.stdout.trim(),
        concat!("attached ", env!("CARGO_PKG_VERSION"))
    );
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = fixture.run(&["completions", shell]).await;
        output.assert_code(0);
        assert!(output.stdout.contains("attached"), "{shell}: {output:?}");
        assert!(output.stderr.is_empty(), "{shell}: {output:?}");
    }
    for args in [
        vec!["unknown"],
        vec!["attach", "host/work", "--", "sh"],
        vec!["account", "import", "--bundle-file", "x", "--bundle-stdin"],
    ] {
        let output = fixture.run(&args).await;
        output.assert_code(2);
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(output.stderr.contains("error:"), "{output:?}");
    }
    let output = fixture.run(&["sessions", "list"]).await;
    output.assert_code(1);
    assert!(
        output
            .stderr
            .contains("could not load Attached configuration"),
        "{output:?}"
    );
}

#[tokio::test]
async fn account_roundtrip_uses_production_encryption_and_refuses_overwrite() {
    let fixture = CliFixture::new();
    let encoded = import(&fixture, "http://127.0.0.1:1").await;
    let account_path = fixture.path("home/.config/attached/sync-account.bundle");
    let stored = fs::read(&account_path).unwrap();
    assert!(stored.starts_with(b"ATSECR01"));
    assert!(
        !stored
            .windows(encoded.len())
            .any(|window| window == encoded.as_bytes())
    );
    assert_private(&account_path);
    let args = [
        "--use-1password",
        "account",
        "export",
        "--type",
        "download",
        "--output",
        "export.bundle",
    ];
    let output = fixture.run(&args).await;
    output.assert_code(0);
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.contains(&encoded));
    assert_eq!(
        fs::read_to_string(fixture.path("export.bundle")).unwrap(),
        format!("{encoded}\n")
    );
    assert_private(&fixture.path("export.bundle"));
    let output = fixture.run(&args).await;
    output.assert_code(1);
    assert_eq!(
        fs::read_to_string(fixture.path("export.bundle")).unwrap(),
        format!("{encoded}\n")
    );
    // Idempotent import must neither replace the encrypted account nor rotate its salt.
    let mut command = fixture.command(&["--use-1password", "account", "import", "--bundle-stdin"]);
    command.stdin(fs::File::open(fixture.path("download.bundle")).unwrap());
    fixture.spawn(command).wait().await.assert_code(0);
    assert_eq!(fs::read(account_path).unwrap(), stored);
    let output = fixture
        .run(&[
            "--use-1password",
            "account",
            "export",
            "--type",
            "publish",
            "--output",
            "publish.bundle",
        ])
        .await;
    output.assert_code(1);
    assert!(!fixture.path("publish.bundle").exists());
}

#[tokio::test]
async fn invalid_stdin_bundle_fails_without_installing_state_or_echoing_secrets() {
    let fixture = CliFixture::new();
    for input in [
        String::new(),
        "INVALID-SECRET-BUNDLE".into(),
        "x".repeat(attached_session_sync_protocol::limits::MAX_BUNDLE_ENCODED_BYTES + 3),
    ] {
        fs::write(fixture.path("input"), &input).unwrap();
        let mut command = fixture.command(&["account", "import", "--bundle-stdin"]);
        command.stdin(fs::File::open(fixture.path("input")).unwrap());
        let output = fixture.spawn(command).wait().await;
        output.assert_code(1);
        assert!(output.stdout.is_empty(), "{output:?}");
        if !input.is_empty() {
            assert!(!output.stderr.contains(&input), "invalid bundle was echoed");
        }
        assert!(
            !fixture
                .path("home/.config/attached/sync-account.bundle")
                .exists()
        );
        assert!(
            !fixture
                .path("home/.config/attached/encryption-salt.argon2id-v1")
                .exists()
        );
    }
}

fn assert_remote_listing(output: &support::CliOutput) {
    output.assert_code(0);
    let lines = output.stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2, "{output:?}");
    assert_eq!(
        lines[1].split_whitespace().take(4).collect::<Vec<_>>(),
        ["remote", "work", "0.2.9", "3.2.1"]
    );
}

#[tokio::test]
async fn catalog_cache_avoids_redundant_downloads_and_outage_never_prints_stale_sessions() {
    timeout(DEADLINE * 3, async {
        let fixture = CliFixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        import(&fixture, &format!("http://{}", listener.local_addr().unwrap())).await;
        let ticket = EndpointTicket::new(iroh::EndpointAddr::new(iroh::SecretKey::from_bytes(&[47; 32]).public())).to_string();
        let (index, record) = catalog(&ticket, 1);
        let server = async {
            respond(&mut checked_request(&listener, false).await, &index, "").await;
            respond(&mut checked_request(&listener, true).await, &record, "ETag: \"1\"\r\n").await;
            // A second invocation must fetch just the index, not the unchanged record.
            respond(&mut checked_request(&listener, false).await, &index, "").await;
            let mut dropped = checked_request(&listener, false).await;
            dropped.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 200\r\nConnection: close\r\n\r\n{\"records\":").await.unwrap();
            dropped.shutdown().await.unwrap();
            drop(dropped);
            respond(&mut checked_request(&listener, false).await, &index, "").await;
        };
        let client = async {
            let args = ["--use-1password", "sessions", "list"];
            let first = fixture.run(&args).await;
            assert_remote_listing(&first);
            let second = fixture.run(&args).await;
            assert_remote_listing(&second);
            let failed = fixture.run(&args).await;
            failed.assert_code(1);
            assert!(failed.stdout.is_empty(), "outage printed stale sessions: {failed:?}");
            assert!(failed.stderr.contains("could not refresh synchronized sessions"), "{failed:?}");
            let recovered = fixture.run(&args).await;
            assert_remote_listing(&recovered);
        };
        tokio::join!(server, client);
    }).await.expect("binary catalog scenario timed out");
}

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
        .alpns(vec![TUNNEL_ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn remote_attach_forwards_bytes_propagates_exit_and_cleans_up_after_connection_loss() {
    timeout(DEADLINE * 4, async {
        let fixture = CliFixture::new();
        fs::write(
            fixture.path("herdr_client.py"),
            include_str!("fixtures/remote_client.py"),
        )
        .unwrap();
        fixture.script(
            "herdr",
            r#"
case "$*" in
  --version) printf 'herdr 3.2.1\n';;
  client) exec /usr/bin/python3 "$FIXTURE_ROOT/herdr_client.py";;
  *) exit 91;;
esac
"#,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        import(
            &fixture,
            &format!("http://{}", listener.local_addr().unwrap()),
        )
        .await;
        let endpoint = endpoint().await;
        assert!(endpoint.addr().relay_urls().next().is_none());
        assert!(
            endpoint
                .addr()
                .ip_addrs()
                .all(|addr| addr.ip().is_loopback())
        );
        let ticket = EndpointTicket::new(endpoint.addr()).to_string();
        // Populate discovery, reuse it for the connection-loss attempt, then
        // explicitly refresh after pruning. Ordinary attachment does not auto-reconnect.
        for (attempt, mode) in ["exit", "drop", "exit"].into_iter().enumerate() {
            for marker in ["received", "proxy-socket", "herdr-pid"] {
                let _ = fs::remove_file(fixture.path(marker));
            }
            let revision = if attempt == 2 { 2 } else { 1 };
            let (index, record) = catalog(&ticket, revision);
            let http = async {
                respond(&mut checked_request(&listener, false).await, &index, "").await;
                respond(
                    &mut checked_request(&listener, true).await,
                    &record,
                    &format!("ETag: \"{revision}\"\r\n"),
                )
                .await;
            };
            let peer = async {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                assert_eq!(
                    connection.remote_id(),
                    iroh::SecretKey::from_bytes(&IDENTITY).public()
                );
                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                authenticate_server(
                    &mut receive,
                    &mut send,
                    &CapabilitySecret::from_bytes([46; 32]),
                    attached_tunnel_protocol::HerdrVersion::new(3, 2, 1),
                    |session| async move {
                        anyhow::ensure!(session == "work", "wrong session");
                        Ok(())
                    },
                    || Ok(()),
                )
                .await
                .unwrap();
                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                read_stream_header(&mut receive).await.unwrap();
                // Larger than the proxy copy buffer; deterministic bytes, both directions.
                let payload = receive.read_to_end(1024 * 1024).await.unwrap();
                assert_eq!(payload, (0..=255_u8).collect::<Vec<_>>().repeat(2048));
                send.write_all(&payload).await.unwrap();
                send.finish().unwrap();
                send.stopped().await.unwrap();
                if mode == "drop" {
                    let (_send, mut receive) = connection.accept_bi().await.unwrap();
                    read_stream_header(&mut receive).await.unwrap();
                    assert_eq!(receive.read_to_end(5).await.unwrap(), b"ready");
                    connection.close(17_u32.into(), b"injected connection loss");
                }
                connection.closed().await;
            };
            let client = async {
                let mut command = fixture.command(&["--use-1password", "attach", "remote/work"]);
                if attempt == 2 {
                    // The failed connection prunes this revision, but discovery is
                    // still cached. Explicitly request the replacement publication.
                    command.arg("--no-cache");
                }
                command.env("FIXTURE_MODE", mode);
                let output = fixture.spawn(command).wait().await;
                if mode == "exit" {
                    output.assert_code(23);
                } else {
                    output.assert_code(1);
                    assert!(output.stderr.contains("connection was lost"), "{output:?}");
                    assert!(output.stderr.contains("run `attach` again"), "{output:?}");
                }
                assert_eq!(
                    fs::read_to_string(fixture.path("received")).unwrap(),
                    "524288"
                );
                let socket = fs::read_to_string(fixture.path("proxy-socket")).unwrap();
                assert!(
                    !std::path::Path::new(&socket).exists(),
                    "proxy socket leaked"
                );
                let pid: i32 = fs::read_to_string(fixture.path("herdr-pid"))
                    .unwrap()
                    .parse()
                    .unwrap();
                let error = rustix::process::test_kill_process(
                    rustix::process::Pid::from_raw(pid).unwrap(),
                )
                .unwrap_err();
                assert_eq!(
                    error,
                    rustix::io::Errno::SRCH,
                    "Herdr child survived CLI exit"
                );
            };
            let exchange = async {
                tokio::join!(peer, client);
            };
            timeout(DEADLINE, async {
                if attempt == 1 {
                    // Keep the service listening so any unintended refresh fails
                    // immediately rather than leaving an HTTP fixture waiting forever.
                    tokio::select! {
                        biased;
                        unexpected = listener.accept() => {
                            panic!("cached attachment contacted the sync service: {unexpected:?}");
                        }
                        () = exchange => {}
                    }
                } else {
                    tokio::join!(http, exchange);
                }
            })
            .await
            .unwrap_or_else(|_| panic!("remote attachment attempt {attempt} ({mode}) timed out"));
        }
        endpoint.close().await;
    })
    .await
    .expect("binary remote attachment scenario timed out");
}
