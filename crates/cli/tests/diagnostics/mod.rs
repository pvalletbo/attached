//! Exercise production encryption, real SSH authentication, broker IPC, and watch cleanup.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

struct ProbeSsh {
    key: russh::keys::PublicKey,
    authenticated: Arc<AtomicUsize>,
    channels: Arc<AtomicUsize>,
}

impl russh::server::Handler for ProbeSsh {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> anyhow::Result<russh::server::Auth> {
        if user == "ssh-test" && key.key_data() == self.key.key_data() {
            self.authenticated.fetch_add(1, Ordering::SeqCst);
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _: russh::Channel<russh::server::Msg>,
        _: russh::server::ChannelOpenHandle,
        _: &mut russh::server::Session,
    ) -> anyhow::Result<()> {
        self.channels.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("a diagnostic must not open a remote session");
    }
}

struct Rig {
    fixture: CliFixture,
    publisher: Endpoint,
    backend: tokio::task::JoinHandle<()>,
    ssh: tokio::task::JoinHandle<()>,
    discovery_down: Arc<AtomicBool>,
    reject: Arc<AtomicBool>,
    stall: Arc<AtomicBool>,
    started: Arc<AtomicUsize>,
    authenticated: Arc<AtomicUsize>,
    channels: Arc<AtomicUsize>,
    bundle: String,
}

impl Rig {
    async fn new() -> Self {
        let fixture = CliFixture::new();
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", http.local_addr().unwrap());
        let identity = iroh::SecretKey::generate().to_bytes();
        let bundle = import_with_identity(&fixture, &origin, identity).await;
        let publisher = Endpoint::builder(presets::N0)
            .clear_ip_transports()
            .bind_addr_with_opts(
                (Ipv4Addr::LOCALHOST, 0),
                BindOpts::default().set_prefix_len(8),
            )
            .unwrap()
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .alpns(vec![SSH_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let (index, record) = catalog(&EndpointTicket::new(publisher.addr()).to_string(), 1);
        let discovery_down = Arc::new(AtomicBool::new(false));
        let down = discovery_down.clone();
        let backend = tokio::spawn(async move {
            loop {
                let (mut stream, _) = http.accept().await.unwrap();
                let headers = request(&mut stream).await;
                assert!(
                    headers.contains(&format!("Bearer {}", ApiToken::from_bytes(TOKEN).encode()))
                );
                if down.load(Ordering::SeqCst) {
                    stream.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                } else if headers
                    .lines()
                    .next()
                    .unwrap()
                    .contains(&format!("/records/{RECORD} "))
                {
                    respond(&mut stream, &record, "ETag: \"1\"\r\n").await;
                } else {
                    respond(&mut stream, &index, "").await;
                }
            }
        });
        let authenticated = Arc::new(AtomicUsize::new(0));
        let channels = Arc::new(AtomicUsize::new(0));
        let reject = Arc::new(AtomicBool::new(false));
        let stall = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicUsize::new(0));
        let stalled = stall.clone();
        let begun = started.clone();
        let endpoint = publisher.clone();
        let auth = authenticated.clone();
        let opened = channels.clone();
        let denied = reject.clone();
        let ssh = tokio::spawn(async move {
            let key = russh::keys::PrivateKey::new(
                russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[77; 32]).into(),
                "test",
            )
            .unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let key = key.clone();
                        let authenticated = auth.clone();
                        let channels = opened.clone();
                        let reject = denied.load(Ordering::SeqCst);
                        let stall = stalled.load(Ordering::SeqCst);
                        let started = begun.clone();
                        tasks.spawn(async move {
                            let Ok(connection) = incoming.await else { return; };
                            started.fetch_add(1, Ordering::SeqCst);
                            if stall {
                                connection.closed().await;
                                return;
                            }
                            assert_eq!(connection.remote_id(), iroh::SecretKey::from_bytes(&identity).public());
                            let Ok((mut send, mut receive)) = connection.accept_bi().await else { return; };
                            if reject {
                                connection.close(0u32.into(), b"access denied");
                                return;
                            }
                            let length = receive.read_u32().await.unwrap() as usize;
                            assert!(length <= 8192);
                            let mut bytes = vec![0; length];
                            receive.read_exact(&mut bytes).await.unwrap();
                            let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                            assert_eq!(request["capability"], serde_json::json!([46; 32].to_vec()));
                            let public_key = russh::keys::PublicKey::from_openssh(request["public_key"].as_str().unwrap()).unwrap();
                            let response = serde_json::to_vec(&serde_json::json!({
                                "username": "ssh-test", "host_key": key.public_key().to_openssh().unwrap(),
                            })).unwrap();
                            send.write_u32(response.len() as u32).await.unwrap();
                            send.write_all(&response).await.unwrap();
                            if let Ok(session) = russh::server::run_stream(
                                Arc::new(russh::server::Config { keys: vec![key], ..Default::default() }),
                                tokio::io::join(receive, send),
                                ProbeSsh { key: public_key, authenticated, channels },
                            ).await {
                                let _ = session.await;
                            }
                            connection.close(0u32.into(), b"test completed");
                        });
                    }
                    completed = tasks.join_next(), if !tasks.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                }
            }
        });
        Self {
            fixture,
            publisher,
            backend,
            ssh,
            discovery_down,
            reject,
            stall,
            started,
            authenticated,
            channels,
            bundle,
        }
    }

    async fn run(&self, command: &str) -> (support::CliOutput, serde_json::Value) {
        let output = self
            .fixture
            .run(&["--use-1password", command, "--json", "--timeout", "3"])
            .await;
        let value = serde_json::from_str(&output.stdout).unwrap_or_else(|_| panic!("{output:?}"));
        for secret in [
            &self.bundle,
            "fixture-only-encryption-password",
            &ApiToken::from_bytes(TOKEN).encode(),
            "endpoint_ticket",
            "attach_capability",
            "consumer_identity_secret",
        ] {
            assert!(!output.stdout.contains(secret), "{output:?}");
            assert!(!output.stderr.contains(secret), "{output:?}");
        }
        (output, value)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.backend.abort();
        self.ssh.abort();
    }
}

#[tokio::test]
async fn doctor_and_status_authenticate_without_commands_or_trust_changes_and_use_cached_hosts_on_outage()
 {
    let rig = Rig::new().await;
    for command in ["doctor", "status"] {
        let (output, report) = rig.run(command).await;
        output.assert_code(0);
        assert_eq!(report["healthy"], true, "{output:?}");
        assert_eq!(report["discovery"], "refreshed");
        assert_eq!(report["hosts"][0]["online"], true);
        assert_eq!(report["hosts"][0]["connection"]["path"], "direct");
        assert!(report["hosts"][0]["connection"]["rtt_ms"].is_u64());
        assert!(report["broker"]["pid"].is_u64());
        assert!(report["broker"]["leases"].as_u64().unwrap() >= 1);
        assert!(
            !rig.fixture
                .path("home/.config/attached/ssh-pins.json")
                .exists()
        );
        assert!(!rig.fixture.path("home/.ssh/config").exists());
    }
    for password in [None, Some("wrong-password-redaction-canary")] {
        let mut command = rig.fixture.command(&["doctor", "--json"]);
        if let Some(password) = password {
            command.env("ATTACHED_ENCRYPTION_PASSWORD", password);
        }
        let output = rig.fixture.spawn(command).wait().await;
        output.assert_code(1);
        let report: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(report["healthy"], false);
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| check["name"] == "credentials" && check["status"] == "fail")
        );
        assert!(!output.stdout.contains("wrong-password-redaction-canary"));
        assert!(!output.stderr.contains("wrong-password-redaction-canary"));
    }
    assert!(rig.authenticated.load(Ordering::SeqCst) >= 2);
    assert_eq!(rig.channels.load(Ordering::SeqCst), 0);
    rig.discovery_down.store(true, Ordering::SeqCst);
    let (output, report) = rig.run("status").await;
    output.assert_code(1);
    assert_eq!(report["healthy"], false);
    assert_eq!(report["discovery"], "cached");
    assert_eq!(report["hosts"][0]["online"], true, "{output:?}");
    rig.publisher.close().await;
}

#[tokio::test]
async fn status_does_not_equate_advertisement_with_access_or_availability() {
    let rig = Rig::new().await;
    rig.reject.store(true, Ordering::SeqCst);
    let (output, report) = rig.run("status").await;
    output.assert_code(1);
    assert_eq!(report["hosts"][0]["online"], false);
    assert_eq!(report["hosts"][0]["failure"], "access_denied");
    rig.publisher.close().await;
    let (output, report) = rig.run("status").await;
    output.assert_code(1);
    assert_eq!(report["hosts"][0]["online"], false);
    assert!(
        ["timed_out", "unreachable"].contains(&report["hosts"][0]["failure"].as_str().unwrap())
    );
}

#[tokio::test]
async fn doctor_reports_bad_configuration_and_locked_or_missing_credentials_as_json() {
    let fixture = CliFixture::new();
    for command in ["doctor", "status"] {
        let output = fixture.run(&[command, "--json"]).await;
        output.assert_code(1);
        let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(value["healthy"], false);
        assert!(
            value["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| check["name"] == "credentials" && check["status"] == "fail")
        );
    }
    fs::write(
        fixture.path("home/.config/attached/config.toml"),
        "secret-value = [",
    )
    .unwrap();
    let output = fixture.run(&["doctor", "--json"]).await;
    output.assert_code(1);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(value["checks"][0]["name"], "configuration");
    assert!(!output.stdout.contains("secret-value"));
    assert!(!output.stderr.contains("secret-value"));
}

#[tokio::test]
async fn status_checks_existing_pins_without_overwriting_them_and_rejects_unknown_targets() {
    let rig = Rig::new().await;
    let pins = rig.fixture.path("home/.config/attached/ssh-pins.json");
    let bytes = serde_json::to_vec(&serde_json::json!({
        rig.publisher.id().to_string(): ["other-user", "ssh-ed25519 wrong-key"]
    }))
    .unwrap();
    fs::write(&pins, &bytes).unwrap();
    fs::set_permissions(&pins, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let (output, report) = rig.run("doctor").await;
    output.assert_code(1);
    assert_eq!(report["hosts"][0]["failure"], "identity_mismatch");
    assert_eq!(fs::read(&pins).unwrap(), bytes);
    fs::write(&pins, b"not-json").unwrap();
    let (output, report) = rig.run("status").await;
    output.assert_code(1);
    assert_eq!(report["hosts"][0]["failure"], "unavailable", "{output:?}");
    assert_eq!(fs::read(&pins).unwrap(), b"not-json");
    let output = rig
        .fixture
        .run(&["--use-1password", "status", "missing", "--json"])
        .await;
    output.assert_code(1);
    let report: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(report["hosts"].as_array().unwrap().is_empty());
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "target")
    );
    rig.publisher.close().await;
}

#[tokio::test]
async fn live_probe_deadline_and_sigterm_cancel_stalled_publishers() {
    use std::process::Stdio;
    let rig = Rig::new().await;
    rig.stall.store(true, Ordering::SeqCst);
    let output = rig
        .fixture
        .run(&["--use-1password", "doctor", "--json", "--timeout", "1"])
        .await;
    output.assert_code(1);
    let report: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(report["hosts"][0]["failure"], "timed_out", "{output:?}");
    let before = rig.started.load(Ordering::SeqCst);
    let mut child = rig
        .fixture
        .command(&[
            "--use-1password",
            "status",
            "--watch",
            "--json",
            "--timeout",
            "120",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    timeout(DEADLINE, async {
        while rig.started.load(Ordering::SeqCst) == before {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let pid = rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    assert!(
        timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert_eq!(rig.channels.load(Ordering::SeqCst), 0);
    rig.publisher.close().await;
}

#[tokio::test]
async fn watch_emits_ndjson_snapshots_reuses_broker_and_handles_sigterm() {
    use std::process::Stdio;
    let rig = Rig::new().await;
    let mut child = rig
        .fixture
        .command(&[
            "--use-1password",
            "status",
            "--watch",
            "--json",
            "--interval",
            "1",
            "--timeout",
            "3",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let first: serde_json::Value = serde_json::from_str(
        &timeout(DEADLINE, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    rig.discovery_down.store(true, Ordering::SeqCst);
    let second: serde_json::Value = serde_json::from_str(
        &timeout(DEADLINE, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first["hosts"][0]["online"], true, "{first}");
    assert_eq!(second["hosts"][0]["online"], true, "{second}");
    assert_eq!(first["broker"]["pid"], second["broker"]["pid"]);
    assert_eq!(second["healthy"], false);
    rig.discovery_down.store(false, Ordering::SeqCst);
    let third: serde_json::Value = serde_json::from_str(
        &timeout(DEADLINE, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(third["healthy"], true, "{third}");
    assert_eq!(second["broker"]["pid"], third["broker"]["pid"]);
    let pid = rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    assert!(
        timeout(DEADLINE, child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert_eq!(rig.channels.load(Ordering::SeqCst), 0);
    rig.publisher.close().await;
}
