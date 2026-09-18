//! Real OpenSSH reads the installed *user* configuration (not a broker's -F
//! snippet). -F only isolates the test from the OS account's actual ~/.ssh/config:
//! OpenSSH intentionally resolves that default via getpwuid, not the HOME variable.
#[path = "workspaces.rs"]
mod workspaces;

use super::ssh_renewal::{StreamSsh, round_trip, ssh};
use super::*;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::AsyncReadExt,
    sync::Mutex,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

struct Publication {
    revision: u64,
    bytes: Vec<u8>,
}
type Publications = Arc<Mutex<Option<BTreeMap<RecordId, Publication>>>>;

struct Discovery {
    origin: String,
    records: Publications,
    requests: Arc<AtomicUsize>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Discovery {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let records = Arc::new(Mutex::new(Some(BTreeMap::<RecordId, Publication>::new())));
        let requests = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let task = {
            let records = records.clone();
            let requests = requests.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = tokio::select! { _ = cancel.cancelled() => break, stream = listener.accept() => stream.unwrap() };
                    let Some(headers) = request_optional(&mut stream).await else {
                        continue;
                    };
                    let path = headers.split_whitespace().nth(1).unwrap();
                    requests.fetch_add(1, Ordering::SeqCst);
                    let mut records = records.lock().await;
                    if let Some(records) = records.as_mut() {
                        let prefix = format!("/v1/accounts/{ACCOUNT}/records");
                        if headers.starts_with("PUT ") {
                            let id =
                                RecordId::parse(path.strip_prefix(&format!("{prefix}/")).unwrap())
                                    .unwrap();
                            let length = headers
                                .lines()
                                .filter_map(|line| line.split_once(':'))
                                .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                                .unwrap()
                                .1
                                .trim()
                                .parse::<usize>()
                                .unwrap();
                            assert!(length <= 16384);
                            let mut bytes = vec![0; length];
                            stream.read_exact(&mut bytes).await.unwrap();
                            let revision = records.get(&id).map_or(1, |record| record.revision + 1);
                            records.insert(id, Publication { revision, bytes });
                            reply(
                                &mut stream,
                                "204 No Content",
                                b"",
                                &format!("ETag: \"{revision}\"\r\n"),
                            )
                            .await;
                            continue;
                        }
                        if path == prefix {
                            let index = LiveRecordIndex::new(
                                records
                                    .iter()
                                    .map(|(id, record)| LiveRecordIndexEntry {
                                        record_id: *id,
                                        revision: record.revision,
                                    })
                                    .collect(),
                            )
                            .unwrap();
                            reply(
                                &mut stream,
                                "200 OK",
                                &serde_json::to_vec(&index).unwrap(),
                                "",
                            )
                            .await;
                        } else {
                            let id =
                                RecordId::parse(path.strip_prefix(&format!("{prefix}/")).unwrap())
                                    .unwrap();
                            if let Some(record) = records.get(&id) {
                                reply(
                                    &mut stream,
                                    "200 OK",
                                    &record.bytes,
                                    &format!("ETag: \"{}\"\r\n", record.revision),
                                )
                                .await;
                            } else {
                                reply(&mut stream, "404 Not Found", b"", "").await;
                            }
                        }
                    } else {
                        reply(&mut stream, "503 Unavailable", b"", "").await;
                    }
                }
            })
        };
        Self {
            origin,
            records,
            requests,
            cancel,
            task,
        }
    }

    async fn stop(self) {
        self.cancel.cancel();
        timeout(DEADLINE, self.task).await.unwrap().unwrap();
    }
}

// Cancellation may close an accepted connection before headers or during the
// response. That is an expected client shutdown, not a fixture protocol failure.
async fn request_optional(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.ok()?);
        assert!(bytes.len() <= 8192);
    }
    Some(String::from_utf8(bytes).unwrap())
}

async fn reply(stream: &mut tokio::net::TcpStream, status: &str, body: &[u8], etag: &str) {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if stream.write_all(headers.as_bytes()).await.is_ok() {
        let _ = stream.write_all(body).await;
    }
}

struct Publisher {
    endpoint: Endpoint,
    record: RecordId,
    commands: Arc<AtomicUsize>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Publisher {
    async fn new(consumer: [u8; 32], seed: u8) -> Self {
        let endpoint = Endpoint::builder(presets::N0)
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
        let cancel = CancellationToken::new();
        let commands = Arc::new(AtomicUsize::new(0));
        let task = {
            let endpoint = endpoint.clone();
            let cancel = cancel.clone();
            let commands = commands.clone();
            tokio::spawn(async move {
                let key = russh::keys::PrivateKey::new(
                    russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]).into(),
                    "test",
                )
                .unwrap();
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        incoming = endpoint.accept() => {
                            let incoming = incoming.unwrap(); let key = key.clone(); let commands = commands.clone();
                            tasks.spawn(async move {
                                let connection = incoming.await.unwrap();
                                assert_eq!(connection.remote_id(), iroh::SecretKey::from_bytes(&consumer).public());
                                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                                let length = receive.read_u32().await.unwrap() as usize;
                                assert!(length <= 8192);
                                let mut bytes = vec![0; length]; receive.read_exact(&mut bytes).await.unwrap();
                                let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                                assert_eq!(request["capability"], serde_json::json!([46; 32].to_vec()));
                                let client_key = russh::keys::PublicKey::from_openssh(request["public_key"].as_str().unwrap()).unwrap();
                                let response = serde_json::to_vec(&serde_json::json!({"username": "ssh-test", "host_key": key.public_key().to_openssh().unwrap()})).unwrap();
                                send.write_u32(response.len() as u32).await.unwrap(); send.write_all(&response).await.unwrap();
                                let config = russh::server::Config { keys: vec![key], ..Default::default() };
                                if let Ok(session) = russh::server::run_stream(Arc::new(config), tokio::io::join(receive, send), StreamSsh { key: client_key, commands, streams: Default::default() }).await { let _ = session.await; }
                                connection.close(0u32.into(), b"test ended");
                            });
                        }
                        task = tasks.join_next(), if !tasks.is_empty() => { task.unwrap().unwrap(); }
                    }
                }
                tasks.abort_all();
                while let Some(result) = tasks.join_next().await {
                    if let Err(error) = result {
                        assert!(error.is_cancelled(), "SSH publisher panicked: {error}");
                    }
                }
            })
        };
        Self {
            endpoint,
            record: RecordId::from_bytes([seed; 16]),
            commands,
            cancel,
            task,
        }
    }

    fn publication(&self, label: &str, revision: u64, enabled: bool, lifetime: u64) -> Publication {
        let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
        let descriptor = HostAccessDescriptor::new(
            label.into(),
            now - Duration::from_secs(65),
            now + Duration::from_secs(lifetime),
            EndpointTicket::new(self.endpoint.addr()).to_string(),
            CapabilitySecret::from_bytes([46; 32]),
            AttachedVersion::new(0, 2, 14),
            enabled,
        )
        .unwrap();
        let (nonce, ciphertext) = seal_host_access_descriptor(
            &descriptor,
            &ROOT_KEY,
            AccountId::parse(ACCOUNT).unwrap().as_bytes(),
            self.record.as_bytes(),
        )
        .unwrap()
        .into_parts();
        Publication {
            revision,
            bytes: serde_json::to_vec(&Envelope::new(nonce, ciphertext).unwrap()).unwrap(),
        }
    }

    async fn advertise(
        &self,
        discovery: &Discovery,
        label: &str,
        revision: u64,
        enabled: bool,
        lifetime: u64,
    ) {
        discovery.records.lock().await.as_mut().unwrap().insert(
            self.record,
            self.publication(label, revision, enabled, lifetime),
        );
    }

    async fn stop(self) {
        self.cancel.cancel();
        timeout(DEADLINE, self.task).await.unwrap().unwrap();
        self.endpoint.close().await;
    }
}

async fn wait_config(fixture: &CliFixture, check: impl Fn(&str) -> bool) -> String {
    timeout(DEADLINE, async {
        loop {
            let content =
                fs::read_to_string(fixture.path("home/.ssh/attached/config")).unwrap_or_default();
            if check(&content) {
                return content;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "configuration never converged; current config: {}\nexporter stdout: {}\nexporter stderr: {}",
            fs::read_to_string(fixture.path("home/.ssh/attached/config")).unwrap_or_default(),
            fs::read_to_string(fixture.path("export.stdout")).unwrap_or_default(),
            fs::read_to_string(fixture.path("export.stderr")).unwrap_or_default()
        )
    })
}

fn start(fixture: &CliFixture) -> tokio::process::Child {
    start_with(fixture, &[])
}

fn start_with(fixture: &CliFixture, extra: &[&str]) -> tokio::process::Child {
    fixture
        .command(&[
            "--use-1password",
            "export-ssh-config",
            "--refresh-interval",
            "1",
        ])
        .args(extra)
        .stdout(fs::File::create(fixture.path("export.stdout")).unwrap())
        .stderr(fs::File::create(fixture.path("export.stderr")).unwrap())
        .spawn()
        .unwrap()
}

async fn stop(broker: tokio::process::Child, signal: rustix::process::Signal) {
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(broker.id().unwrap() as i32).unwrap(),
        signal,
    )
    .unwrap();
    let output = timeout(DEADLINE, broker.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "exporter failed: {output:?}");
}

async fn check_command(config: &Path, alias: &str) {
    let output = timeout(DEADLINE, ssh(config, alias, "printf expected").output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(7),
        "{alias}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"expected");
    assert_eq!(output.stderr, b"expected-error");
}

fn runtime_files(configuration: &str) -> Vec<PathBuf> {
    configuration
        .lines()
        .filter_map(|line| line.trim().strip_prefix("IdentityFile "))
        .map(|path| PathBuf::from(path.trim_matches('"')))
        .collect()
}

#[tokio::test]
async fn exporter_autodiscovers_all_hosts_and_reconciles_aliases_without_interrupting_streams() {
    let fixture = CliFixture::new();
    let discovery = Discovery::new().await;
    let consumer = iroh::SecretKey::generate().to_bytes();
    import_with_identity(&fixture, &discovery.origin, consumer).await;
    let office = Publisher::new(consumer, 61).await;
    let laptop = Publisher::new(consumer, 62).await;
    // Start with an empty account catalog: no host argument or follow-up command.
    fs::create_dir(fixture.path("home/.ssh")).unwrap();
    let config = fixture.path("home/.ssh/config");
    let personal = b"# personal config\nHost personal\n  HostName personal.example\n  User original\nHost *\n  User unwanted\n  ProxyCommand false\n  RequestTTY force\n  StrictHostKeyChecking no\n";
    fs::write(&config, personal).unwrap();
    let broker = start(&fixture);
    wait_config(&fixture, |text| text.contains("Host attached-*\n")).await;
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .starts_with("# BEGIN Attached")
    );
    assert!(!fixture.path("home/.ssh/attached/config").is_symlink());
    let duplicate = fixture.run(&["--use-1password", "export-ssh-config"]).await;
    assert!(!duplicate.status.success());
    assert!(
        duplicate.stderr.contains("already running"),
        "{duplicate:?}"
    );

    office.advertise(&discovery, "Office", 1, true, 300).await;
    let configured = wait_config(&fixture, |text| text.contains(" attached-office\n")).await;
    let mut files = runtime_files(&configured);
    for file in &files {
        assert_private(file);
    }
    check_command(&config, "attached-office").await;
    let mut active = ssh(&config, "attached-office", "cat")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = active.stdin.take().unwrap();
    let mut stdout = active.stdout.take().unwrap();
    round_trip(&mut stdin, &mut stdout, b"before-discovery\0\xff\n").await;

    // The initial unlock suffices for hosts added later: no account reload/op call.
    fs::remove_file(fixture.path("home/.config/attached/sync-account.bundle")).unwrap();
    fs::remove_file(fixture.path("bin/op")).unwrap();
    laptop.advertise(&discovery, "Laptop", 1, true, 300).await;
    let configured = wait_config(&fixture, |text| text.contains(" attached-laptop\n")).await;
    files.extend(runtime_files(&configured));
    let mut clients = JoinSet::new();
    for alias in [
        "attached-office",
        "attached-laptop",
        "attached-office",
        "attached-laptop",
    ] {
        let config = config.clone();
        clients.spawn(async move {
            check_command(&config, alias).await;
        });
    }
    while let Some(result) = clients.join_next().await {
        result.unwrap();
    }

    // An existing wildcard must not override Attached policy; ordinary hosts
    // retain their own settings and do not inherit the final generated Host block.
    let evaluated = tokio::process::Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&config)
        .arg("personal")
        .output()
        .await
        .unwrap();
    assert!(evaluated.status.success());
    let evaluated = String::from_utf8(evaluated.stdout).unwrap();
    assert!(evaluated.contains("hostname personal.example\n"));
    assert!(evaluated.contains("user original\n"));
    assert!(evaluated.contains("stricthostkeychecking false\n"));
    assert!(evaluated.contains("proxycommand false\n"));

    // Case-insensitive duplicates lose only the friendly alias. Stable IDs still
    // connect, and a removed alias fails locally instead of falling back to DNS.
    laptop.advertise(&discovery, "OFFICE", 2, true, 300).await;
    wait_config(&fixture, |text| {
        !text.contains(" attached-office\n") && !text.contains(" attached-laptop\n")
    })
    .await;
    check_command(&config, &format!("attached-{}", office.endpoint.id())).await;
    check_command(&config, &format!("attached-{}", laptop.endpoint.id())).await;
    let failed = timeout(
        DEADLINE,
        ssh(&config, "attached-office", "printf expected").output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(failed.status.code(), Some(255));
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("Could not resolve hostname"));
    round_trip(&mut stdin, &mut stdout, b"after-label-collision\n").await;

    laptop.advertise(&discovery, "Renamed", 3, true, 300).await;
    wait_config(&fixture, |text| {
        text.contains(" attached-renamed\n") && text.contains(" attached-office\n")
    })
    .await;
    laptop.advertise(&discovery, "Renamed", 4, false, 300).await;
    wait_config(&fixture, |text| {
        !text.contains(&format!("Host attached-{} ", laptop.endpoint.id()))
    })
    .await;
    discovery
        .records
        .lock()
        .await
        .as_mut()
        .unwrap()
        .remove(&office.record);
    wait_config(&fixture, |text| !text.contains("IdentityFile")).await;
    round_trip(&mut stdin, &mut stdout, b"after-unpublication\n").await;
    assert_eq!(office.commands.load(Ordering::SeqCst), 5);
    assert_eq!(laptop.commands.load(Ordering::SeqCst), 3);
    // User edits made during the foreground session survive cleanup byte-for-byte.
    let mut modified = fs::read(&config).unwrap();
    modified.extend_from_slice(b"# new personal setting\n");
    fs::write(&config, modified).unwrap();
    stop(broker, rustix::process::Signal::INT).await;
    assert_eq!(
        fs::read(&config).unwrap(),
        [personal.as_slice(), b"# new personal setting\n"].concat()
    );
    for file in files {
        assert!(
            !file.exists(),
            "temporary key survived shutdown: {}",
            file.display()
        );
    }
    let ended = timeout(DEADLINE, active.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !ended.status.success(),
        "active stream was not cancelled on broker shutdown"
    );
    office.stop().await;
    laptop.stop().await;
    discovery.stop().await;
}

#[tokio::test]
async fn exporter_retains_live_hosts_during_outages_expires_aliases_and_recovers() {
    let fixture = CliFixture::new();
    let discovery = Discovery::new().await;
    let consumer = iroh::SecretKey::generate().to_bytes();
    import_with_identity(&fixture, &discovery.origin, consumer).await;
    let office = Publisher::new(consumer, 63).await;
    office.advertise(&discovery, "Office", 1, true, 300).await;
    let broker = start(&fixture);
    wait_config(&fixture, |text| text.contains(" attached-office\n")).await;
    let config = fixture.path("home/.ssh/config");
    let mut active = ssh(&config, "attached-office", "cat")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = active.stdin.take().unwrap();
    let mut stdout = active.stdout.take().unwrap();
    round_trip(&mut stdin, &mut stdout, b"live\n").await;
    // Prove outage reuse with a long lease; do not race a real OpenSSH handshake
    // against a short expiration when the workspace tests run in parallel.
    *discovery.records.lock().await = None;
    let before = discovery.requests.load(Ordering::SeqCst);
    timeout(DEADLINE, async {
        while discovery.requests.load(Ordering::SeqCst) == before {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    check_command(&config, "attached-office").await;
    // Replace the fixture snapshot atomically: publishing a transient empty
    // index would legitimately retire the broker before the short lease arrives.
    *discovery.records.lock().await = Some(BTreeMap::from([(
        office.record,
        office.publication("Expiring", 2, true, 10),
    )]));
    // Rename confirms that the short-lived revision has reached the exporter.
    wait_config(&fixture, |text| text.contains(" attached-expiring\n")).await;
    *discovery.records.lock().await = None;
    wait_config(&fixture, |text| !text.contains("IdentityFile")).await;
    let failed = timeout(
        DEADLINE,
        ssh(&config, "attached-expiring", "printf expected").output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(failed.status.code(), Some(255));
    round_trip(&mut stdin, &mut stdout, b"after-expiry\n").await;
    *discovery.records.lock().await = Some(BTreeMap::from([(
        office.record,
        office.publication("Recovered", 3, true, 300),
    )]));
    wait_config(&fixture, |text| text.contains(" attached-recovered\n")).await;
    check_command(&config, "attached-recovered").await;
    round_trip(&mut stdin, &mut stdout, b"recovered\n").await;
    stop(broker, rustix::process::Signal::TERM).await;
    assert_eq!(fs::read(&config).unwrap(), b"");
    timeout(DEADLINE, active.wait()).await.unwrap().unwrap();
    office.stop().await;
    discovery.stop().await;
}

#[tokio::test]
async fn exporter_rebuilds_transport_after_suspension_without_unlocking_again() {
    let fixture = CliFixture::new();
    let discovery = Discovery::new().await;
    let consumer = iroh::SecretKey::generate().to_bytes();
    import_with_identity(&fixture, &discovery.origin, consumer).await;
    let office = Publisher::new(consumer, 66).await;
    office.advertise(&discovery, "Office", 1, true, 300).await;
    let broker = start(&fixture);
    let configured = wait_config(&fixture, |text| text.contains(" attached-office\n")).await;
    let old_keys = runtime_files(&configured);
    let config = fixture.path("home/.ssh/config");
    check_command(&config, "attached-office").await;
    let mut active = ssh(&config, "attached-office", "cat")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = active.stdin.take().unwrap();
    let mut stdout = active.stdout.take().unwrap();
    round_trip(&mut stdin, &mut stdout, b"before-suspend\n").await;
    fs::remove_file(fixture.path("home/.config/attached/sync-account.bundle")).unwrap();
    fs::remove_file(fixture.path("bin/op")).unwrap();

    // Suspend only the exporter, not the fixture/runtime. This deterministically
    // exercises a missed heartbeat without suspending the CI machine or relying
    // on a public relay. Unit tests separately cover clocks that pause in sleep.
    let pid = rustix::process::Pid::from_raw(broker.id().unwrap() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
    tokio::time::sleep(Duration::from_secs(32)).await;
    rustix::process::kill_process(pid, rustix::process::Signal::CONT).unwrap();
    let recovered = wait_config(&fixture, |text| {
        text.contains(" attached-office\n") && text != configured
    })
    .await;
    for key in old_keys {
        assert!(!key.exists(), "old transport retained a temporary key");
    }
    let ended = timeout(DEADLINE, active.wait()).await.unwrap().unwrap();
    assert!(!ended.success());
    check_command(&config, "attached-office").await;
    // Recovery must never replay the cat or any other previous SSH command.
    assert_eq!(office.commands.load(Ordering::SeqCst), 3);
    stop(broker, rustix::process::Signal::TERM).await;
    for key in runtime_files(&recovered) {
        assert!(!key.exists());
    }
    office.stop().await;
    discovery.stop().await;
}

#[tokio::test]
async fn exporter_cleans_up_on_hangup_and_restarts_without_manual_configuration() {
    let fixture = CliFixture::new();
    let discovery = Discovery::new().await;
    import_with_identity(
        &fixture,
        &discovery.origin,
        iroh::SecretKey::generate().to_bytes(),
    )
    .await;
    let broker = start(&fixture);
    wait_config(&fixture, |text| text.contains("Host attached-*\n")).await;
    stop(broker, rustix::process::Signal::HUP).await;
    assert_eq!(fs::read(fixture.path("home/.ssh/config")).unwrap(), b"");
    let mut broker = start(&fixture);
    wait_started(&fixture).await;
    broker.start_kill().unwrap();
    timeout(DEADLINE, broker.wait()).await.unwrap().unwrap();
    let crashed = fs::read(fixture.path("home/.ssh/config")).unwrap();
    assert!(crashed.starts_with(b"# BEGIN Attached"));
    let broker = start(&fixture);
    wait_started(&fixture).await;
    assert_eq!(fs::read(fixture.path("home/.ssh/config")).unwrap(), crashed);
    stop(broker, rustix::process::Signal::TERM).await;
    assert_eq!(fs::read(fixture.path("home/.ssh/config")).unwrap(), b"");
    discovery.stop().await;
}

async fn wait_started(fixture: &CliFixture) {
    timeout(DEADLINE, async {
        while !fs::read_to_string(fixture.path("export.stderr"))
            .unwrap_or_default()
            .contains("SSH forwarding enabled")
        {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unavailable_hosts_do_not_block_healthy_hosts_or_shutdown() {
    let fixture = CliFixture::new();
    let discovery = Discovery::new().await;
    let consumer = iroh::SecretKey::generate().to_bytes();
    import_with_identity(&fixture, &discovery.origin, consumer).await;
    let unavailable = Publisher::new(consumer, 64).await;
    unavailable.cancel.cancel(); // Still advertises an address, but never handles SSH setup.
    let office = Publisher::new(consumer, 65).await;
    unavailable
        .advertise(&discovery, "Unavailable", 1, true, 300)
        .await;
    office.advertise(&discovery, "Office", 1, true, 300).await;
    let broker = start(&fixture);
    let configured = wait_config(&fixture, |text| text.contains(" attached-office\n")).await;
    assert!(!configured.contains(" attached-unavailable\n"));
    check_command(&fixture.path("home/.ssh/config"), "attached-office").await;
    // Cancellation interrupts the unresponsive host's setup rather than waiting
    // for its 20-second deadline. Do not shrink the normal CI readiness budget.
    timeout(
        Duration::from_secs(5),
        stop(broker, rustix::process::Signal::INT),
    )
    .await
    .unwrap();
    for file in runtime_files(&configured) {
        assert!(!file.exists());
    }
    unavailable.stop().await;
    office.stop().await;
    discovery.stop().await;
}
