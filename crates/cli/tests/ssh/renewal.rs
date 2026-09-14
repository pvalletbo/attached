//! Real foreground broker + OpenSSH across lease renewal, without editing ~/.ssh.
use super::*;
use std::{
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    sync::Mutex,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

struct Snapshot {
    index: Vec<u8>,
    record: Vec<u8>,
    revision: u64,
}

fn snapshot(
    ticket: &str,
    revision: u64,
    capability: u8,
    expires: chrono::DateTime<chrono::Utc>,
) -> Snapshot {
    let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let descriptor = SessionAccessDescriptor::new(
        if revision == 1 {
            "remote"
        } else {
            "renamed-publisher"
        }
        .into(),
        now - Duration::from_secs(1),
        expires,
        ticket.into(),
        CapabilitySecret::from_bytes([capability; 32]),
        AttachedVersion::new(0, 2, 12),
        HerdrVersion::new(99, 0, 0),
        Vec::new(),
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
    Snapshot {
        index: serde_json::to_vec(
            &LiveRecordIndex::new(vec![LiveRecordIndexEntry {
                record_id: RECORD,
                revision,
            }])
            .unwrap(),
        )
        .unwrap(),
        record: serde_json::to_vec(&Envelope::new(nonce, ciphertext).unwrap()).unwrap(),
        revision,
    }
}

struct StreamSsh {
    key: russh::keys::PublicKey,
    commands: Arc<AtomicUsize>,
    streams: std::collections::HashSet<russh::ChannelId>,
}
impl russh::server::Handler for StreamSsh {
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
        self.commands.fetch_add(1, Ordering::SeqCst);
        session.channel_success(channel)?;
        match command {
            b"cat" => {
                self.streams.insert(channel);
            }
            b"printf expected" => {
                session.data(channel, b"expected".to_vec())?;
                session.extended_data(channel, 1, b"expected-error".to_vec())?;
                session.exit_status_request(channel, 7)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            _ => panic!("unexpected fixture command"),
        }
        Ok(())
    }
    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> anyhow::Result<()> {
        if self.streams.contains(&channel) {
            session.data(channel, data.to_vec())?;
        }
        Ok(())
    }
    async fn channel_eof(
        &mut self,
        channel: russh::ChannelId,
        session: &mut russh::server::Session,
    ) -> anyhow::Result<()> {
        if self.streams.remove(&channel) {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

fn ssh(config: &Path, alias: &str, command: &str) -> tokio::process::Command {
    let mut process = tokio::process::Command::new("ssh");
    process
        .arg("-F")
        .arg(config)
        .arg(alias)
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    process
}

async fn round_trip(
    stdin: &mut tokio::process::ChildStdin,
    stdout: &mut tokio::process::ChildStdout,
    bytes: &[u8],
) {
    timeout(DEADLINE, async {
        stdin.write_all(bytes).await.unwrap();
        let mut received = vec![0; bytes.len()];
        stdout.read_exact(&mut received).await.unwrap();
        assert_eq!(received, bytes);
    })
    .await
    .expect("existing SSH stream stopped working");
}

async fn broker_case(expire: bool) {
    let fixture = CliFixture::new();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", http.local_addr().unwrap());
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
    let ticket = EndpointTicket::new(publisher.addr()).to_string();
    let expires = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap()
        + Duration::from_secs(if expire { 15 } else { 300 });
    let publication = Arc::new(Mutex::new(Some(snapshot(&ticket, 1, 46, expires))));
    let requests = Arc::new(AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let http_task = {
        let publication = publication.clone();
        let requests = requests.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = tokio::select! { accepted = http.accept() => accepted.unwrap(), _ = cancel.cancelled() => break };
                let headers = request(&mut stream).await;
                let path = headers.split_whitespace().nth(1).unwrap();
                requests.fetch_add(1, Ordering::SeqCst);
                let publication = publication.lock().await;
                if let Some(snapshot) = publication.as_ref() {
                    let index_path = format!("/v1/accounts/{ACCOUNT}/records");
                    if path == index_path {
                        respond(&mut stream, &snapshot.index, "").await;
                    } else {
                        assert_eq!(path, format!("{index_path}/{RECORD}"));
                        respond(
                            &mut stream,
                            &snapshot.record,
                            &format!("ETag: \"{}\"\r\n", snapshot.revision),
                        )
                        .await;
                    }
                } else {
                    stream.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            }
        })
    };
    let capability = Arc::new(AtomicU8::new(46));
    let connections = Arc::new(AtomicUsize::new(0));
    let commands = Arc::new(AtomicUsize::new(0));
    let ssh_task = {
        let endpoint = publisher.clone();
        let cancel = cancel.clone();
        let capability = capability.clone();
        let connections = connections.clone();
        let commands = commands.clone();
        tokio::spawn(async move {
            let key = russh::keys::PrivateKey::new(
                russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[77; 32]).into(),
                "test",
            )
            .unwrap();
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    incoming = endpoint.accept() => {
                        let incoming = incoming.unwrap(); let key = key.clone(); let capability = capability.clone();
                        let connections = connections.clone(); let commands = commands.clone();
                        tasks.spawn(async move {
                            let connection = incoming.await.unwrap();
                            connections.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(connection.remote_id(), iroh::SecretKey::from_bytes(&consumer_identity).public());
                            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                            let length = receive.read_u32().await.unwrap() as usize;
                            assert!(length <= 8192);
                            let mut bytes = vec![0; length]; receive.read_exact(&mut bytes).await.unwrap();
                            let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                            if request["capability"] != serde_json::json!([capability.load(Ordering::SeqCst); 32].to_vec()) {
                                connection.close(403u32.into(), b"stale capability"); return;
                            }
                            let client_key = russh::keys::PublicKey::from_openssh(request["public_key"].as_str().unwrap()).unwrap();
                            let response = serde_json::to_vec(&serde_json::json!({"username": "ssh-test", "host_key": key.public_key().to_openssh().unwrap()})).unwrap();
                            send.write_u32(response.len() as u32).await.unwrap(); send.write_all(&response).await.unwrap();
                            let config = russh::server::Config { keys: vec![key], ..Default::default() };
                            if let Ok(session) = russh::server::run_stream(Arc::new(config), tokio::io::join(receive, send), StreamSsh { key: client_key, commands, streams: Default::default() }).await { let _ = session.await; }
                            connection.close(0u32.into(), b"test completed");
                        });
                    }
                    task = tasks.join_next(), if !tasks.is_empty() => { task.unwrap().unwrap(); }
                }
            }
            tasks.abort_all();
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    assert!(error.is_cancelled(), "publisher fixture panicked: {error}");
                }
            }
        })
    };
    let mut broker = fixture
        .command(&[
            "--use-1password",
            "ssh",
            "--no-cache",
            "--expose-config",
            "remote",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut broker_output = BufReader::new(broker.stdout.take().unwrap());
    let mut config_line = String::new();
    timeout(DEADLINE, broker_output.read_line(&mut config_line))
        .await
        .unwrap()
        .unwrap();
    assert!(
        !config_line.is_empty(),
        "broker exited before exposing its SSH configuration"
    );
    let config = std::path::PathBuf::from(config_line.trim());
    let alias = format!("attached-{}", publisher.id());
    let config_before = fs::read(&config).unwrap();
    let identity_path = config.parent().unwrap().join("identity");
    let identity_before = fs::read(&identity_path).unwrap();
    let catalog_before = fs::read(fixture.path("home/.config/attached/sync-catalog.json")).unwrap();
    // The running broker must not consult newly locked/removed account state.
    fs::remove_file(fixture.path("home/.config/attached/sync-account.bundle")).unwrap();
    fs::remove_file(fixture.path("bin/op")).unwrap();
    let mut active = ssh(&config, &alias, "cat")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut active_stdin = active.stdin.take().unwrap();
    let mut active_stdout = active.stdout.take().unwrap();
    round_trip(
        &mut active_stdin,
        &mut active_stdout,
        b"before-renewal\0\xff\n",
    )
    .await;
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    if expire {
        let until_expiry = (expires - chrono::Utc::now()).to_std().unwrap_or_default();
        tokio::time::sleep(until_expiry + Duration::from_millis(100)).await;
        *publication.lock().await = None;
        let before = connections.load(Ordering::SeqCst);
        let failed = timeout(DEADLINE, ssh(&config, &alias, "printf expected").output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed.status.code(), Some(255));
        assert_eq!(
            connections.load(Ordering::SeqCst),
            before,
            "expired descriptor was used to dial"
        );
        round_trip(
            &mut active_stdin,
            &mut active_stdout,
            b"during-discovery-outage\n",
        )
        .await;
        tokio::time::sleep(Duration::from_millis(2100)).await;
    }
    capability.store(47, Ordering::SeqCst);
    *publication.lock().await = Some(snapshot(
        &ticket,
        2,
        47,
        chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap()
            + Duration::from_secs(300),
    ));
    let mut clients = JoinSet::new();
    for _ in 0..4 {
        let config = config.clone();
        let alias = alias.clone();
        clients.spawn(async move {
            let output = timeout(DEADLINE, ssh(&config, &alias, "printf expected").output())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(output.status.code(), Some(7), "{:?}", output.stderr);
            assert_eq!(output.stdout, b"expected");
            assert_eq!(output.stderr, b"expected-error");
        });
    }
    while let Some(result) = clients.join_next().await {
        result.unwrap();
    }
    assert_eq!(
        requests.load(Ordering::SeqCst),
        if expire { 5 } else { 4 },
        "concurrent clients duplicated discovery refresh"
    );
    assert_eq!(
        commands.load(Ordering::SeqCst),
        5,
        "a command was replayed or lost"
    );
    round_trip(
        &mut active_stdin,
        &mut active_stdout,
        b"after-renewal\0\xff\n",
    )
    .await;
    assert!(fs::read(&config).unwrap() == config_before);
    assert!(fs::read(&identity_path).unwrap() == identity_before);
    assert!(
        fs::read(fixture.path("home/.config/attached/sync-catalog.json")).unwrap()
            == catalog_before
    );
    drop(active_stdin);
    let output = timeout(DEADLINE, active.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(broker.id().unwrap() as i32).unwrap(),
        rustix::process::Signal::INT,
    )
    .unwrap();
    let output = timeout(DEADLINE, broker.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(!config.exists());
    cancel.cancel();
    timeout(DEADLINE, http_task).await.unwrap().unwrap();
    timeout(DEADLINE, ssh_task).await.unwrap().unwrap();
    publisher.close().await;
}

#[tokio::test]
async fn broker_renews_expired_descriptor_and_survives_discovery_outage_without_dropping_streams() {
    broker_case(true).await;
}

#[tokio::test]
async fn broker_refreshes_changed_capability_before_expiry_without_replaying_commands() {
    broker_case(false).await;
}
