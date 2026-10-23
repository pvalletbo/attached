use super::*;
use attached_session_sync_protocol::account::RecordId;
use iroh::{RelayMode, endpoint::BindOpts};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DEADLINE: Duration = Duration::from_secs(15);

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

struct Harness {
    publisher_state: tempfile::TempDir,
    consumer_state: tempfile::TempDir,
    publisher: Endpoint,
    consumer: Endpoint,
    capability: CapabilitySecret,
    cancel: CancellationToken,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new() -> Self {
        let publisher_state = crate::test_support::canonical_tempdir();
        let consumer_state = crate::test_support::canonical_tempdir();
        sync::state::test_support::create_publisher(publisher_state.path(), "https://sync.example")
            .unwrap();
        sync::state::test_support::create_account(consumer_state.path(), "https://sync.example")
            .unwrap();
        let publisher = endpoint(iroh::SecretKey::generate()).await;
        let consumer = endpoint(iroh::SecretKey::from_bytes(&[0x43; 32])).await;
        let capability = CapabilitySecret::generate();
        let cancel = CancellationToken::new();
        let server = {
            let publisher = publisher.clone();
            let path = publisher_state.path().to_owned();
            let capability = capability.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        incoming = publisher.accept() => {
                            let path = path.clone();
                            let capability = capability.clone();
                            let cancel = cancel.clone();
                            tasks.spawn(async move {
                                if let Ok(connection) = incoming.unwrap().await {
                                    let _ = serve(connection, path, capability, cancel).await;
                                }
                            });
                        }
                        _ = tasks.join_next(), if !tasks.is_empty() => {},
                    }
                }
                while tasks.join_next().await.is_some() {}
            })
        };
        Self {
            publisher_state,
            consumer_state,
            publisher,
            consumer,
            capability,
            cancel,
            server,
        }
    }

    fn client(&self, port: u16) -> Arc<Client> {
        Arc::new(Client {
            endpoint: self.consumer.clone(),
            descriptors: Descriptors::new(sync::state_catalog::HostConnection {
                record_id: RecordId::from_bytes([1; 16]),
                service_revision: 1,
                endpoint_ticket: EndpointTicket::new(self.publisher.addr()).to_string(),
                endpoint_identity: *self.publisher.id().as_bytes(),
                attach_capability: self.capability.to_bytes(),
                attached_version: [0, 3, 7],
                expires_at: sync::utc_now_seconds() + Duration::from_secs(300),
                ssh_enabled: true,
            }),
            account: sync::state::load_account(self.consumer_state.path(), ApiKeyScope::Download)
                .unwrap(),
            port,
            connection: Mutex::new(None),
        })
    }

    async fn close(self) {
        self.cancel.cancel();
        timeout(DEADLINE, self.server).await.unwrap().unwrap();
        self.consumer.close().await;
        self.publisher.close().await;
    }
}

async fn open_stream(client: &Client) -> (iroh::endpoint::SendStream, iroh::endpoint::RecvStream) {
    let connection = client.connection().await.unwrap();
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    write_tcp_forward_open(&mut send).await.unwrap();
    assert_eq!(
        read_tcp_forward_status(&mut receive).await.unwrap(),
        TcpForwardStatus::Ready
    );
    (send, receive)
}

#[tokio::test]
async fn tcp_listener_multiplexes_binary_half_closes_and_server_first_protocols() {
    timeout(DEADLINE, async {
        let harness = Harness::new().await;
        let service = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = service.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            for _ in 0..8 {
                let (mut stream, _) = service.accept().await.unwrap();
                tasks.spawn(async move {
                    stream.write_all(b"server-first\0\xff").await.unwrap();
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).await.unwrap();
                    stream.write_all(&request).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local = listener.local_addr().unwrap();
        assert_eq!(local.ip(), Ipv4Addr::LOCALHOST);
        let client = harness.client(port);
        let forwarding = tokio::spawn(listen(listener, client, "remote"));
        let mut tools = JoinSet::new();
        for id in 0..8 {
            tools.spawn(async move {
                let mut stream = TcpStream::connect(local).await.unwrap();
                let mut banner = [0; 14];
                stream.read_exact(&mut banner).await.unwrap();
                assert_eq!(&banner, b"server-first\0\xff");
                let request: Vec<u8> = (0..262_144).map(|n| (n + id) as u8).collect();
                stream.write_all(&request).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, request);
            });
        }
        while let Some(result) = tools.join_next().await {
            result.unwrap();
        }
        server.await.unwrap();
        forwarding.abort();
        let _ = forwarding.await;
        assert!(TcpStream::connect(local).await.is_err());
        harness.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn refused_destination_does_not_poison_tunnel_and_new_connections_reconnect() {
    timeout(DEADLINE, async {
        let harness = Harness::new().await;
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let client = harness.client(port);
        let connection = client.connection().await.unwrap();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        write_tcp_forward_open(&mut send).await.unwrap();
        assert_eq!(
            read_tcp_forward_status(&mut receive).await.unwrap(),
            TcpForwardStatus::ConnectionFailed
        );
        assert!(connection.close_reason().is_none());
        let service = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        for _ in 0..2 {
            let (send, mut receive) = open_stream(&client).await;
            let (mut remote, _) = service.accept().await.unwrap();
            remote.write_all(b"ready").await.unwrap();
            let mut response = [0; 5];
            receive.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ready");
            drop((send, receive, remote));
            client
                .connection()
                .await
                .unwrap()
                .close(0u32.into(), b"simulate disconnect");
        }
        harness.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_forwarding_rejects_wrong_identity_capability_and_missing_credentials() {
    timeout(DEADLINE, async {
        let harness = Harness::new().await;
        for scenario in 0..4 {
            let peer = endpoint(if scenario == 0 {
                iroh::SecretKey::generate()
            } else {
                iroh::SecretKey::from_bytes(&[0x43; 32])
            })
            .await;
            if scenario == 2 {
                std::fs::write(
                    harness.publisher_state.path().join("sync-account.bundle"),
                    b"corrupt",
                )
                .unwrap();
            } else if scenario == 3 {
                std::fs::remove_file(harness.publisher_state.path().join("sync-account.bundle"))
                    .unwrap();
            }
            let connection = peer.connect(harness.publisher.addr(), ALPN).await.unwrap();
            let result = async {
                let (mut send, mut receive) = connection.open_bi().await?;
                let capability = if scenario == 1 {
                    CapabilitySecret::generate()
                } else {
                    harness.capability.clone()
                };
                write_tcp_forward_request(&mut send, &capability, 4096).await?;
                read_tcp_forward_status(&mut receive).await
            }
            .await;
            assert!(result.is_err(), "accepted unauthorized scenario {scenario}");
            peer.close().await;
        }
        harness.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn revocation_and_cancellation_terminate_idle_application_streams() {
    for revoke in [false, true] {
        timeout(DEADLINE, async {
            let harness = Harness::new().await;
            let service = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let client = harness.client(service.local_addr().unwrap().port());
            let (_send, mut receive) = open_stream(&client).await;
            let (_remote, _) = service.accept().await.unwrap();
            if revoke {
                std::fs::remove_file(harness.publisher_state.path().join("sync-account.bundle"))
                    .unwrap();
            } else {
                harness.cancel.cancel();
            }
            let mut byte = [0; 1];
            let result = timeout(Duration::from_secs(4), receive.read(&mut byte))
                .await
                .unwrap();
            assert!(!matches!(result, Ok(Some(n)) if n != 0));
            harness.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn publisher_stream_limit_rejects_excess_without_connecting_other_destinations() {
    timeout(DEADLINE, async {
        let harness = Harness::new().await;
        let service = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client = harness.client(service.local_addr().unwrap().port());
        let mut streams = Vec::new();
        let mut sockets = Vec::new();
        for _ in 0..MAX_STREAMS {
            streams.push(open_stream(&client).await);
            sockets.push(service.accept().await.unwrap().0);
        }
        let connection = client.connection().await.unwrap();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        let excess = async {
            write_tcp_forward_open(&mut send).await?;
            read_tcp_forward_status(&mut receive).await
        }
        .await;
        assert!(
            excess.is_err(),
            "accepted a stream beyond the publisher limit"
        );
        assert!(
            connection.close_reason().is_none(),
            "excess stream killed the entire tunnel"
        );
        assert!(
            timeout(Duration::from_millis(50), service.accept())
                .await
                .is_err()
        );
        harness.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_client_setup_closes_the_pending_quic_connection() {
    timeout(DEADLINE, async {
        let harness = Harness::new().await;
        // Stop the normal accept loop, but leave the endpoint alive for a silent peer.
        harness.cancel.cancel();
        while !harness.server.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut client = harness.client(4096);
        let client = Arc::get_mut(&mut client).unwrap();
        let host = client.descriptors.get(&client.account, None).await.unwrap();
        let server = async {
            let connection = harness.publisher.accept().await.unwrap().await.unwrap();
            let (_send, _receive) = connection.accept_bi().await.unwrap();
            // Accept setup bytes but deliberately never acknowledge authentication.
            connection.closed().await;
        };
        let caller = async {
            assert!(
                timeout(Duration::from_millis(200), client.open(&host))
                    .await
                    .is_err()
            );
        };
        tokio::join!(server, caller);
        harness.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn destination_supports_ipv6_loopback_without_dns() {
    timeout(DEADLINE, async {
        let service = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let stream = connect_loopback(service.local_addr().unwrap().port())
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap().ip(), Ipv6Addr::LOCALHOST);
    })
    .await
    .unwrap();
}
