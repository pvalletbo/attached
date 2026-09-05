use super::*;
use std::{io, net::Ipv4Addr, time::Duration};

use attached_tunnel_protocol::{
    AttachedUpdateRequest, UpgradeResponse, read_attached_update_request, read_upgrade_request,
    write_attached_update_response, write_upgrade_response,
};
use iroh::{RelayMode, endpoint::BindOpts};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(60);
const LARGE_PAYLOAD_SIZE: usize = 256 * 1024;
const MAX_CONNECTIONS: usize = 16;
const MAX_PENDING_CONNECTIONS: usize = 16;
const TEST_HERDR_VERSION: HerdrVersion = HerdrVersion::new(0, 7, 5);

async fn serve_fixed_connection(
    connection: Connection,
    connection_id: u64,
    session: Session,
    secret: CapabilitySecret,
    herdr_version: Option<HerdrVersion>,
    cancellation: CancellationToken,
) -> Result<()> {
    let expected_name = session.name().to_owned();
    serve_connection(
        connection,
        connection_id,
        &secret,
        herdr_version.unwrap_or(TEST_HERDR_VERSION),
        cancellation,
        move |name| async move {
            anyhow::ensure!(name == expected_name, "unexpected session");
            Ok(session)
        },
        || Ok(()),
    )
    .await
}

async fn serve_endpoint<F>(
    endpoint: &Endpoint,
    session: Session,
    capability: CapabilitySecret,
    herdr_version: Option<HerdrVersion>,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let cancellation = CancellationToken::new();
    let pending_limit = Arc::new(Semaphore::new(MAX_PENDING_CONNECTIONS));
    let authenticated_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    let result = loop {
        tokio::select! {
            shutdown_result = &mut shutdown => break shutdown_result,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break Err(anyhow!("Iroh endpoint stopped accepting connections"));
                };
                let pending_permit = match pending_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        drop(incoming);
                        continue;
                    }
                };
                let connection_id = next_connection_id();
                let session = session.clone();
                let secret = capability.clone();
                let authenticated_limit = authenticated_limit.clone();
                let child_cancellation = cancellation.child_token();
                connections.spawn(async move {
                    let result = async {
                        let connection = timeout(AUTHENTICATION_TIMEOUT, incoming)
                            .await
                            .context("Iroh connection handshake timed out")?
                            .context("Iroh connection failed")?;
                        let expected_name = session.name().to_owned();
                        serve_connection(
                            connection,
                            connection_id,
                            &secret,
                            herdr_version.unwrap_or(TEST_HERDR_VERSION),
                            child_cancellation,
                            move |name| async move {
                                anyhow::ensure!(name == expected_name, "unexpected session");
                                Ok(session)
                            },
                            move || {
                                drop(pending_permit);
                                authenticated_limit
                                    .try_acquire_owned()
                                    .context("authenticated connection limit reached")
                            },
                        )
                        .await
                    }
                    .await;
                    if let Err(error) = result {
                        warn!(connection_id, category = "iroh_connection", error = %error, "Iroh client connection closed");
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    error!(category = "task", error = %error, "Iroh connection task failed");
                }
            }
        }
    };

    cancellation.cancel();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}

async fn authenticate_client(
    connection: &Connection,
    session: &str,
    capability: &CapabilitySecret,
    herdr_version: Option<HerdrVersion>,
) -> Result<()> {
    super::authenticate_client(
        connection,
        session,
        capability,
        herdr_version.unwrap_or(TEST_HERDR_VERSION),
    )
    .await
}

struct Harness {
    _root: tempfile::TempDir,
    tui: UnixListener,
    server_endpoint: Endpoint,
    client_endpoint: Endpoint,
    connection: Connection,
    server_connection: Connection,
    server: JoinHandle<Result<()>>,
}

impl Harness {
    async fn authenticated() -> Self {
        let root = tempfile::tempdir().unwrap();
        let tui_path = root.path().join("tui.sock");
        let tui = UnixListener::bind(&tui_path).unwrap();
        let session = Session::new("test".to_owned(), tui_path);
        let secret = CapabilitySecret::generate();
        let (server_endpoint, client_endpoint, connection, server_connection) =
            connected_endpoints().await;
        let server = tokio::spawn(serve_fixed_connection(
            server_connection.clone(),
            1,
            session,
            secret.clone(),
            None,
            CancellationToken::new(),
        ));
        within(authenticate_client(&connection, "test", &secret, None))
            .await
            .unwrap();
        Self {
            _root: root,
            tui,
            server_endpoint,
            client_endpoint,
            connection,
            server_connection,
            server,
        }
    }

    async fn open(&self) -> (SendStream, RecvStream) {
        open_tui(&self.connection).await
    }

    async fn close(self) {
        self.connection.close(0_u32.into(), b"test complete");
        let _ = within(self.server).await;
        self.client_endpoint.close().await;
        self.server_endpoint.close().await;
    }
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

async fn attached_update_endpoint(
    identity: iroh::SecretKey,
    bind_addr: Option<std::net::SocketAddr>,
) -> Endpoint {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let result = Endpoint::builder(presets::N0)
            .secret_key(identity.clone())
            .clear_ip_transports()
            .bind_addr_with_opts(
                bind_addr.unwrap_or_else(|| (Ipv4Addr::LOCALHOST, 0).into()),
                BindOpts::default().set_prefix_len(8),
            )
            .unwrap()
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .alpns(vec![ATTACHED_UPDATE_ALPN.to_vec()])
            .bind()
            .await;
        match result {
            Ok(endpoint) => return endpoint,
            // Parallel subprocess tests can briefly inherit a CLOEXEC UDP socket
            // between fork and exec. Closing its owning endpoint is not a barrier
            // for those inherited descriptors. Retry only this fixed-port rebind.
            Err(iroh::endpoint::BindError::Sockets { ref source, .. })
                if bind_addr.is_some()
                    && source.kind() == io::ErrorKind::AddrInUse
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("could not bind test update endpoint: {error:#}"),
        }
    }
}

async fn upgrade_endpoint(identity: iroh::SecretKey) -> Endpoint {
    Endpoint::builder(presets::N0)
        .secret_key(identity)
        .clear_ip_transports()
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_prefix_len(8),
        )
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![UPGRADE_ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

async fn connected_endpoints() -> (Endpoint, Endpoint, Connection, Connection) {
    let server = endpoint().await;
    let client = endpoint().await;
    let address = server.addr();
    assert!(address.relay_urls().next().is_none());
    let direct_addresses: Vec<_> = address.ip_addrs().copied().collect();
    assert!(!direct_addresses.is_empty());
    assert!(
        direct_addresses
            .iter()
            .all(|address| address.ip().is_loopback())
    );

    let incoming = within(async {
        server
            .accept()
            .await
            .expect("server endpoint stopped")
            .await
    });
    let outgoing = within(client.connect(address, TUNNEL_ALPN));
    let (server_connection, client_connection) = tokio::join!(incoming, outgoing);
    (
        server,
        client,
        client_connection.unwrap(),
        server_connection.unwrap(),
    )
}

async fn within<F: Future>(future: F) -> F::Output {
    timeout(TEST_TIMEOUT, future)
        .await
        .expect("offline integration operation timed out")
}

async fn accept(listener: &UnixListener) -> UnixStream {
    within(listener.accept()).await.unwrap().0
}

async fn open_tui(connection: &Connection) -> (SendStream, RecvStream) {
    let (mut send, receive) = within(connection.open_bi()).await.unwrap();
    within(write_stream_header(&mut send)).await.unwrap();
    (send, receive)
}

fn unix_pair() -> (UnixStream, UnixStream) {
    let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
    left.set_nonblocking(true).unwrap();
    right.set_nonblocking(true).unwrap();
    (
        UnixStream::from_std(left).unwrap(),
        UnixStream::from_std(right).unwrap(),
    )
}

#[tokio::test]
async fn remote_herdr_upgrade_confirmation_is_entirely_offline() {
    within(async {
        let capability = CapabilitySecret::from_bytes([0x72; 32]);
        let requested = HerdrVersion::new(4, 5, 6);
        let server = upgrade_endpoint(iroh::SecretKey::generate()).await;
        let client = upgrade_endpoint(iroh::SecretKey::generate()).await;
        let server_addr = server.addr();
        assert!(server_addr.relay_urls().next().is_none());
        assert!(
            server_addr
                .ip_addrs()
                .all(|address| address.ip().is_loopback())
        );

        let server_capability = capability.clone();
        let serving = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let request = read_upgrade_request(&mut receive, &server_capability)
                .await
                .unwrap();
            assert_eq!(request.session, "work");
            assert_eq!(request.requested_version, requested);
            write_upgrade_response(&mut send, UpgradeResponse::Updated(requested))
                .await
                .unwrap();
            send.stopped().await.unwrap();
            server.close().await;
        });

        let installed =
            request_upgrade_on_endpoint(&client, server_addr, "work", &capability, requested)
                .await
                .unwrap();
        assert_eq!(installed, requested);
        client.close().await;
        serving.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn attached_update_client_reconnects_to_replacement_endpoint_entirely_offline() {
    within(async {
        let server_identity = iroh::SecretKey::generate();
        let client_identity = iroh::SecretKey::generate();
        let capability = CapabilitySecret::from_bytes([0x73; 32]);
        let operation_id = UpdateOperationId::from_bytes([0x29; 16]);
        let candidate_version = AttachedVersion::new(0, 4, 0);
        let old = attached_update_endpoint(server_identity.clone(), None).await;
        let old_addr = old.addr();
        assert!(old_addr.relay_urls().next().is_none());
        let bind_addr = old.bound_sockets()[0];
        assert!(bind_addr.ip().is_loopback());
        let (old_closed_tx, old_closed_rx) = tokio::sync::oneshot::channel();

        let old_capability = capability.clone();
        let old_server = tokio::spawn(async move {
            let connection = old.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            assert_eq!(
                read_attached_update_request(&mut receive, &old_capability)
                    .await
                    .unwrap(),
                AttachedUpdateRequest::Start {
                    session: "work".to_owned()
                }
            );
            write_attached_update_response(
                &mut send,
                AttachedUpdateResponse::Restarting {
                    operation_id,
                    version: candidate_version,
                    reconnect_timeout_secs: 5,
                },
            )
            .await
            .unwrap();
            send.stopped().await.unwrap();
            drop((send, receive, connection));
            old.close().await;
            drop(old);
            old_closed_tx.send(()).unwrap();
        });

        let candidate_capability = capability.clone();
        let candidate_server = tokio::spawn(async move {
            old_closed_rx.await.unwrap();
            let candidate = attached_update_endpoint(server_identity, Some(bind_addr)).await;
            assert_eq!(candidate.bound_sockets(), [bind_addr]);
            let connection = candidate.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            assert_eq!(
                read_attached_update_request(&mut receive, &candidate_capability)
                    .await
                    .unwrap(),
                AttachedUpdateRequest::Confirm {
                    session: "work".to_owned(),
                    operation_id,
                    observed_version: candidate_version,
                }
            );
            write_attached_update_response(
                &mut send,
                AttachedUpdateResponse::Committed(candidate_version),
            )
            .await
            .unwrap();
            send.stopped().await.unwrap();
            drop((send, receive, connection));
            candidate.close().await;
        });

        let client = attached_update_endpoint(client_identity, None).await;
        let installed = request_attached_update_on_endpoint(&client, old_addr, "work", &capability)
            .await
            .unwrap();
        assert_eq!(installed, candidate_version);
        client.close().await;
        old_server.await.unwrap();
        candidate_server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn synchronized_connection_resolves_the_selected_session_after_authentication() {
    within(async {
        let root = tempfile::tempdir().unwrap();
        let tui_path = root.path().join("tui.sock");
        let tui = UnixListener::bind(&tui_path).unwrap();
        let session = Session::new("work".to_owned(), tui_path);
        let capability = CapabilitySecret::generate();
        let (server_endpoint, client_endpoint, connection, server_connection) =
            connected_endpoints().await;
        let server_capability = capability.clone();
        let server = tokio::spawn(async move {
            serve_connection(
                server_connection,
                1,
                &server_capability,
                TEST_HERDR_VERSION,
                CancellationToken::new(),
                move |name| async move {
                    anyhow::ensure!(name == "work", "unexpected session");
                    Ok(session)
                },
                || Ok(()),
            )
            .await
        });

        authenticate_client(
            &connection,
            "work",
            &capability,
            Some(HerdrVersion::new(0, 7, 5)),
        )
        .await
        .unwrap();
        let (mut send, _receive) = open_tui(&connection).await;
        let mut upstream = accept(&tui).await;
        send.write_all(b"synchronized").await.unwrap();
        send.finish().unwrap();
        let mut payload = Vec::new();
        upstream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"synchronized");

        connection.close(0_u32.into(), b"done");
        let _ = server.await;
        client_endpoint.close().await;
        server_endpoint.close().await;
    })
    .await;
}

#[tokio::test]
async fn authenticated_tui_streams_are_full_duplex_and_long_lived() {
    within(async {
        let harness = Harness::authenticated().await;
        let (mut first_send, mut first_receive) = harness.open().await;
        let (mut second_send, mut second_receive) = harness.open().await;
        let mut first_upstream = accept(&harness.tui).await;
        let mut second_upstream = accept(&harness.tui).await;

        first_send.write_all(b"sub").await.unwrap();
        let mut request = [0; 3];
        first_upstream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"sub");
        first_upstream.write_all(b"event-1").await.unwrap();
        let mut first = [0; 7];
        first_receive.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"event-1");
        first_upstream.write_all(b"event-2").await.unwrap();
        let mut second = [0; 7];
        first_receive.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"event-2");

        let client = async {
            second_send.write_all(b"input-1").await.unwrap();
            let mut output = [0; 8];
            second_receive.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"output-1");
            second_send.write_all(b"input-2").await.unwrap();
        };
        let server = async {
            let mut input = [0; 7];
            second_upstream.read_exact(&mut input).await?;
            assert_eq!(&input, b"input-1");
            second_upstream.write_all(b"output-1").await?;
            second_upstream.read_exact(&mut input).await?;
            assert_eq!(&input, b"input-2");
            io::Result::Ok(())
        };
        let ((), server_result) = tokio::join!(client, server);
        server_result.unwrap();

        harness.close().await;
    })
    .await;
}

#[tokio::test]
async fn authenticated_local_forwarder_routes_tui_end_to_end() {
    within(async {
        let harness = Harness::authenticated().await;
        let (mut local_client, local_proxy) = unix_pair();
        let forwarder = tokio::spawn(forward_one_local(
            local_proxy,
            harness.connection.clone(),
            1,
            1,
            CancellationToken::new(),
        ));
        let mut upstream = accept(&harness.tui).await;

        local_client.write_all(b"input").await.unwrap();
        let mut input = [0; 5];
        upstream.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"input");
        upstream.write_all(b"screen").await.unwrap();
        let mut screen = [0; 6];
        local_client.read_exact(&mut screen).await.unwrap();
        assert_eq!(&screen, b"screen");
        local_client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();

        within(forwarder).await.unwrap().unwrap();
        harness.close().await;
    })
    .await;
}

#[tokio::test]
async fn empty_fragmented_large_and_slow_reader_payloads_are_preserved() {
    within(async {
        let harness = Harness::authenticated().await;

        let (mut empty_send, mut empty_receive) = harness.open().await;
        let mut empty_upstream = accept(&harness.tui).await;
        empty_send.finish().unwrap();
        let mut empty = Vec::new();
        empty_upstream.read_to_end(&mut empty).await.unwrap();
        assert!(empty.is_empty());
        empty_upstream.shutdown().await.unwrap();
        assert_eq!(
            empty_receive.read_to_end(1).await.unwrap(),
            Vec::<u8>::new()
        );

        let (mut fragmented_send, _fragmented_receive) = harness.open().await;
        let mut fragmented_upstream = accept(&harness.tui).await;
        for fragment in [b"frag".as_slice(), b"ment".as_slice(), b"ed".as_slice()] {
            fragmented_send.write_all(fragment).await.unwrap();
            tokio::task::yield_now().await;
        }
        fragmented_send.finish().unwrap();
        let mut fragmented = Vec::new();
        fragmented_upstream
            .read_to_end(&mut fragmented)
            .await
            .unwrap();
        assert_eq!(fragmented, b"fragmented");

        let (mut large_send, _large_receive) = harness.open().await;
        let mut large_upstream = accept(&harness.tui).await;
        let payload: Vec<u8> = (0..LARGE_PAYLOAD_SIZE).map(|index| index as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            large_send.write_all(&payload).await.unwrap();
            large_send.finish().unwrap();
        });
        let slow_reader = tokio::spawn(async move {
            let mut received = Vec::with_capacity(LARGE_PAYLOAD_SIZE);
            let mut chunk = [0; 257];
            loop {
                let count = large_upstream.read(&mut chunk).await.unwrap();
                if count == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..count]);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            received
        });
        writer.await.unwrap();
        assert_eq!(slow_reader.await.unwrap(), expected);

        harness.close().await;
    })
    .await;
}

#[tokio::test]
async fn simultaneous_streams_half_close_and_restore_capacity() {
    within(async {
        let harness = Harness::authenticated().await;
        let mut clients = Vec::new();
        for index in 0..8_u8 {
            let (mut send, mut receive) = harness.open().await;
            let mut upstream = accept(&harness.tui).await;
            clients.push(tokio::spawn(async move {
                send.write_all(&[index]).await.unwrap();
                send.finish().unwrap();
                let mut request = [0];
                upstream.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [index]);
                assert_eq!(upstream.read(&mut request).await.unwrap(), 0);
                upstream.write_all(&[index.wrapping_add(1)]).await.unwrap();
                upstream.shutdown().await.unwrap();
                let response = receive.read_to_end(2).await.unwrap();
                assert_eq!(response, [index.wrapping_add(1)]);
            }));
        }
        for client in clients {
            client.await.unwrap();
        }

        let (mut send, _receive) = harness.open().await;
        let mut upstream = accept(&harness.tui).await;
        send.write_all(b"reused").await.unwrap();
        send.finish().unwrap();
        let mut reused = Vec::new();
        upstream.read_to_end(&mut reused).await.unwrap();
        assert_eq!(reused, b"reused");
        harness.close().await;
    })
    .await;
}

#[tokio::test]
async fn abrupt_local_and_iroh_closures_do_not_poison_later_streams() {
    within(async {
        let harness = Harness::authenticated().await;

        let (mut first_send, first_receive) = harness.open().await;
        let first_upstream = accept(&harness.tui).await;
        first_send.write_all(b"before-local-close").await.unwrap();
        drop(first_upstream);
        drop(first_send);
        drop(first_receive);

        let (second_send, second_receive) = harness.open().await;
        let mut second_upstream = accept(&harness.tui).await;
        drop(second_send);
        drop(second_receive);
        let mut eof = [0];
        assert_eq!(second_upstream.read(&mut eof).await.unwrap(), 0);

        let (mut third_send, _third_receive) = harness.open().await;
        let mut third_upstream = accept(&harness.tui).await;
        third_send.write_all(b"still-alive").await.unwrap();
        third_send.finish().unwrap();
        let mut payload = Vec::new();
        third_upstream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"still-alive");

        harness
            .server_connection
            .close(7_u32.into(), b"abrupt server test close");
        harness.connection.closed().await;
        harness.client_endpoint.close().await;
        harness.server_endpoint.close().await;
    })
    .await;
}

#[derive(Clone, Copy)]
enum AuthAttempt {
    WrongSecret,
    Malformed,
    DataBeforeAuth,
}

#[tokio::test]
async fn unauthorized_and_malformed_clients_never_open_tui_socket() {
    within(async {
        for attempt in [
            AuthAttempt::WrongSecret,
            AuthAttempt::Malformed,
            AuthAttempt::DataBeforeAuth,
        ] {
            let root = tempfile::tempdir().unwrap();
            let tui_path = root.path().join("tui.sock");
            let tui = UnixListener::bind(&tui_path).unwrap();
            let session = Session::new("test".to_owned(), tui_path);
            let expected = CapabilitySecret::generate();
            let (server_endpoint, client_endpoint, connection, server_connection) =
                connected_endpoints().await;
            let server = tokio::spawn(serve_fixed_connection(
                server_connection,
                1,
                session,
                expected.clone(),
                None,
                CancellationToken::new(),
            ));

            let (mut send, mut receive) = connection.open_bi().await.unwrap();
            match attempt {
                AuthAttempt::WrongSecret => {
                    write_auth_request(&mut send, "test", &CapabilitySecret::generate(), None)
                        .await
                        .unwrap();
                    assert!(read_auth_response(&mut receive, None).await.is_err());
                }
                AuthAttempt::Malformed => {
                    send.write_all(b"bad").await.unwrap();
                    send.finish().unwrap();
                }
                AuthAttempt::DataBeforeAuth => {
                    send.write_all(b"terminal-data-before-auth").await.unwrap();
                    send.finish().unwrap();
                }
            }
            assert!(server.await.unwrap().is_err());
            assert!(
                timeout(Duration::from_millis(100), tui.accept())
                    .await
                    .is_err()
            );
            connection.close(0_u32.into(), b"done");
            client_endpoint.close().await;
            server_endpoint.close().await;
        }
    })
    .await;
}

#[tokio::test]
async fn partial_authentication_times_out_without_opening_tui_socket() {
    within(async {
        let root = tempfile::tempdir().unwrap();
        let tui_path = root.path().join("tui.sock");
        let tui = UnixListener::bind(&tui_path).unwrap();
        let session = Session::new("test".to_owned(), tui_path);
        let (server_endpoint, client_endpoint, connection, server_connection) =
            connected_endpoints().await;
        let server = tokio::spawn(serve_fixed_connection(
            server_connection,
            1,
            session,
            CapabilitySecret::generate(),
            None,
            CancellationToken::new(),
        ));
        let (mut send, _receive) = connection.open_bi().await.unwrap();
        send.write_all(b"HD").await.unwrap();

        let result = timeout(AUTHENTICATION_TIMEOUT + Duration::from_secs(2), server)
            .await
            .expect("partial authentication was not timed out")
            .unwrap();
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(
            timeout(Duration::from_millis(100), tui.accept())
                .await
                .is_err()
        );
        client_endpoint.close().await;
        server_endpoint.close().await;
    })
    .await;
}

#[tokio::test]
async fn missing_tui_socket_rejects_one_stream_and_later_recovers() {
    within(async {
        let root = tempfile::tempdir().unwrap();
        let tui_path = root.path().join("tui.sock");
        let session = Session::new("test".to_owned(), tui_path.clone());
        let secret = CapabilitySecret::generate();
        let (server_endpoint, client_endpoint, connection, server_connection) =
            connected_endpoints().await;
        let server = tokio::spawn(serve_fixed_connection(
            server_connection,
            1,
            session,
            secret.clone(),
            None,
            CancellationToken::new(),
        ));
        authenticate_client(&connection, "test", &secret, None)
            .await
            .unwrap();

        let (mut missing_send, mut missing_receive) = open_tui(&connection).await;
        missing_send.write_all(b"unreachable").await.unwrap();
        missing_send.finish().unwrap();
        let missing_result = missing_receive.read_to_end(1).await;
        assert!(missing_result.is_err() || missing_result.unwrap().is_empty());

        let tui = UnixListener::bind(&tui_path).unwrap();
        let (mut recovered_send, _recovered_receive) = open_tui(&connection).await;
        let mut upstream = accept(&tui).await;
        recovered_send.write_all(b"reachable").await.unwrap();
        recovered_send.finish().unwrap();
        let mut payload = Vec::new();
        upstream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"reachable");

        connection.close(0_u32.into(), b"done");
        let _ = server.await;
        client_endpoint.close().await;
        server_endpoint.close().await;
    })
    .await;
}

#[tokio::test]
async fn socket_recreation_routes_only_new_streams_to_the_replacement() {
    within(async {
        let harness = Harness::authenticated().await;
        let tui_path = harness
            .tui
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .to_owned();

        let (mut old_send, mut old_receive) = harness.open().await;
        let mut old_upstream = accept(&harness.tui).await;
        old_send.write_all(b"old-before").await.unwrap();
        let mut old_before = [0; 10];
        old_upstream.read_exact(&mut old_before).await.unwrap();
        assert_eq!(&old_before, b"old-before");

        drop(old_upstream);
        let old_output = old_receive.read_to_end(16).await.unwrap();
        assert!(old_output.is_empty());
        drop(old_send);

        std::fs::remove_file(&tui_path).unwrap();
        let replacement = UnixListener::bind(&tui_path).unwrap();
        let (mut new_send, _new_receive) = harness.open().await;
        let mut new_upstream = accept(&replacement).await;
        new_send.write_all(b"new-stream").await.unwrap();
        new_send.finish().unwrap();
        let mut new_payload = Vec::new();
        new_upstream.read_to_end(&mut new_payload).await.unwrap();
        assert_eq!(new_payload, b"new-stream");

        harness.close().await;
    })
    .await;
}

#[tokio::test]
async fn parent_connection_loss_cancels_several_active_tui_streams() {
    within(async {
        let harness = Harness::authenticated().await;
        let (mut first_send, _first_receive) = harness.open().await;
        let (mut second_send, _second_receive) = harness.open().await;
        let mut first_upstream = accept(&harness.tui).await;
        let mut second_upstream = accept(&harness.tui).await;

        first_send.write_all(b"one-live").await.unwrap();
        second_send.write_all(b"two-live").await.unwrap();
        let mut first = [0; 8];
        let mut second = [0; 8];
        first_upstream.read_exact(&mut first).await.unwrap();
        second_upstream.read_exact(&mut second).await.unwrap();

        harness
            .server_connection
            .close(9_u32.into(), b"parent lost");
        harness.connection.closed().await;
        assert_eq!(first_upstream.read(&mut first).await.unwrap(), 0);
        assert_eq!(second_upstream.read(&mut second).await.unwrap(), 0);
        harness.close().await;
    })
    .await;
}

#[tokio::test]
async fn server_accepts_a_later_client_after_unauthorized_client() {
    within(async {
        let root = tempfile::tempdir().unwrap();
        let tui_path = root.path().join("tui.sock");
        let tui = UnixListener::bind(&tui_path).unwrap();
        let session = Session::new("test".to_owned(), tui_path);
        let server_endpoint = endpoint().await;
        let server_addr = server_endpoint.addr();
        let closer = server_endpoint.clone();
        let capability = CapabilitySecret::generate();
        let server_secret = capability.clone();
        let server = tokio::spawn(async move {
            serve_endpoint(
                &server_endpoint,
                session,
                server_secret,
                None,
                std::future::pending::<Result<()>>(),
            )
            .await
        });

        let wrong_endpoint = endpoint().await;
        let wrong_connection = wrong_endpoint
            .connect(server_addr.clone(), TUNNEL_ALPN)
            .await
            .unwrap();
        let error = authenticate_client(
            &wrong_connection,
            "test",
            &CapabilitySecret::generate(),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("server rejected tunnel authentication"),
            "{error}"
        );
        wrong_endpoint.close().await;

        let good_endpoint = endpoint().await;
        let good_connection = good_endpoint
            .connect(server_addr.clone(), TUNNEL_ALPN)
            .await
            .unwrap();
        authenticate_client(&good_connection, "test", &capability, None)
            .await
            .unwrap();
        let (mut send, _receive) = open_tui(&good_connection).await;
        send.write_all(b"healthy").await.unwrap();
        send.finish().unwrap();
        let mut upstream = accept(&tui).await;
        let mut payload = Vec::new();
        upstream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"healthy");

        good_endpoint.close().await;
        closer.close().await;
        let error = server.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("stopped accepting"), "{error}");
    })
    .await;
}

#[tokio::test]
async fn authenticated_capacity_rejects_before_success_and_recovers_with_routing() {
    within(async {
        let root = tempfile::tempdir().unwrap();
        let tui_path = root.path().join("tui.sock");
        let tui = UnixListener::bind(&tui_path).unwrap();
        let session = Session::new("test".to_owned(), tui_path);
        let server_endpoint = endpoint().await;
        let server_addr = server_endpoint.addr();
        let closer = server_endpoint.clone();
        let capability = CapabilitySecret::generate();
        let server_secret = capability.clone();
        let server = tokio::spawn(async move {
            serve_endpoint(
                &server_endpoint,
                session,
                server_secret,
                None,
                std::future::pending::<Result<()>>(),
            )
            .await
        });

        let established_endpoint = endpoint().await;
        let established = established_endpoint
            .connect(server_addr.clone(), TUNNEL_ALPN)
            .await
            .unwrap();
        authenticate_client(&established, "test", &capability, None)
            .await
            .unwrap();

        let mut attackers = Vec::new();
        for _ in 0..(MAX_CONNECTIONS - 1) {
            let attacker_endpoint = endpoint().await;
            let connection = attacker_endpoint
                .connect(server_addr.clone(), TUNNEL_ALPN)
                .await
                .unwrap();
            let (mut send, receive) = connection.open_bi().await.unwrap();
            send.write_all(b"HD").await.unwrap();
            attackers.push((attacker_endpoint, connection, send, receive));
        }

        let replacement_endpoint = endpoint().await;
        let replacement = replacement_endpoint
            .connect(server_addr.clone(), TUNNEL_ALPN)
            .await
            .unwrap();
        authenticate_client(&replacement, "test", &capability, None)
            .await
            .expect("pending unauthenticated clients consumed authenticated capacity");

        let (mut send, _receive) = open_tui(&established).await;
        send.write_all(b"established-remains-live").await.unwrap();
        send.finish().unwrap();
        let mut upstream = accept(&tui).await;
        let mut payload = Vec::new();
        upstream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"established-remains-live");

        for (attacker_endpoint, connection, send, mut receive) in attackers {
            drop(send);
            let _ = receive.read_to_end(1).await;
            connection.close(0_u32.into(), b"end unauthorized attempt");
            attacker_endpoint.close().await;
        }
        let mut authenticated = Vec::new();
        for _ in 2..MAX_CONNECTIONS {
            let client_endpoint = endpoint().await;
            let connection = client_endpoint
                .connect(server_addr.clone(), TUNNEL_ALPN)
                .await
                .unwrap();
            authenticate_client(&connection, "test", &capability, None)
                .await
                .unwrap();
            authenticated.push((client_endpoint, connection));
        }

        let excess_endpoint = endpoint().await;
        let excess = excess_endpoint
            .connect(server_addr.clone(), TUNNEL_ALPN)
            .await
            .unwrap();
        let error = authenticate_client(&excess, "test", &capability, None)
            .await
            .expect_err("a saturated server must reject before authentication succeeds")
            .to_string();
        assert!(error.contains("capacity"), "{error}");

        let (released_endpoint, released) = authenticated.pop().unwrap();
        released.close(0_u32.into(), b"release authenticated capacity");
        released_endpoint.close().await;

        let (recovered_endpoint, recovered) = loop {
            let client_endpoint = endpoint().await;
            let connection = client_endpoint
                .connect(server_addr.clone(), TUNNEL_ALPN)
                .await
                .unwrap();
            match authenticate_client(&connection, "test", &capability, None).await {
                Ok(()) => break (client_endpoint, connection),
                Err(error) if error.to_string().contains("capacity") => {
                    client_endpoint.close().await;
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("recovery authentication failed unexpectedly: {error:#}"),
            }
        };
        let (mut recovered_send, _recovered_receive) = open_tui(&recovered).await;
        recovered_send
            .write_all(b"capacity-recovered")
            .await
            .unwrap();
        recovered_send.finish().unwrap();
        let mut recovered_upstream = accept(&tui).await;
        let mut recovered_payload = Vec::new();
        recovered_upstream
            .read_to_end(&mut recovered_payload)
            .await
            .unwrap();
        assert_eq!(recovered_payload, b"capacity-recovered");

        recovered_endpoint.close().await;
        excess_endpoint.close().await;
        drop(authenticated);
        replacement_endpoint.close().await;
        established_endpoint.close().await;
        closer.close().await;
        let _ = server.await;
    })
    .await;
}

#[tokio::test]
async fn endpoint_fatal_failure_is_propagated() {
    within(async {
        let root = tempfile::tempdir().unwrap();
        let tui_path = root.path().join("tui.sock");
        let _tui = UnixListener::bind(&tui_path).unwrap();
        let session = Session::new("test".to_owned(), tui_path);
        let endpoint = endpoint().await;
        let closer = endpoint.clone();
        let server = tokio::spawn(async move {
            serve_endpoint(
                &endpoint,
                session,
                CapabilitySecret::generate(),
                None,
                std::future::pending::<Result<()>>(),
            )
            .await
        });

        closer.close().await;
        let error = server.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("stopped accepting"), "{error}");
    })
    .await;
}

#[tokio::test]
async fn local_tui_forwarder_enforces_stream_limit_and_recovers() {
    within(async {
        let harness = Harness::authenticated().await;
        let (workspace, tui_listener) = SocketWorkspace::create().await.unwrap();
        let cancellation = CancellationToken::new();
        let mut forwarders = spawn_forwarders(
            tui_listener,
            harness.connection.clone(),
            cancellation.clone(),
            1,
        );
        let mut local_clients = Vec::new();
        let mut upstreams = Vec::new();

        for _ in 0..MAX_STREAMS_PER_CONNECTION {
            local_clients.push(UnixStream::connect(workspace.tui_path()).await.unwrap());
            upstreams.push(accept(&harness.tui).await);
        }

        let mut excess = UnixStream::connect(workspace.tui_path()).await.unwrap();
        excess.write_all(b"queued").await.unwrap();
        let mut byte = [0];
        assert!(
            timeout(Duration::from_millis(100), excess.read(&mut byte))
                .await
                .is_err(),
            "the excess local TUI stream was opened and rejected instead of waiting"
        );

        drop(local_clients.pop());
        drop(upstreams.pop());
        let mut recovered_upstream = accept(&harness.tui).await;
        let mut payload = [0; 6];
        recovered_upstream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"queued");

        cancellation.cancel();
        while forwarders.join_next().await.is_some() {}
        drop(local_clients);
        drop(upstreams);
        harness.close().await;
    })
    .await;
}

#[tokio::test]
async fn server_stream_limit_rejects_excess_and_recovers_after_release() {
    within(async {
        let harness = Harness::authenticated().await;
        let mut held = Vec::new();
        let mut upstreams = Vec::new();
        for _ in 0..MAX_STREAMS_PER_CONNECTION {
            held.push(harness.open().await);
            upstreams.push(accept(&harness.tui).await);
        }

        let (mut excess_send, mut excess_receive) = harness.open().await;
        excess_send.write_all(b"excess").await.unwrap();
        excess_send.finish().unwrap();
        assert!(
            timeout(Duration::from_millis(100), harness.tui.accept())
                .await
                .is_err()
        );
        let excess = excess_receive.read_to_end(1).await;
        assert!(excess.is_err() || excess.unwrap().is_empty());

        drop(held.pop());
        drop(upstreams.pop());
        tokio::task::yield_now().await;

        let (mut recovered_send, _recovered_receive) = harness.open().await;
        let mut recovered_upstream = accept(&harness.tui).await;
        recovered_send.write_all(b"recovered").await.unwrap();
        recovered_send.finish().unwrap();
        let mut recovered = Vec::new();
        recovered_upstream
            .read_to_end(&mut recovered)
            .await
            .unwrap();
        assert_eq!(recovered, b"recovered");

        drop(held);
        drop(upstreams);
        harness.close().await;
    })
    .await;
}
