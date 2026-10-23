use super::*;
use iroh::{EndpointAddr, EndpointId, RelayMode};
use std::{
    net::Ipv4Addr,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn ipc_frames_are_bounded_and_versioned() {
    let mut oversized = (ipc::MAX_FRAME as u32 + 1).to_be_bytes().to_vec();
    assert!(
        ipc::read::<_, Request>(&mut oversized.as_slice())
            .await
            .is_err()
    );
    oversized.clear();
    ipc::write(
        &mut oversized,
        &Request {
            version: ipc::VERSION,
            operation: Operation::Lease {
                identity: SecretKey::generate().public(),
            },
        },
    )
    .await
    .unwrap();
    let request: Request = ipc::read(&mut oversized.as_slice()).await.unwrap();
    assert_eq!(request.version, ipc::VERSION);
    assert!(
        serde_json::from_slice::<Request>(br#"{"version":1,"operation":{"op":"Lease","extra":1}}"#)
            .is_err()
    );
}

async fn rpc(path: &Path, operation: Operation) -> (UnixStream, Response) {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let response = ipc::request(&mut stream, operation).await.unwrap();
    (stream, response)
}

async fn lease(path: &Path, identity: EndpointId) -> (UnixStream, Token) {
    let (stream, response) = rpc(path, Operation::Lease { identity }).await;
    let Response::Lease { lease, .. } = response else {
        panic!("expected lease");
    };
    (stream, lease)
}

async fn connect(
    path: &Path,
    lease: Token,
    address: EndpointAddr,
    alpn: &[u8],
) -> (UnixStream, Token) {
    let (stream, response) = rpc(
        path,
        Operation::Connect {
            lease,
            address,
            alpn: alpn.to_vec(),
        },
    )
    .await;
    let Response::Connected { connection } = response else {
        panic!("expected connection");
    };
    (stream, connection)
}

async fn open(path: &Path, lease: Token, connection: Token) -> UnixStream {
    let (stream, response) = rpc(path, Operation::Open { lease, connection }).await;
    assert!(matches!(response, Response::Open));
    stream
}

async fn roundtrip(stream: &mut UnixStream, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    let mut reply = vec![0; bytes.len()];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, bytes);
}

#[derive(Debug)]
struct CountConsumer {
    identity: EndpointId,
    registrations: AtomicUsize,
}
impl iroh_relay::server::AccessControl for CountConsumer {
    async fn on_connect(
        &self,
        request: &iroh_relay::server::ClientRequest,
    ) -> iroh_relay::server::Access {
        if request.endpoint_id() == self.identity {
            self.registrations.fetch_add(1, Ordering::SeqCst);
        }
        iroh_relay::server::Access::Allow
    }
}

#[tokio::test]
async fn shared_broker_uses_one_real_relay_registration_and_isolates_client_leases() {
    timeout(Duration::from_secs(30), async {
        let key = SecretKey::generate();
        let access = Arc::new(CountConsumer {
            identity: key.public(),
            registrations: AtomicUsize::new(0),
        });
        let mut relay_config = iroh_relay::server::RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay_config.access = access.clone();
        let mut config = iroh_relay::server::ServerConfig::default();
        config.relay = Some(relay_config);
        let relay = iroh_relay::server::Server::spawn(config).await.unwrap();
        let url: iroh::RelayUrl = format!("http://{}", relay.http_addr().unwrap())
            .parse()
            .unwrap();
        let mode = RelayMode::custom([url]);
        let publisher = Endpoint::builder(presets::N0)
            .clear_ip_transports()
            .clear_address_lookup()
            .relay_mode(mode.clone())
            .alpns(vec![
                crate::ssh::ALPN.to_vec(),
                crate::forward::ALPN.to_vec(),
            ])
            .bind()
            .await
            .unwrap();
        publisher.online().await;
        let cancel = CancellationToken::new();
        let echo = {
            let publisher = publisher.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        incoming = publisher.accept() => {
                            tasks.spawn(async move {
                                let connection = incoming.unwrap().await.unwrap();
                                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                                let _ = tokio::io::copy(&mut receive, &mut send).await;
                                let _ = send.shutdown().await;
                                let _ = send.stopped().await;
                            });
                        }
                        _ = tasks.join_next(), if !tasks.is_empty() => {},
                    }
                }
            })
        };
        let root = crate::test_support::canonical_tempdir();
        let path = root.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let identity = key.public();
        let broker = tokio::spawn(serve(listener, move || {
            Endpoint::builder(presets::N0)
                .secret_key(key.clone())
                .clear_ip_transports()
                .clear_address_lookup()
                .relay_mode(mode.clone())
        }));
        let (exporter, ssh_lease) = lease(&path, identity).await;
        let (forwarder, tcp_lease) = lease(&path, identity).await;
        let (ssh_control, ssh) =
            connect(&path, ssh_lease, publisher.addr(), crate::ssh::ALPN).await;
        let (tcp_control, tcp) =
            connect(&path, tcp_lease, publisher.addr(), crate::forward::ALPN).await;
        let mut wrong_scope = UnixStream::connect(&path).await.unwrap();
        assert!(
            ipc::request(
                &mut wrong_scope,
                Operation::Open {
                    lease: tcp_lease,
                    connection: ssh
                }
            )
            .await
            .is_err()
        );
        drop(wrong_scope);
        let mut ssh_stream = open(&path, ssh_lease, ssh).await;
        let mut tcp_stream = open(&path, tcp_lease, tcp).await;
        let bytes: Vec<u8> = (0..262_144).map(|n| n as u8).collect();
        // Keep writes small here to test long-lived mixed protocols without
        // intentionally filling both sides of an echo stream's receive window.
        roundtrip(&mut ssh_stream, b"ssh\0\xff").await;
        roundtrip(&mut tcp_stream, &bytes[..1024]).await;
        assert_eq!(
            access.registrations.load(Ordering::SeqCst),
            1,
            "commands displaced one another on the relay"
        );
        drop(exporter);
        let ended = timeout(Duration::from_secs(3), ssh_stream.read(&mut [0; 1]))
            .await
            .unwrap();
        assert!(!matches!(ended, Ok(n) if n != 0));
        roundtrip(&mut tcp_stream, b"exporter-stopped\0\xff").await;
        let (second, connection) =
            connect(&path, tcp_lease, publisher.addr(), crate::forward::ALPN).await;
        let mut other = open(&path, tcp_lease, connection).await;
        roundtrip(&mut other, b"another-connection\0\xff").await;
        drop(second);
        roundtrip(&mut tcp_stream, b"one-connection-stopped\0\xff").await;
        assert_eq!(access.registrations.load(Ordering::SeqCst), 1);
        drop((
            forwarder,
            ssh_control,
            tcp_control,
            ssh_stream,
            tcp_stream,
            other,
        ));
        timeout(Duration::from_secs(6), broker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        cancel.cancel();
        echo.await.unwrap();
        publisher.close().await;
        relay.shutdown().await.unwrap();
    })
    .await
    .expect("relay-only broker test timed out");
}

#[tokio::test]
async fn broker_rejects_wrong_identity_version_and_unknown_sessions_without_dialing() {
    timeout(Duration::from_secs(10), async {
        let root = crate::test_support::canonical_tempdir();
        let path = root.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let key = SecretKey::generate();
        let identity = key.public();
        let broker = tokio::spawn(serve(listener, move || {
            Endpoint::builder(presets::N0)
                .secret_key(key.clone())
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
        }));
        for request in [
            Request {
                version: ipc::VERSION + 1,
                operation: Operation::Lease { identity },
            },
            Request {
                version: ipc::VERSION,
                operation: Operation::Lease {
                    identity: SecretKey::generate().public(),
                },
            },
            Request {
                version: ipc::VERSION,
                operation: Operation::Open {
                    lease: [0; 16],
                    connection: [0; 16],
                },
            },
            Request {
                version: ipc::VERSION,
                operation: Operation::Connect {
                    lease: [0; 16],
                    address: EndpointAddr::new(identity),
                    alpn: b"arbitrary".to_vec(),
                },
            },
        ] {
            let mut stream = UnixStream::connect(&path).await.unwrap();
            ipc::write(&mut stream, &request).await.unwrap();
            assert!(matches!(
                ipc::read::<_, Response>(&mut stream).await.unwrap(),
                Response::Error { .. }
            ));
        }
        let (client, _) = lease(&path, identity).await;
        drop(client);
        timeout(Duration::from_secs(6), broker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .await
    .unwrap();
}
