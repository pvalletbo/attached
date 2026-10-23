//! Exercise the real CLI's discovery, encrypted credentials, local TCP listener,
//! wire protocol, and signal cleanup. Publisher data-path behavior is covered by
//! the in-process Iroh/TCP integration tests in forward_tests.rs.
use super::*;
use attached_tunnel_protocol::{
    TCP_FORWARD_ALPN, TcpForwardStatus, read_tcp_forward_open, read_tcp_forward_request,
    write_tcp_forward_status,
};
use tokio::{io::AsyncReadExt, net::TcpStream, task::JoinSet};

#[tokio::test]
async fn forwarding_help_and_bind_errors_do_not_require_credentials() {
    let fixture = CliFixture::new();
    let output = fixture.run(&["forward", "--help"]).await;
    output.assert_code(0);
    assert!(output.stdout.contains("--local"));
    assert!(output.stdout.contains("--remote"));
    assert!(output.stdout.contains("127.0.0.1"));
    assert!(output.stdout.contains("never other hosts"));
    assert!(output.stdout.contains("relays"));
    let busy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = busy.local_addr().unwrap().port().to_string();
    let output = fixture
        .run(&["forward", "office", "--local", &port, "--remote", "4096"])
        .await;
    output.assert_code(1);
    assert!(
        output
            .stderr
            .contains(&format!("could not bind local TCP port 127.0.0.1:{port}")),
        "{output:?}"
    );
}

#[tokio::test]
async fn termination_interrupts_stalled_initial_discovery() {
    timeout(DEADLINE, async {
        let fixture = CliFixture::new();
        let discovery = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", discovery.local_addr().unwrap());
        import_with_identity(&fixture, &origin, iroh::SecretKey::generate().to_bytes()).await;
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reservation.local_addr().unwrap();
        drop(reservation);
        let running = fixture.spawn(fixture.command(&[
            "--use-1password",
            "forward",
            "remote",
            "--local",
            &local.port().to_string(),
            "--remote",
            "4096",
            "--no-cache",
        ]));
        let (mut request_stream, _) = discovery.accept().await.unwrap();
        request(&mut request_stream).await;
        // Never send headers: shutdown must not wait for the HTTP deadline.
        running.signal(rustix::process::Signal::TERM);
        let output = timeout(Duration::from_secs(4), running.wait())
            .await
            .unwrap();
        output.assert_code(0);
        assert!(TcpStream::connect(local).await.is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn real_cli_forwards_single_port_and_cleans_up_on_terminal_signals() {
    for signal in [
        rustix::process::Signal::INT,
        rustix::process::Signal::TERM,
        rustix::process::Signal::HUP,
    ] {
        timeout(DEADLINE, async {
            let fixture = CliFixture::new();
            let discovery = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", discovery.local_addr().unwrap());
            let consumer_key = iroh::SecretKey::generate();
            import_with_identity(&fixture, &origin, consumer_key.to_bytes()).await;
            let publisher = Endpoint::builder(presets::N0)
                .clear_ip_transports()
                .bind_addr_with_opts(
                    (Ipv4Addr::LOCALHOST, 0),
                    BindOpts::default().set_prefix_len(8),
                )
                .unwrap()
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
                .alpns(vec![TCP_FORWARD_ALPN.to_vec()])
                .bind()
                .await
                .unwrap();
            let (index, record) = catalog(&EndpointTicket::new(publisher.addr()).to_string(), 1);
            let http = tokio::spawn(async move {
                respond(&mut checked_request(&discovery, false).await, &index, "").await;
                respond(
                    &mut checked_request(&discovery, true).await,
                    &record,
                    "ETag: \"1\"\r\n",
                )
                .await;
            });
            let server = {
                let publisher = publisher.clone();
                tokio::spawn(async move {
                    let connection = publisher.accept().await.unwrap().await.unwrap();
                    assert_eq!(connection.remote_id(), consumer_key.public());
                    assert_eq!(connection.alpn(), TCP_FORWARD_ALPN);
                    let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                    assert_eq!(
                        read_tcp_forward_request(
                            &mut receive,
                            &CapabilitySecret::from_bytes([46; 32])
                        )
                        .await
                        .unwrap(),
                        4096
                    );
                    write_tcp_forward_status(&mut send, TcpForwardStatus::Ready)
                        .await
                        .unwrap();
                    send.shutdown().await.unwrap();
                    let mut tasks = JoinSet::new();
                    for _ in 0..2 {
                        let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                        tasks.spawn(async move {
                            read_tcp_forward_open(&mut receive).await.unwrap();
                            write_tcp_forward_status(&mut send, TcpForwardStatus::Ready)
                                .await
                                .unwrap();
                            send.write_all(b"banner\0\xff").await.unwrap();
                            let request = receive.read_to_end(1024).await.unwrap();
                            send.write_all(&request).await.unwrap();
                            send.shutdown().await.unwrap();
                        });
                    }
                    while let Some(result) = tasks.join_next().await {
                        result.unwrap();
                    }
                    connection.closed().await;
                })
            };
            let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = reservation.local_addr().unwrap();
            drop(reservation);
            let port = address.port().to_string();
            let running = fixture.spawn(fixture.command(&[
                "--use-1password",
                "forward",
                "remote",
                "--local",
                &port,
                "--remote",
                "4096",
                "--no-cache",
            ]));
            timeout(DEADLINE, async {
                while !running.stderr().contains("Forwarding ") {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("forwarder did not become ready: {}", running.stderr()));
            let mut tools = JoinSet::new();
            for _ in 0..2 {
                tools.spawn(async move {
                    let mut stream = TcpStream::connect(address).await.unwrap();
                    let mut banner = [0; 8];
                    stream.read_exact(&mut banner).await.unwrap();
                    assert_eq!(&banner, b"banner\0\xff");
                    stream.write_all(b"request\0\xff").await.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).await.unwrap();
                    assert_eq!(response, b"request\0\xff");
                });
            }
            while let Some(result) = tools.join_next().await {
                result.unwrap();
            }
            running.signal(signal);
            let output = running.wait().await;
            output.assert_code(0);
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(!output.stderr.contains("connection failed"), "{output:?}");
            assert!(
                TcpStream::connect(address).await.is_err(),
                "listener survived shutdown"
            );
            http.await.unwrap();
            server.await.unwrap();
            publisher.close().await;
        })
        .await
        .expect("real forward CLI timed out");
    }
}
