use super::*;
use attached_tunnel_protocol::FOCUSED_TUNNEL_ALPN;
use iroh::{
    RelayMode,
    endpoint::{BindOpts, presets},
};
use std::{
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn endpoint(alpns: Vec<Vec<u8>>) -> Endpoint {
    Endpoint::builder(presets::N0)
        .clear_ip_transports()
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_prefix_len(8),
        )
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(alpns)
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn focused_attach_authenticates_before_api_access_and_proxies_tui_after_focus() {
    timeout(Duration::from_secs(20), async {
        for (valid_capability, occupant) in [(false, "term2"), (true, "term2"), (true, "stale")] {
            let root = crate::test_support::canonical_tempdir();
            let api_path = root.path().join("herdr.sock");
            let tui_path = root.path().join("herdr-client.sock");
            let api = UnixListener::bind(&api_path).unwrap();
            let tui = UnixListener::bind(&tui_path).unwrap();
            std::fs::set_permissions(&api_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let server = endpoint(vec![FOCUSED_TUNNEL_ALPN.to_vec()]).await;
            let client = endpoint(vec![]).await;
            let address = server.addr();
            let resolved = Arc::new(AtomicBool::new(false));
            let flag = resolved.clone();
            let cancellation = CancellationToken::new();
            let stop = cancellation.clone();
            let server_task = tokio::spawn(async move {
                let connection = server.accept().await.unwrap().await.unwrap();
                let result = serve_connection(connection, 1, &CapabilitySecret::from_bytes([1;32]),
                    HerdrVersion::new(0,8,2), stop,
                    move |name| async move {
                        flag.store(true, Ordering::SeqCst);
                        assert_eq!(name, "work");
                        Ok(Session::new(name, tui_path))
                    }, || Ok(())).await;
                server.close().await;
                result
            });
            let connection = client.connect(address, FOCUSED_TUNNEL_ALPN).await.unwrap();
            let pane = crate::pane_focus::PaneFocus {pane_id: "w1:p2".into(), terminal_id: Some(occupant.into())};
            let key = if valid_capability {[1;32]} else {[2;32]};
            let capability = CapabilitySecret::from_bytes(key);
            let auth = authenticate_client(&connection, "work", &capability, HerdrVersion::new(0,8,2), Some(&pane));
            let api_task = async {
                if !valid_capability { return; }
                let methods: &[&str] = if occupant == "term2" { &["pane.get", "pane.focus"] } else { &["pane.get"] };
                for &method in methods {
                    assert!(timeout(Duration::from_millis(10), tui.accept()).await.is_err(), "TUI opened before focus finished");
                    let (stream, _) = api.accept().await.unwrap();
                    let mut lines = BufReader::new(stream);
                    let mut line = String::new();
                    lines.read_line(&mut line).await.unwrap();
                    let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(request["method"], method);
                    assert_eq!(request["params"], serde_json::json!({"pane_id":"w1:p2"}));
                    lines.get_mut().write_all(b"{\"id\":\"attached-focus\",\"result\":{\"pane\":{\"pane_id\":\"w1:p2\",\"terminal_id\":\"term2\"}}}\n").await.unwrap();
                }
            };
            let (auth, ()) = timeout(Duration::from_secs(12), async { tokio::join!(auth, api_task) }).await.expect("authentication/API exchange timed out");
            assert_eq!(auth.is_ok(), valid_capability);
            assert_eq!(resolved.load(Ordering::SeqCst), valid_capability);
            assert!(timeout(Duration::from_millis(30), api.accept()).await.is_err(), "unexpected extra API operation");
            if valid_capability {
                let (mut send, mut receive) = connection.open_bi().await.unwrap();
                write_stream_header(&mut send).await.unwrap();
                let (mut stream, _) = timeout(Duration::from_secs(2), tui.accept()).await.expect("TUI accept timed out").unwrap();
                stream.write_all(b"hello").await.unwrap();
                let mut bytes = [0;5];
                timeout(Duration::from_secs(2), receive.read_exact(&mut bytes)).await.expect("TUI output timed out").unwrap();
                assert_eq!(&bytes, b"hello");
            } else {
                assert!(timeout(Duration::from_millis(30), api.accept()).await.is_err());
                assert!(timeout(Duration::from_millis(30), tui.accept()).await.is_err());
            }
            cancellation.cancel();
            connection.close(0_u32.into(), b"test complete");
            let result = timeout(Duration::from_secs(2), server_task).await.expect("server shutdown timed out").unwrap();
            if !valid_capability {assert!(result.is_err());}
            client.close().await;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn older_hosts_fall_back_to_ordinary_authenticated_tunnel_protocol() {
    timeout(Duration::from_secs(15), async {
        let server = endpoint(vec![TUNNEL_ALPN.to_vec()]).await;
        let client = endpoint(vec![]).await;
        let incoming = async {
            loop {
                if let Ok(connection) = server.accept().await.unwrap().await {
                    break connection;
                }
            }
        };
        let (incoming, outgoing) = tokio::join!(
            incoming,
            connect_for_attachment(&client, server.addr(), true)
        );
        let outgoing = outgoing.unwrap();
        assert_eq!(incoming.alpn(), TUNNEL_ALPN);
        assert_eq!(outgoing.alpn(), TUNNEL_ALPN);
        outgoing.close(0_u32.into(), b"done");
        client.close().await;
        server.close().await;
    })
    .await
    .unwrap();
}
