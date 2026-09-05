use super::*;
use iroh::{
    RelayMode,
    endpoint::{BindOpts, presets},
};
use std::{
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};

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
        .alpns(vec![EVENTS_ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn unauthenticated_peer_cannot_resolve_or_open_any_herdr_socket() {
    let server = endpoint().await;
    let client = endpoint().await;
    let resolved = Arc::new(AtomicBool::new(false));
    let flag = resolved.clone();
    let address = server.addr();
    let service = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        authorize_identity(
            &connection,
            iroh::SecretKey::from_bytes(&[3; 32]).public().as_bytes(),
        )
        .await
        .unwrap();
        let result = serve(
            connection,
            &CapabilitySecret::from_bytes([1; 32]),
            HerdrVersion::new(0, 8, 2),
            CancellationToken::new(),
            move |_| async move {
                flag.store(true, Ordering::SeqCst);
                anyhow::bail!("must not resolve")
            },
            || Ok(()),
        )
        .await;
        server.close().await;
        result
    });
    let result = connect(
        &client,
        &iroh::SecretKey::from_bytes(&[3; 32]),
        address,
        "test",
        &CapabilitySecret::from_bytes([2; 32]),
    )
    .await;
    assert!(result.is_err());
    let _ = timeout(Duration::from_secs(15), service)
        .await
        .unwrap()
        .unwrap();
    assert!(!resolved.load(Ordering::SeqCst));
    client.close().await;
}

#[tokio::test]
async fn authenticated_event_tunnel_is_server_only_and_never_opens_tui() {
    timeout(Duration::from_secs(20), async {
        let root = crate::test_support::canonical_tempdir();
        let api_path = root.path().join("herdr.sock");
        let api = UnixListener::bind(&api_path).unwrap();
        std::fs::set_permissions(&api_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let tui_path = root.path().join("herdr-client.sock");
        let tui = UnixListener::bind(&tui_path).unwrap();
        let api_task = tokio::spawn(async move {
            let (stream, _) = api.accept().await.unwrap();
            let mut lines = BufReader::new(stream);
            let mut request = String::new();
            lines.read_line(&mut request).await.unwrap();
            assert!(request.contains("pane.list"));
            lines.get_mut().write_all(b"{\"id\":\"attached-events\",\"result\":{\"panes\":[]}}\n").await.unwrap();
            let (stream, _) = api.accept().await.unwrap();
            let mut lines = BufReader::new(stream);
            request.clear();
            lines.read_line(&mut request).await.unwrap();
            assert!(request.contains("events.subscribe"));
            lines.get_mut().write_all(b"{\"id\":\"attached-events\",\"result\":{\"type\":\"subscription_started\"}}\n").await.unwrap();
            // Retain the subscription until the tunnel closes.
            request.clear();
            assert_eq!(lines.read_line(&mut request).await.unwrap(), 0);
        });
        let server = endpoint().await;
        let client = endpoint().await;
        let address = server.addr();
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let service = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            authorize_identity(&connection, iroh::SecretKey::from_bytes(&[3; 32]).public().as_bytes()).await.unwrap();
            let result = serve(connection, &CapabilitySecret::from_bytes([1; 32]), HerdrVersion::new(0,8,2), stop,
                move |name| async move { anyhow::ensure!(name == "work", "bad session"); Ok(Session::new(name, tui_path)) }, || Ok(())).await;
            server.close().await;
            result
        });
        let (guard, stream) = connect(&client, &iroh::SecretKey::from_bytes(&[3; 32]), address, "work", &CapabilitySecret::from_bytes([1; 32])).await.unwrap();
        let mut lines = super::super::protocol::Lines::new(BufReader::new(stream));
        let baseline = lines.next().await.unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&baseline).unwrap(), serde_json::json!({"type":"snapshot","panes":[]}));
        assert!(timeout(Duration::from_millis(30), tui.accept()).await.is_err());
        // Unused bidirectional streams have no route to Herdr's JSON API.
        let (mut malicious, _) = guard.connection.open_bi().await.unwrap();
        malicious.write_all(b"{\"method\":\"pane.close\"}\n").await.unwrap();
        cancellation.cancel();
        service.await.unwrap().unwrap();
        api_task.await.unwrap();
        drop(guard);
        client.close().await;
    }).await.unwrap();
}
