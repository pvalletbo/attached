use std::{future::pending, time::Duration};

use super::*;
use attached_tunnel_protocol::{
    CapabilitySecret, HerdrVersion, TUNNEL_ALPN, authenticate_server, read_stream_header,
};
use iroh::{Endpoint, endpoint::presets};

#[test]
fn errors_exposed_to_javascript_are_generic() {
    assert_eq!(
        sanitize_error("connect"),
        "unable to connect to the Herdr tunnel"
    );
    assert_eq!(MAX_RECEIVE_CHUNK, 64 * 1024);
}

#[tokio::test]
async fn connection_attempts_have_a_deadline() {
    let result = connect_with_controls(
        Duration::from_millis(1),
        CancellationToken::new(),
        pending::<Result<(), String>>(),
    )
    .await;

    assert_eq!(result.unwrap_err(), "connection timed out");
}

#[tokio::test]
async fn connection_attempts_can_be_cancelled() {
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let result = connect_with_controls(
        Duration::from_secs(30),
        cancellation,
        pending::<Result<(), String>>(),
    )
    .await;

    assert_eq!(result.unwrap_err(), "connection cancelled");
}

#[tokio::test]
async fn browser_client_authenticates_before_opening_a_tui_stream() {
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![TUNNEL_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    server.online().await;
    let capability = CapabilitySecret::generate();
    let server_capability = capability.clone();
    let server_endpoint = server.clone();
    let server_task = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        let (mut auth_send, mut auth_receive) = connection.accept_bi().await.unwrap();
        authenticate_server(
            &mut auth_receive,
            &mut auth_send,
            &server_capability,
            HerdrVersion::new(0, 7, 5),
            |session| async move {
                anyhow::ensure!(session == "default", "unexpected session");
                Ok(())
            },
            || Ok(()),
        )
        .await
        .unwrap();
        let (mut send, mut receive) = connection.accept_bi().await.unwrap();
        read_stream_header(&mut receive).await.unwrap();
        let mut request = [0_u8; 4];
        receive.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        send.write_all(b"pong").await.unwrap();
        send.finish().unwrap();
        let _ = connection.closed().await;
    });

    let tunnel = connect_tunnel_controlled(
        server.addr(),
        "default".to_owned(),
        capability,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    tunnel.send(b"ping").await.unwrap();
    assert_eq!(tunnel.receive().await.unwrap().unwrap(), b"pong");
    tunnel.close().await;
    server_task.await.unwrap();
    server.close().await;
}
