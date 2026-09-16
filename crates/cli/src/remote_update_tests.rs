use super::*;
use attached_tunnel_protocol::{
    AttachedUpdateRequest, read_attached_update_request, write_attached_update_response,
};
use iroh::{RelayMode, endpoint::BindOpts};
use std::{future::Future, net::Ipv4Addr};
async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("offline update timed out")
}
async fn attached_update_endpoint(
    identity: iroh::SecretKey,
    bind_addr: Option<std::net::SocketAddr>,
) -> Endpoint {
    Endpoint::builder(presets::N0)
        .secret_key(identity)
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
        .await
        .unwrap()
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
                AttachedUpdateRequest::Start
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
        let installed = request_attached_update_on_endpoint(&client, old_addr, &capability)
            .await
            .unwrap();
        assert_eq!(installed, candidate_version);
        client.close().await;
        old_server.await.unwrap();
        candidate_server.await.unwrap();
    })
    .await;
}
