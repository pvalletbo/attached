use super::*;
use attached_session_sync_protocol::account::ConsumerIdentitySecret;
use attached_tunnel_protocol::{
    read_attached_update_response, write_attached_update_confirm_request,
};
use iroh::RelayMode;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn offline(builder: iroh::endpoint::Builder) -> Endpoint {
    builder
        .clear_ip_transports()
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_prefix_len(8),
        )
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn serving_admits_only_the_consumer_and_only_ssh_or_attached_update() {
    timeout(Duration::from_secs(15), async {
        let consumer = ConsumerIdentitySecret::from_bytes([0x5a; 32]);
        let key = iroh::SecretKey::from_bytes(consumer.as_bytes());
        let publisher = offline(server_endpoint_builder(
            &iroh::SecretKey::generate(),
            consumer.authorized_identity(),
        ))
        .await;
        for alpn in [crate::ssh::ALPN, ATTACHED_UPDATE_ALPN] {
            for authorized in [true, false] {
                let peer_key = if authorized {
                    key.clone()
                } else {
                    iroh::SecretKey::generate()
                };
                let peer = offline(Endpoint::builder(presets::N0).secret_key(peer_key)).await;
                let (client, server) = tokio::join!(peer.connect(publisher.addr(), alpn), async {
                    publisher.accept().await.unwrap().await
                });
                if authorized {
                    let client = client.unwrap();
                    let server = server.unwrap();
                    assert_eq!(server.remote_id(), key.public());
                    assert_eq!(server.alpn(), alpn);
                    client.close(0u32.into(), b"test complete");
                    server.close(0u32.into(), b"test complete");
                } else {
                    assert!(
                        server.is_err(),
                        "unauthorized peer reached application dispatch"
                    );
                    drop(client);
                }
                peer.close().await;
            }
        }
        for obsolete in [
            b"herdr-tunnel/3".as_slice(),
            b"herdr-upgrade/1",
            b"attached-update/1",
        ] {
            let peer = offline(Endpoint::builder(presets::N0).secret_key(key.clone())).await;
            let (client, server) = tokio::join!(peer.connect(publisher.addr(), obsolete), async {
                publisher.accept().await.unwrap().await
            });
            assert!(client.is_err() && server.is_err(), "accepted obsolete ALPN");
            peer.close().await;
        }
        publisher.close().await;
    })
    .await
    .expect("server admission timed out");
}

#[tokio::test]
async fn production_dispatch_serves_ssh_and_host_update_without_application_state() {
    timeout(Duration::from_secs(15), async {
        let root = crate::test_support::canonical_tempdir();
        crate::secure_state::prepare_private_dir(root.path()).unwrap();
        let consumer = ConsumerIdentitySecret::from_bytes([0x5a; 32]);
        let publisher = offline(server_endpoint_builder(&iroh::SecretKey::generate(), consumer.authorized_identity())).await;
        let client = offline(Endpoint::builder(presets::N0).secret_key(iroh::SecretKey::from_bytes(consumer.as_bytes()))).await;
        crate::secure_state::StateDir::open(root.path()).unwrap().atomic_replace("ssh-access.json", &serde_json::to_vec(&serde_json::json!({
            "consumer": client.id().as_bytes(), "uid": rustix::process::geteuid().as_raw(),
            "username": "attached-test", "home": root.path(), "shell": "/bin/sh",
            "generation": vec![3; 32], "enabled": true,
        })).unwrap()).unwrap();
        let capability = CapabilitySecret::from_bytes([7; 32]);
        let abort = CancellationToken::new();
        let resources = Arc::new(UpdateResources {
            config: ServeConfig { state_dir: root.path().to_owned(), host_label: "office".into() },
            master_key: Arc::new(Zeroizing::new([9; 32])), endpoint_identity: *publisher.id().as_bytes(),
            bind_sockets: publisher.bound_sockets(), capability: capability.clone(),
            update_limit: Arc::new(Semaphore::new(1)), active_operation: Arc::new(Mutex::new(None)),
            candidate: None, rollback: None,
        });
        let serve = serve_endpoint(&publisher, capability.clone(), resources, Some(abort.clone()));
        let exercise = async {
            let ssh = client.connect(publisher.addr(), crate::ssh::ALPN).await.unwrap();
            let (mut send, mut receive) = ssh.open_bi().await.unwrap();
            let key = russh::keys::PrivateKey::new(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[4; 32]).into(), "test").unwrap();
            let request = serde_json::to_vec(&serde_json::json!({"capability": capability.to_bytes(), "public_key": key.public_key().to_openssh().unwrap()})).unwrap();
            send.write_u32(request.len() as u32).await.unwrap();
            send.write_all(&request).await.unwrap();
            let length = receive.read_u32().await.unwrap() as usize;
            assert!(length <= 8192);
            let mut bytes = vec![0; length]; receive.read_exact(&mut bytes).await.unwrap();
            let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(response["username"], "attached-test");
            assert!(response["host_key"].as_str().unwrap().starts_with("ssh-ed25519 "));
            ssh.close(0u32.into(), b"test complete");
            let update = client.connect(publisher.addr(), ATTACHED_UPDATE_ALPN).await.unwrap();
            let (mut send, mut receive) = update.open_bi().await.unwrap();
            write_attached_update_confirm_request(&mut send, &capability, UpdateOperationId::from_bytes([6; 16]), attached_version::current()).await.unwrap();
            assert!(matches!(read_attached_update_response(&mut receive).await.unwrap(), AttachedUpdateResponse::Failed(reason) if reason == "unknown Attached update operation"));
            update.close(0u32.into(), b"test complete");
            abort.cancel();
        };
        let (result, ()) = tokio::join!(serve, exercise);
        assert!(matches!(result.unwrap(), EndpointOutcome::CandidateAborted));
        client.close().await; publisher.close().await;
    }).await.expect("host serving timed out");
}
