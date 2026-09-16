use super::*;
use iroh::RelayMode;
use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;

fn local_builder() -> iroh::endpoint::Builder {
    Endpoint::builder(presets::N0)
        .clear_ip_transports()
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_prefix_len(8),
        )
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![EVENTS_ALPN.to_vec(), TUNNEL_ALPN.to_vec()])
}

#[tokio::test]
async fn ephemeral_watchers_must_prove_the_consumer_key_before_dispatch_and_cannot_replay() {
    timeout(Duration::from_secs(20), async {
        let consumer = iroh::SecretKey::from_bytes(&[4; 32]);
        let server = local_builder()
            .hooks(ConsumerIdentityAuthorization::new(
                AuthorizedConsumerIdentity::from_bytes(*consumer.public().as_bytes()),
            ))
            .bind()
            .await
            .unwrap();
        let client = local_builder().bind().await.unwrap();
        assert_ne!(
            client.id(),
            consumer.public(),
            "watcher must not share the interactive relay identity"
        );
        let mut previous_signature = [0; 64];
        for case in ["valid", "wrong-key", "replay", "wrong-domain"] {
            let incoming = server.accept();
            let outgoing = client.connect(server.addr(), EVENTS_ALPN);
            let server_task = async {
                let connection = incoming.await.unwrap().await;
                if let Ok(connection) = &connection {
                    // No dispatch is possible until the EndpointHook accepts the proof.
                    assert_eq!(case, "valid");
                    let _ = connection.closed().await;
                }
                connection.is_ok()
            };
            let client_task = async {
                let connection = outgoing.await.unwrap();
                let mut material = [0; 32];
                connection
                    .export_keying_material(&mut material, b"attached-events-consumer-v1", b"")
                    .unwrap();
                let mut message = if case == "wrong-domain" {
                    b"attached/other-operation/v1\0".to_vec()
                } else {
                    b"attached/events/consumer-proof/v1\0".to_vec()
                };
                message.extend_from_slice(&material);
                let signature = match case {
                    "wrong-key" => iroh::SecretKey::from_bytes(&[5; 32])
                        .sign(&message)
                        .to_bytes(),
                    "replay" => previous_signature,
                    _ => consumer.sign(&message).to_bytes(),
                };
                if case == "valid" {
                    previous_signature = signature;
                }
                let (mut send, mut receive) = connection.open_bi().await.unwrap();
                send.write_all(&signature).await.unwrap();
                send.finish().unwrap();
                let accepted = receive.read_u8().await.is_ok_and(|byte| byte == 0);
                assert_eq!(accepted, case == "valid");
                connection.close(0_u32.into(), b"test complete");
            };
            let (accepted, ()) = tokio::join!(server_task, client_task);
            assert_eq!(accepted, case == "valid");
        }
        // Even a watcher that can sign proofs cannot use its ephemeral transport
        // identity for interactive control: other ALPNs retain the original gate.
        let (incoming, outgoing) = tokio::join!(
            async { server.accept().await.unwrap().await },
            client.connect(server.addr(), TUNNEL_ALPN)
        );
        assert!(incoming.is_err());
        if let Ok(connection) = outgoing {
            let _ = connection.closed().await;
        }
        client.close().await;
        server.close().await;
    })
    .await
    .unwrap();
}
