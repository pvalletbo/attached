use super::*;
use attached_session_sync_protocol::account::RecordId;
use attached_tunnel_protocol::{EVENTS_ALPN, authenticate_server};
use iroh::{
    RelayMode,
    endpoint::{BindOpts, presets},
};
use protocol::{Message, Pane, Status};
use std::net::Ipv4Addr;
use tokio::sync::oneshot;

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

fn pane(status: Status) -> Pane {
    Pane {
        pane_id: "w1:p1".into(),
        terminal_id: Some("term_1".into()),
        workspace_id: "w1".into(),
        agent_status: status,
        agent: Some("pi".into()),
        title: None,
    }
}

#[tokio::test]
async fn reconnect_is_live_only_and_interactive_suppression_does_not_replay() {
    timeout(Duration::from_secs(15), async {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        let server = endpoint().await;
        let client = endpoint().await;
        let identity = iroh::SecretKey::from_bytes(&[7; 32]);
        let attachment = SyncedAttachment {
            record_id: RecordId::from_bytes([1; 16]),
            service_revision: 1,
            endpoint_ticket: EndpointTicket::new(server.addr()).to_string(),
            endpoint_identity: *server.id().as_bytes(),
            attach_capability: [1; 32],
            attached_version: None,
            herdr_version: [0, 8, 2],
            expires_at: sync::utc_now_seconds() + chrono::Duration::seconds(30),
            session: "work".into(),
        };
        let active = activity::attach(&state_dir, attachment.endpoint_identity, "work").unwrap();
        let (suppressed_tx, suppressed_rx) = oneshot::channel();
        let (continue_tx, continue_rx) = oneshot::channel();
        let server_key = identity.public();
        let service = tokio::spawn(async move {
            // First connection publishes only a done baseline, then disconnects.
            for iteration in 0..2 {
                let connection = server.accept().await.unwrap().await.unwrap();
                transport::authorize_identity(&connection, server_key.as_bytes())
                    .await
                    .unwrap();
                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                authenticate_server(
                    &mut receive,
                    &mut send,
                    &CapabilitySecret::from_bytes([1; 32]),
                    herdr_version::HerdrVersion::new(0, 8, 2),
                    |name| async move { Ok(name) },
                    || Ok(()),
                )
                .await
                .unwrap();
                let mut events = connection.open_uni().await.unwrap();
                protocol::write_message(
                    &mut events,
                    &Message::Snapshot {
                        panes: vec![pane(Status::Done)],
                    },
                )
                .await
                .unwrap();
                if iteration == 0 {
                    // Ensure bootstrap was received before simulating host loss.
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    connection.close(0_u32.into(), b"simulated disconnect");
                    continue;
                }
                for status in [Status::Working, Status::Blocked, Status::Idle] {
                    protocol::write_message(&mut events, &Message::State { pane: pane(status) })
                        .await
                        .unwrap();
                }
                // Wait until the consumer has had time to process the suppressed cycle.
                tokio::time::sleep(Duration::from_millis(100)).await;
                suppressed_tx.send(()).unwrap();
                continue_rx.await.unwrap();
                // Seen/idle state after detaching is not a new completion.
                for status in [Status::Idle, Status::Working, Status::Done, Status::Idle] {
                    protocol::write_message(&mut events, &Message::State { pane: pane(status) })
                        .await
                        .unwrap();
                }
                let _ = connection.closed().await;
                break;
            }
            server.close().await;
        });
        let (tx, mut rx) = mpsc::channel(8);
        let watcher = tokio::spawn(watch_session(
            client.clone(),
            identity,
            state_dir,
            "host/work".into(),
            attachment,
            1,
            tx,
        ));
        suppressed_rx.await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "history or active-client notification leaked"
        );
        drop(active);
        continue_tx.send(()).unwrap();
        let notice = rx.recv().await.unwrap();
        assert_eq!(notice.target, "host/work");
        assert_eq!(notice.notice.title, "pi finished");
        assert!(
            timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err()
        );
        watcher.abort();
        let _ = watcher.await;
        service.await.unwrap();
        client.close().await;
    })
    .await
    .unwrap();
}
