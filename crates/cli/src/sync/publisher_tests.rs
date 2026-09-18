use super::*;
use attached_session_sync_protocol::crypto::{
    Envelope, VerificationContext, open_host_access_descriptor,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn publication_advertises_ssh_by_default_and_tracks_account_availability() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let root = crate::test_support::canonical_tempdir();
        let path = root.path().join("publisher");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let creator = root.path().join("creator");
        state::test_support::create_account(&creator, &format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let bundle = state::export_account(&creator, ApiKeyScope::Publish).unwrap();
        state::import_account(&path, bundle.as_bytes()).unwrap();
        let account = state::load_account(&path, ApiKeyScope::Publish).unwrap();
        let identity = iroh::SecretKey::generate().public();
        let record_id = derive_record_id(account.account_id().as_bytes(), identity.as_bytes());
        let response_started = std::cell::Cell::new(None);
        let server = async {
            for (revision, enabled) in [(1, true), (2, false), (3, true)] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let (header_end, length) = loop {
                    let mut chunk = [0; 4096];
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0 && bytes.len() < 16384);
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        assert!(headers.starts_with(&format!("PUT /v1/accounts/{}/records/{record_id} HTTP/1.1", account.account_id())));
                        let length = headers.lines().filter_map(|line| line.split_once(':'))
                            .find(|(key, _)| key.eq_ignore_ascii_case("content-length")).unwrap().1.trim().parse::<usize>().unwrap();
                        break (end + 4, length);
                    }
                };
                while bytes.len() < header_end + length {
                    let mut chunk = [0; 4096];
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0 && bytes.len() < 16384);
                    bytes.extend_from_slice(&chunk[..count]);
                }
                let wire = &bytes[header_end..header_end + length];
                assert!(!wire.windows(b"office".len()).any(|window| window == b"office"));
                let envelope = ApiEnvelope::parse_json(wire).unwrap();
                let descriptor = open_host_access_descriptor(
                    &Envelope::new(envelope.nonce, envelope.ciphertext).unwrap(), account.account_root_key(),
                    &VerificationContext { account_id: *account.account_id().as_bytes(), record_id: *record_id.as_bytes(), now: super::super::utc_now_seconds() },
                ).unwrap();
                let descriptor = descriptor.descriptor();
                assert_eq!(descriptor.host_label(), "office");
                assert_eq!(descriptor.endpoint_identity(), *identity.as_bytes());
                assert_eq!(descriptor.ssh_enabled(), enabled);
                assert_eq!(descriptor.attach_capability_bytes(), [9; 32]);
                assert_eq!((descriptor.expires_at() - descriptor.issued_at()).num_seconds(), 90);
                response_started.set(Some(Instant::now()));
                socket.write_all(format!("HTTP/1.1 204 No Content\r\nETag: \"{revision}\"\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        };
        let client = async {
            let mut publisher = Publisher::load(&path, *identity.as_bytes()).unwrap();
            let endpoint = EndpointAddr::new(identity);
            let key = CapabilitySecret::from_bytes([9; 32]);
            assert_eq!(publisher.publish_snapshot("office", endpoint.clone(), &key).await.unwrap(), PublishOutcome::Published { revision: 1 });
            assert!(publisher.next_refresh_at.unwrap() <= response_started.get().unwrap() + REPUBLISH_INTERVAL,
                "HTTP response latency postponed the next publication deadline");
            assert_eq!(publisher.publish_snapshot("office", endpoint.clone(), &key).await.unwrap(), PublishOutcome::Unchanged);
            assert!(!path.join("ssh-access.json").exists());
            std::fs::remove_file(path.join("sync-account.bundle")).unwrap();
            assert_eq!(publisher.publish_snapshot("office", endpoint.clone(), &key).await.unwrap(), PublishOutcome::Published { revision: 2 });
            state::import_account(&path, bundle.as_bytes()).unwrap();
            assert_eq!(publisher.publish_snapshot("office", endpoint, &key).await.unwrap(), PublishOutcome::Published { revision: 3 });
        };
        tokio::join!(server, client);
    }).await.expect("host publication timed out");
}
