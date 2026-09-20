use super::*;
use attached_session_sync_protocol::{
    account::{
        AccountBundle, AccountId, AccountRootKey, ApiToken, ConsumerIdentitySecret,
        ScopedAccountBundle, ServiceOrigin,
    },
    api::{Envelope, LiveRecordIndex, LiveRecordIndexEntry},
    canonical::AttachedVersion,
    crypto::seal_host_access_descriptor,
};
use attached_tunnel_protocol::CapabilitySecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn bundle(origin: &str) -> String {
    AccountBundle::Scoped(
        ScopedAccountBundle::from_download_parts(
            ServiceOrigin::parse(origin).unwrap(),
            AccountId::parse("01940000-0000-7000-8000-000000000001").unwrap(),
            ApiToken::from_bytes([3; 32]),
            AccountRootKey::from_bytes([4; 32]),
            ConsumerIdentitySecret::from_bytes([5; 32]),
        )
        .unwrap(),
    )
    .encode()
}

fn public_key() -> String {
    ssh_key::PublicKey::new(
        ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            *iroh::SecretKey::generate().public().as_bytes(),
        )),
        "",
    )
    .to_openssh()
    .unwrap()
}

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::N0)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .relay_mode(iroh::RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![attached_tunnel_protocol::SSH_ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

fn descriptor(publisher: &Endpoint) -> HostAccessDescriptor {
    let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    HostAccessDescriptor::new(
        "office".into(),
        now,
        now + chrono::Duration::minutes(5),
        EndpointTicket::new(publisher.addr()).to_string(),
        CapabilitySecret::from_bytes([6; 32]),
        AttachedVersion::new(0, 3, 4),
        true,
    )
    .unwrap()
}

#[test]
fn download_import_validates_and_never_exposes_credentials_in_errors() {
    let client = AttachedClient::new(format!(" \n{}\n", bundle("https://sync.example"))).unwrap();
    assert_eq!(client.account_id(), "01940000-0000-7000-8000-000000000001");
    client.close();
    assert!(matches!(
        client.hosts(AttachedCancellation::new()),
        Err(MobileError::Closed)
    ));
    assert!(matches!(
        AttachedClient::new("secret-looking-invalid-data".into()),
        Err(MobileError::InvalidDownloadBundle)
    ));
    let account = AccountBundle::parse(bundle("https://sync.example").as_bytes()).unwrap();
    let AccountBundle::Scoped(account) = account else {
        unreachable!()
    };
    assert!(account.consumer_identity_secret().is_some());
    let cancel = AttachedCancellation::new();
    cancel.cancel();
    let client = AttachedClient::new(bundle("https://sync.example")).unwrap();
    assert!(matches!(client.hosts(cancel), Err(MobileError::Closed)));
}

#[tokio::test]
async fn encrypted_discovery_and_mobile_socket_roundtrip() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let publisher = endpoint().await;
        let desc = descriptor(&publisher);
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", http.local_addr().unwrap());
        let encoded = bundle(&origin);
        let account = discovery::Account::parse(encoded.clone()).unwrap();
        let id = attached_session_sync_protocol::account::RecordId::from_bytes([7; 16]);
        let (nonce, ciphertext) = seal_host_access_descriptor(&desc, &account.root, account.id.as_bytes(), id.as_bytes()).unwrap().into_parts();
        let record = serde_json::to_vec(&Envelope::new(nonce, ciphertext).unwrap()).unwrap();
        let index = serde_json::to_vec(&LiveRecordIndex::new(vec![LiveRecordIndexEntry { record_id: id, revision: 1 }]).unwrap()).unwrap();
        let http_task = tokio::spawn(async move {
            for _ in 0..4 {
                let (mut socket, _) = http.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                    assert!(request.len() < 8192);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.to_ascii_lowercase().contains("authorization: bearer "));
                let response = if request.lines().next().unwrap().contains(&format!("/records/{id} ")) { &record } else { &index };
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).as_bytes()).await.unwrap();
                socket.write_all(response).await.unwrap();
            }
        });
        let public = public_key();
        let expected = public.clone();
        let host = public_key();
        let expected_host = host.clone();
        let server = publisher.clone();
        let echo_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            assert_eq!(connection.remote_id(), iroh::SecretKey::from_bytes(&[5;32]).public());
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let request: Request = read_frame(&mut receive).await.unwrap();
            assert_eq!(request.public_key, expected);
            assert_eq!(request.capability, [6;32]);
            write_frame(&mut send, &Response { username: "publisher".into(), host_key: host }).await.unwrap();
            tokio::io::copy(&mut receive, &mut send).await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
            connection.closed().await;
        });
        let client = AttachedClient::new(encoded).unwrap();
        let copy = client.clone();
        let hosts = tokio::task::spawn_blocking(move || copy.hosts(AttachedCancellation::new())).await.unwrap().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].label, "office");
        let copy = client.clone();
        let tunnel = tokio::task::spawn_blocking(move || copy.connect(hosts[0].endpoint_id.clone(), public, AttachedCancellation::new())).await.unwrap().unwrap();
        assert_eq!(tunnel.username(), "publisher");
        assert_eq!(tunnel.host_key(), expected_host);
        // Exercise the owned socket without introducing unsafe raw-fd recovery
        // into the tests; take_socket must refuse any subsequent transfer.
        let socket = tunnel.socket.lock().unwrap().take().unwrap();
        assert!(matches!(tunnel.take_socket(), Err(MobileError::Closed)));
        let mut socket = UnixStream::from_std(socket).unwrap();
        let payload = vec![42; 512 * 1024];
        let (mut read, mut write) = socket.split();
        let upload = async { write.write_all(&payload).await.unwrap(); write.shutdown().await.unwrap(); };
        let download = async { let mut output = Vec::new(); read.read_to_end(&mut output).await.unwrap(); output };
        let (_, output) = tokio::join!(upload, download);
        assert_eq!(payload, output);
        tunnel.close();
        client.close();
        echo_task.await.unwrap();
        http_task.await.unwrap();
        publisher.close().await;
    }).await.unwrap();
}

#[tokio::test]
async fn expired_descriptors_are_rejected_before_network_dial() {
    let publisher = endpoint().await;
    let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let expired = HostAccessDescriptor::new(
        "office".into(),
        now - chrono::Duration::minutes(5),
        now,
        EndpointTicket::new(publisher.addr()).to_string(),
        CapabilitySecret::from_bytes([6; 32]),
        AttachedVersion::new(0, 3, 4),
        true,
    )
    .unwrap();
    assert!(
        open(
            &publisher,
            &expired,
            &public_key(),
            CancellationToken::new()
        )
        .await
        .is_err()
    );
    publisher.close().await;
}
