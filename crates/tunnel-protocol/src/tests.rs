use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TEST_SERVER_VERSION: HerdrVersion = HerdrVersion::new(1, 2, 3);

async fn authenticate_fixed_server<R, W>(
    reader: &mut R,
    writer: &mut W,
    expected_session: &str,
    expected_secret: &CapabilitySecret,
    server_herdr_version: HerdrVersion,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let expected_session = expected_session.to_owned();
    authenticate_server(
        reader,
        writer,
        expected_secret,
        server_herdr_version,
        move |session| async move {
            ensure!(session == expected_session, "authentication denied");
            Ok(())
        },
        || Ok(()),
    )
    .await
    .map(|_| ())
}

#[test]
fn native_compatibility_requires_exact_version_equality() {
    let local = HerdrVersion::new(1, 2, 3);
    assert!(ensure_herdr_compatible(local, local).is_ok());
    for remote in [
        HerdrVersion::new(1, 2, 4),
        HerdrVersion::new(1, 3, 3),
        HerdrVersion::new(2, 2, 3),
    ] {
        assert!(ensure_herdr_compatible(local, remote).is_err());
    }
}

#[tokio::test]
async fn remote_upgrade_frames_bind_session_capability_and_exact_version() {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let secret = CapabilitySecret([7; 32]);
        let (mut client, mut server) = tokio::io::duplex(512);
        let writing =
            write_upgrade_request(&mut client, "work", &secret, HerdrVersion::new(1, 2, 3));
        let reading = read_upgrade_request(&mut server, &secret);
        let ((), request) = tokio::try_join!(writing, reading).unwrap();
        assert_eq!(request.session, "work");
        assert_eq!(request.requested_version, HerdrVersion::new(1, 2, 3));

        let (mut server, mut client) = tokio::io::duplex(128);
        let writing = write_upgrade_response(
            &mut server,
            UpgradeResponse::Updated(HerdrVersion::new(1, 2, 3)),
        );
        let reading = read_upgrade_response(&mut client);
        let ((), response) = tokio::try_join!(writing, reading).unwrap();
        assert_eq!(
            response,
            UpgradeResponse::Updated(HerdrVersion::new(1, 2, 3))
        );
    })
    .await
    .expect("remote-upgrade frame scenario timed out");
}

#[tokio::test]
async fn upgrade_requests_reject_wrong_capability_and_bounded_malformed_frames() {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let expected = CapabilitySecret([7; 32]);
        let wrong = CapabilitySecret([8; 32]);
        let version = postcard::to_stdvec(&Some(HerdrVersion::new(1, 2, 3))).unwrap();
        let mut valid = Vec::new();
        valid.extend_from_slice(&UPGRADE_MAGIC);
        valid.push(1);
        valid.extend_from_slice(&4_u16.to_be_bytes());
        valid.extend_from_slice(b"work");
        valid.extend_from_slice(&wrong.0);
        valid.push(version.len() as u8);
        valid.extend_from_slice(&version);

        let mut wrong_reader = valid.as_slice();
        assert!(
            read_upgrade_request(&mut wrong_reader, &expected)
                .await
                .unwrap_err()
                .to_string()
                .contains("denied")
        );

        let mut oversized = Vec::new();
        oversized.extend_from_slice(&UPGRADE_MAGIC);
        oversized.push(1);
        oversized.extend_from_slice(&((MAX_SESSION_NAME_LEN + 1) as u16).to_be_bytes());
        let mut oversized_reader = oversized.as_slice();
        assert!(
            read_upgrade_request(&mut oversized_reader, &expected)
                .await
                .unwrap_err()
                .to_string()
                .contains("too long")
        );

        for length in 0..valid.len() {
            let mut truncated = &valid[..length];
            assert!(
                read_upgrade_request(&mut truncated, &wrong).await.is_err(),
                "accepted request truncated at byte {length}"
            );
        }

        let mut trailing = valid.clone();
        trailing.push(0xff);
        let mut trailing_reader = trailing.as_slice();
        assert!(
            read_upgrade_request(&mut trailing_reader, &wrong)
                .await
                .is_err()
        );
    })
    .await
    .expect("upgrade-request rejection scenario timed out");
}

#[tokio::test]
async fn upgrade_responses_reject_oversized_truncated_and_trailing_frames() {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&UPGRADE_MAGIC);
        oversized.extend_from_slice(&[1, 1]);
        oversized.extend_from_slice(&((MAX_UPGRADE_MESSAGE_LEN + 1) as u16).to_be_bytes());
        let mut oversized_reader = oversized.as_slice();
        assert!(
            read_upgrade_response(&mut oversized_reader)
                .await
                .unwrap_err()
                .to_string()
                .contains("too long")
        );

        let valid = [UPGRADE_MAGIC.as_slice(), &[1, 2]].concat();
        for length in 0..valid.len() {
            let mut truncated = &valid[..length];
            assert!(
                read_upgrade_response(&mut truncated).await.is_err(),
                "accepted response truncated at byte {length}"
            );
        }

        let mut trailing = valid;
        trailing.push(0xff);
        let mut trailing_reader = trailing.as_slice();
        assert!(read_upgrade_response(&mut trailing_reader).await.is_err());
    })
    .await
    .expect("upgrade-response rejection scenario timed out");
}

#[test]
fn all_tunnel_protocol_constants_remain_unchanged() {
    assert_eq!(MAX_SESSION_NAME_LEN, 255);
    assert_eq!(AUTH_OK, 0);
    assert_eq!(AUTH_DENIED, 1);
    assert_eq!(AUTH_INCOMPATIBLE_HERDR, 2);
    assert_eq!(AUTH_UNSUPPORTED_TUNNEL, 3);
    assert_eq!(AUTH_CAPACITY_EXHAUSTED, 4);
    assert_eq!(MAX_VERSION_WIRE_LEN, 16);
    assert_eq!(PROTOCOL_VERSION, 3);
    assert_eq!(TUNNEL_ALPN, b"herdr-tunnel/3");
}

#[tokio::test]
async fn interactive_stream_header_preserves_following_payload() {
    let (mut writer, mut reader) = tokio::io::duplex(64);
    let writing = async {
        write_stream_header(&mut writer).await?;
        writer.write_all(b"payload").await?;
        Result::<()>::Ok(())
    };
    let reading = async {
        read_stream_header(&mut reader).await?;
        let mut payload = [0; 7];
        reader.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"payload");
        Result::<()>::Ok(())
    };
    tokio::try_join!(writing, reading).unwrap();
}

#[tokio::test]
async fn rejects_truncated_and_wrong_version_stream_headers() {
    let (mut writer, mut reader) = tokio::io::duplex(16);
    writer.write_all(&STREAM_MAGIC).await.unwrap();
    writer.shutdown().await.unwrap();
    assert!(read_stream_header(&mut reader).await.is_err());

    let (mut writer, mut reader) = tokio::io::duplex(16);
    writer
        .write_all(&[
            STREAM_MAGIC[0],
            STREAM_MAGIC[1],
            STREAM_MAGIC[2],
            STREAM_MAGIC[3],
            PROTOCOL_VERSION + 1,
        ])
        .await
        .unwrap();
    assert!(read_stream_header(&mut reader).await.is_err());
}

#[tokio::test]
async fn authenticates_only_matching_session_and_secret() {
    let expected = CapabilitySecret([1; 32]);
    let (client, server) = tokio::io::duplex(512);
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let client = async {
        write_auth_request(
            &mut client_writer,
            "default",
            &expected,
            Some(HerdrVersion::new(1, 2, 3)),
        )
        .await?;
        read_auth_response(&mut client_reader, Some(HerdrVersion::new(1, 2, 3))).await
    };
    let server = authenticate_fixed_server(
        &mut server_reader,
        &mut server_writer,
        "default",
        &expected,
        TEST_SERVER_VERSION,
    );
    tokio::try_join!(client, server).unwrap();
}

#[tokio::test]
async fn host_authentication_returns_the_requested_session() {
    let secret = CapabilitySecret([1; 32]);
    let (client, server) = tokio::io::duplex(512);
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let client = async {
        write_auth_request(&mut client_writer, "work", &secret, None).await?;
        read_auth_response(&mut client_reader, None).await
    };
    let server = authenticate_server(
        &mut server_reader,
        &mut server_writer,
        &secret,
        TEST_SERVER_VERSION,
        |session| async move { Ok(session) },
        || Ok(7),
    );
    let ((), (session, admission)) = tokio::try_join!(client, server).unwrap();
    assert_eq!(session, "work");
    assert_eq!(admission, 7);
}

#[tokio::test]
async fn host_resolution_failure_is_rejected_before_authentication_succeeds() {
    let secret = CapabilitySecret([1; 32]);
    let (client, server) = tokio::io::duplex(512);
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let client = async {
        write_auth_request(&mut client_writer, "stopped", &secret, None).await?;
        read_auth_response(&mut client_reader, None).await
    };
    let server = authenticate_server(
        &mut server_reader,
        &mut server_writer,
        &secret,
        TEST_SERVER_VERSION,
        |_| async { Result::<()>::Err(anyhow::anyhow!("session stopped")) },
        || Ok(()),
    );
    let (client_result, server_result) = tokio::join!(client, server);
    assert!(client_result.unwrap_err().to_string().contains("rejected"));
    assert!(
        server_result
            .unwrap_err()
            .to_string()
            .contains("requested session is unavailable")
    );
}

#[tokio::test]
async fn rejects_wrong_capability_without_exposing_it() {
    let expected = CapabilitySecret([1; 32]);
    let supplied = CapabilitySecret([2; 32]);
    let (client, server) = tokio::io::duplex(512);
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let client = async {
        write_auth_request(&mut client_writer, "default", &supplied, None)
            .await
            .unwrap();
        read_auth_response(&mut client_reader, None).await
    };
    let server = authenticate_fixed_server(
        &mut server_reader,
        &mut server_writer,
        "default",
        &expected,
        TEST_SERVER_VERSION,
    );
    let (client_result, server_result) = tokio::join!(client, server);
    assert!(client_result.unwrap_err().to_string().contains("rejected"));
    assert!(server_result.unwrap_err().to_string().contains("denied"));
}

#[tokio::test]
async fn returns_explicit_response_for_unsupported_auth_version() {
    let secret = CapabilitySecret([1; 32]);
    let (client, server) = tokio::io::duplex(128);
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let client = async {
        client_writer.write_all(&AUTH_MAGIC).await.unwrap();
        client_writer.write_u8(PROTOCOL_VERSION - 1).await.unwrap();
        client_writer.shutdown().await.unwrap();
        read_auth_response(&mut client_reader, None).await
    };
    let server = authenticate_fixed_server(
        &mut server_reader,
        &mut server_writer,
        "default",
        &secret,
        TEST_SERVER_VERSION,
    );
    let (client_result, server_result) = tokio::join!(client, server);
    assert!(
        client_result
            .unwrap_err()
            .to_string()
            .contains("unsupported")
    );
    assert!(
        server_result
            .unwrap_err()
            .to_string()
            .contains("unsupported")
    );
}

#[tokio::test]
async fn explicit_incompatibility_response_is_never_accepted() {
    let (mut writer, mut reader) = tokio::io::duplex(32);
    write_auth_response(
        &mut writer,
        AUTH_INCOMPATIBLE_HERDR,
        HerdrVersion::new(1, 2, 9),
    )
    .await
    .unwrap();
    let error = read_auth_response(&mut reader, Some(HerdrVersion::new(1, 2, 3)))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("rejected incompatible"), "{error}");
}

#[tokio::test]
async fn rejects_incompatible_herdr_versions_during_authentication() {
    let secret = CapabilitySecret([1; 32]);
    let (client, server) = tokio::io::duplex(512);
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);

    let client = async {
        let local = HerdrVersion::new(1, 2, 3);
        write_auth_request(&mut client_writer, "default", &secret, Some(local))
            .await
            .unwrap();
        read_auth_response(&mut client_reader, Some(local)).await
    };
    let server = authenticate_fixed_server(
        &mut server_reader,
        &mut server_writer,
        "default",
        &secret,
        HerdrVersion::new(1, 2, 4),
    );
    let (client_result, server_result) = tokio::join!(client, server);
    for error in [client_result.unwrap_err(), server_result.unwrap_err()] {
        let error = error.to_string();
        assert!(error.contains("1.2.3"), "{error}");
        assert!(error.contains("1.2.4"), "{error}");
    }
}

#[tokio::test]
async fn rejects_malformed_authentication_prefixes() {
    let mut cases = vec![Vec::new()];
    for length in 1..AUTH_MAGIC.len() {
        cases.push(AUTH_MAGIC[..length].to_vec());
    }
    cases.extend([
        b"NOPE".to_vec(),
        [AUTH_MAGIC.as_slice(), &[PROTOCOL_VERSION + 1]].concat(),
        [AUTH_MAGIC.as_slice(), &[PROTOCOL_VERSION, 0]].concat(),
        [AUTH_MAGIC.as_slice(), &[PROTOCOL_VERSION, 1, 0, b'x']].concat(),
    ]);

    for bytes in cases {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&bytes).await.unwrap();
        writer.shutdown().await.unwrap();
        let result = async {
            let version = read_auth_preamble(&mut reader).await?;
            ensure!(
                version == PROTOCOL_VERSION,
                "unsupported tunnel protocol version {version}"
            );
            read_auth_request_body(&mut reader).await
        }
        .await;
        assert!(
            result.is_err(),
            "accepted malformed authentication frame {bytes:?}"
        );
    }
}
