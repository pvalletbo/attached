use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn host_update_requests_bind_capability_operation_and_observed_version() {
    let secret = CapabilitySecret::from_bytes([7; 32]);
    let operation = UpdateOperationId::from_bytes([8; 16]);
    let version = AttachedVersion::new(1, 2, 3);
    let mut bytes = Vec::new();
    write_attached_update_start_request(&mut bytes, &secret)
        .await
        .unwrap();
    assert_eq!(
        bytes.len(),
        38,
        "host-wide update must not encode a session name"
    );
    assert_eq!(
        read_attached_update_request(&mut bytes.as_slice(), &secret)
            .await
            .unwrap(),
        AttachedUpdateRequest::Start
    );
    bytes.clear();
    write_attached_update_confirm_request(&mut bytes, &secret, operation, version)
        .await
        .unwrap();
    assert_eq!(
        read_attached_update_request(&mut bytes.as_slice(), &secret)
            .await
            .unwrap(),
        AttachedUpdateRequest::Confirm {
            operation_id: operation,
            observed_version: version
        }
    );
    assert!(
        read_attached_update_request(
            &mut bytes.as_slice(),
            &CapabilitySecret::from_bytes([9; 32])
        )
        .await
        .is_err()
    );
    for length in 0..bytes.len() {
        assert!(
            read_attached_update_request(&mut &bytes[..length], &secret)
                .await
                .is_err(),
            "accepted truncation {length}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        read_attached_update_request(&mut trailing.as_slice(), &secret)
            .await
            .is_err()
    );
    for (offset, byte) in [(0, b'X'), (4, 1), (5, 9)] {
        let mut invalid = bytes.clone();
        invalid[offset] = byte;
        assert!(
            read_attached_update_request(&mut invalid.as_slice(), &secret)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn update_responses_roundtrip_and_reject_malformed_or_unbounded_frames() {
    let version = AttachedVersion::new(2, 3, 4);
    for response in [
        AttachedUpdateResponse::Restarting {
            operation_id: UpdateOperationId::from_bytes([8; 16]),
            version,
            reconnect_timeout_secs: 30,
        },
        AttachedUpdateResponse::Committed(version),
        AttachedUpdateResponse::Current(version),
        AttachedUpdateResponse::Failed("bounded error".into()),
        AttachedUpdateResponse::Busy,
        AttachedUpdateResponse::Waiting,
    ] {
        let mut bytes = Vec::new();
        // Responses are consumed by the writer; keep the expected value via Debug.
        let expected = format!("{response:?}");
        write_attached_update_response(&mut bytes, response)
            .await
            .unwrap();
        assert_eq!(
            format!(
                "{:?}",
                read_attached_update_response(&mut bytes.as_slice())
                    .await
                    .unwrap()
            ),
            expected
        );
        for length in 0..bytes.len() {
            assert!(
                read_attached_update_response(&mut &bytes[..length])
                    .await
                    .is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            read_attached_update_response(&mut trailing.as_slice())
                .await
                .is_err()
        );
        for (offset, byte) in [(0, b'X'), (4, 1), (5, 99)] {
            let mut invalid = bytes.clone();
            invalid[offset] = byte;
            assert!(
                read_attached_update_response(&mut invalid.as_slice())
                    .await
                    .is_err()
            );
        }
    }
    assert!(
        write_attached_update_response(
            &mut Vec::new(),
            AttachedUpdateResponse::Failed("x".repeat(MAX_ATTACHED_UPDATE_MESSAGE_LEN + 1))
        )
        .await
        .is_err()
    );
    let mut oversized = Vec::from(ATTACHED_UPDATE_MAGIC);
    oversized.extend_from_slice(&[ATTACHED_UPDATE_PROTOCOL_VERSION, 3]);
    oversized.extend_from_slice(&513_u16.to_be_bytes());
    assert!(
        read_attached_update_response(&mut oversized.as_slice())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn fragmented_update_frames_work_over_streams() {
    let secret = CapabilitySecret::from_bytes([7; 32]);
    let mut encoded = Vec::new();
    write_attached_update_start_request(&mut encoded, &secret)
        .await
        .unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let send = async {
        for byte in encoded {
            writer.write_u8(byte).await.unwrap();
        }
        writer.shutdown().await.unwrap();
    };
    let receive = async {
        assert_eq!(
            read_attached_update_request(&mut reader, &secret)
                .await
                .unwrap(),
            AttachedUpdateRequest::Start
        );
        assert_eq!(reader.read(&mut [0]).await.unwrap(), 0);
    };
    tokio::join!(send, receive);
}

#[test]
fn only_ssh_and_attached_update_protocols_are_exposed_and_secrets_are_redacted() {
    assert_eq!(SSH_ALPN, b"attached-ssh/1");
    assert_eq!(ATTACHED_UPDATE_ALPN, b"attached-update/2");
    assert_eq!(
        format!("{:?}", CapabilitySecret::from_bytes([7; 32])),
        "CapabilitySecret(REDACTED)"
    );
    assert!(AttachedVersion::new(1, 2, 10) > AttachedVersion::new(1, 2, 9));
}
