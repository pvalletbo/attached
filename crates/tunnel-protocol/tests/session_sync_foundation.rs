use attached_tunnel_protocol::{
    CapabilitySecret, HerdrVersion, PROTOCOL_VERSION, TUNNEL_ALPN, write_auth_request,
    write_stream_header,
};
use tokio::io::AsyncReadExt;

#[test]
fn capability_secret_byte_bridge_round_trips_and_redacts() {
    let sentinel = core::array::from_fn(|index| (index as u8).wrapping_mul(7).wrapping_add(3));
    let secret = CapabilitySecret::from_bytes(sentinel);
    let exported = secret.to_bytes();

    assert_eq!(exported, sentinel);

    let mut independent = secret.to_bytes();
    independent[0] ^= 0xff;
    assert_ne!(independent, sentinel);
    assert_eq!(secret.to_bytes(), sentinel);

    assert_eq!(format!("{secret:?}"), "CapabilitySecret(REDACTED)");
    assert!(!format!("{secret:?}").contains(&format!("{sentinel:?}")));
}

#[tokio::test]
async fn interactive_tunnel_preambles_are_stable() {
    let (mut writer, mut reader) = tokio::io::duplex(128);
    write_auth_request(
        &mut writer,
        "build",
        &CapabilitySecret::from_bytes([0x66; 32]),
        Some(HerdrVersion::new(1, 2, 3)),
    )
    .await
    .unwrap();
    let mut auth = Vec::new();
    reader.read_to_end(&mut auth).await.unwrap();
    assert_eq!(
        auth,
        [
            0x48, 0x44, 0x52, 0x41, 0x03, 0x00, 0x05, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x04, 0x01, 0x01, 0x02, 0x03,
        ]
    );

    let (mut writer, mut reader) = tokio::io::duplex(16);
    write_stream_header(&mut writer).await.unwrap();
    let mut stream = [0; 5];
    reader.read_exact(&mut stream).await.unwrap();
    assert_eq!(stream, *b"HDRS\x03");

    assert_eq!(PROTOCOL_VERSION, 3);
    assert_eq!(TUNNEL_ALPN, b"herdr-tunnel/3");
}
