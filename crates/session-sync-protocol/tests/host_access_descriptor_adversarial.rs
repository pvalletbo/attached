use attached_session_sync_protocol::{
    AttachedVersion, Envelope, HostAccessDescriptor, HostAccessError, VerificationContext,
    canonical::MAX_CANONICAL_HOST_ACCESS_DESCRIPTOR_LEN,
    crypto::open_host_access_descriptor as open, decode_host_access_descriptor as decode,
    encode_host_access_descriptor as encode, seal_host_access_descriptor as seal_descriptor,
};
use attached_tunnel_protocol::CapabilitySecret;
use chrono::{DateTime, Utc};

const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";
fn timestamp(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}
fn descriptor(
    host: String,
    issued: DateTime<Utc>,
    expires: DateTime<Utc>,
    ticket: String,
    enabled: bool,
) -> Result<HostAccessDescriptor, HostAccessError> {
    HostAccessDescriptor::new(
        host,
        issued,
        expires,
        ticket,
        CapabilitySecret::from_bytes([6; 32]),
        AttachedVersion::new(4, 5, 6),
        enabled,
    )
}
fn fixture(enabled: bool) -> HostAccessDescriptor {
    descriptor(
        "office".into(),
        timestamp(1_700_000_000),
        timestamp(1_700_000_300),
        ENDPOINT.into(),
        enabled,
    )
    .unwrap()
}
fn context(now: i64) -> VerificationContext {
    VerificationContext {
        account_id: [0xa1; 16],
        record_id: [0xb2; 16],
        now: timestamp(now),
    }
}
fn seal(descriptor: &HostAccessDescriptor) -> Envelope {
    seal_descriptor(descriptor, &[8; 32], &[0xa1; 16], &[0xb2; 16]).unwrap()
}
fn position(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap()
}

#[test]
fn canonical_encoding_has_no_application_metadata_and_preserves_explicit_ssh_consent() {
    for enabled in [false, true] {
        let bytes = encode(&fixture(enabled)).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.ssh_enabled(), enabled);
        assert_eq!(decoded.host_label(), "office");
        assert_eq!(decoded.attached_version(), AttachedVersion::new(4, 5, 6));
        assert_eq!(decoded.attach_capability_bytes(), [6; 32]);
        assert_eq!(encode(&decoded).unwrap(), bytes);
    }
    let mut bytes = encode(&fixture(true)).unwrap();
    *bytes.last_mut().unwrap() = 1; // Consent must be a CBOR boolean, not truthy data.
    assert!(decode(&bytes).is_err());
}

#[test]
fn cbor_rejects_truncation_trailing_reordering_indefinite_and_nonshort_forms() {
    let bytes = encode(&fixture(true)).unwrap();
    for length in 0..bytes.len() {
        assert!(decode(&bytes[..length]).is_err(), "truncation {length}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing).err(), Some(HostAccessError::Malformed));
    for first in [0xa6, 0xa8, 0xbf] {
        let mut invalid = bytes.clone();
        invalid[0] = first;
        assert!(decode(&invalid).is_err());
    }
    let mut reordered = bytes.clone();
    reordered[1] = 0;
    assert_eq!(
        decode(&reordered).err(),
        Some(HostAccessError::NonCanonical)
    );
    let mut nonshort = bytes.clone();
    nonshort.splice(1..2, [0x18, 1]);
    assert_eq!(decode(&nonshort).err(), Some(HostAccessError::NonCanonical));
    let capability = position(&bytes, &[5, 0x58, 0x20]);
    let mut wrong_length = bytes.clone();
    wrong_length[capability + 2] = 31;
    assert!(decode(&wrong_length).is_err());
    assert_eq!(
        decode(&vec![0; MAX_CANONICAL_HOST_ACCESS_DESCRIPTOR_LEN + 1]).err(),
        Some(HostAccessError::Limit)
    );
}

#[test]
fn constructors_enforce_host_lifetime_and_endpoint_boundaries() {
    for label in ["a".to_owned(), "a".repeat(64)] {
        assert!(descriptor(label, timestamp(10), timestamp(70), ENDPOINT.into(), true).is_ok());
    }
    for label in [
        String::new(),
        "a".repeat(65),
        "-bad".into(),
        "bad label".into(),
        "bad\nlabel".into(),
        "bad/label".into(),
    ] {
        assert!(descriptor(label, timestamp(10), timestamp(70), ENDPOINT.into(), true).is_err());
    }
    for lifetime in [60, 900] {
        assert!(
            descriptor(
                "office".into(),
                timestamp(10),
                timestamp(10 + lifetime),
                ENDPOINT.into(),
                true
            )
            .is_ok()
        );
    }
    for (issued, expires) in [
        (timestamp(10), timestamp(10)),
        (timestamp(10), timestamp(69)),
        (timestamp(10), timestamp(911)),
        (timestamp(-1), timestamp(60)),
        (DateTime::from_timestamp(10, 1).unwrap(), timestamp(70)),
        (timestamp(10), DateTime::from_timestamp(70, 1).unwrap()),
    ] {
        assert!(descriptor("office".into(), issued, expires, ENDPOINT.into(), true).is_err());
    }
    for ticket in [
        String::new(),
        "not-a-ticket".into(),
        ENDPOINT.to_uppercase(),
        "x".repeat(4097),
        "é".into(),
    ] {
        assert!(descriptor("office".into(), timestamp(10), timestamp(70), ticket, true).is_err());
    }
}

#[test]
fn decoded_fields_revalidate_types_utf8_widths_and_numeric_ranges() {
    let bytes = encode(&fixture(true)).unwrap();
    for (offset, byte) in [
        (position(&bytes, b"office"), b'-'),
        (position(&bytes, ENDPOINT.as_bytes()), 0xff),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset] = byte;
        assert!(decode(&invalid).is_err());
    }
    let version = position(&bytes, &[6, 0x83, 4, 5, 6]);
    let mut oversized = bytes.clone();
    oversized.splice(version + 2..version + 3, [0x1a, 0, 1, 0, 0]);
    assert_eq!(
        decode(&oversized).err(),
        Some(HostAccessError::InvalidField)
    );
    let mut wrong_array = bytes.clone();
    wrong_array[version + 1] = 0x82;
    assert!(decode(&wrong_array).is_err());
    let issued = position(&bytes, &[2, 0x1a, 0x65, 0x53, 0xf1, 0]);
    let mut oversized_time = bytes;
    oversized_time.splice(
        issued + 1..issued + 6,
        [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
    assert_eq!(
        decode(&oversized_time).err(),
        Some(HostAccessError::InvalidField)
    );
}

#[test]
fn aead_context_key_nonce_ciphertext_and_expiration_fail_closed() {
    let envelope = seal(&fixture(true));
    let valid = context(1_700_000_100);
    assert!(open(&envelope, &[8; 32], &valid).is_ok());
    for wrong in [
        VerificationContext {
            account_id: [0xa2; 16],
            ..valid
        },
        VerificationContext {
            record_id: [0xb3; 16],
            ..valid
        },
    ] {
        assert_eq!(
            open(&envelope, &[8; 32], &wrong).err(),
            Some(HostAccessError::Decryption)
        );
    }
    assert_eq!(
        open(&envelope, &[9; 32], &valid).err(),
        Some(HostAccessError::Decryption)
    );
    for now in [1_700_000_300, 1_699_999_939] {
        assert_eq!(
            open(&envelope, &[8; 32], &context(now)).err(),
            Some(HostAccessError::Expired)
        );
    }
    assert!(
        open(&envelope, &[8; 32], &context(1_699_999_940)).is_ok(),
        "60 seconds of future skew is allowed"
    );
    let mut ciphertext = envelope.ciphertext().to_vec();
    ciphertext[0] ^= 1;
    assert_eq!(
        open(
            &Envelope::new(*envelope.nonce(), ciphertext).unwrap(),
            &[8; 32],
            &valid
        )
        .err(),
        Some(HostAccessError::Decryption)
    );
    let mut nonce = *envelope.nonce();
    nonce[0] ^= 1;
    assert_eq!(
        open(
            &Envelope::new(nonce, envelope.ciphertext().to_vec()).unwrap(),
            &[8; 32],
            &valid
        )
        .err(),
        Some(HostAccessError::Decryption)
    );
}

#[test]
fn plaintext_omits_external_context_and_debug_output_redacts_secrets() {
    let descriptor = fixture(true);
    let bytes = encode(&descriptor).unwrap();
    for external in [[0xa1; 16], [0xb2; 16]] {
        assert!(!bytes.windows(16).any(|window| window == external));
    }
    let debug = format!("{descriptor:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(ENDPOINT));
    assert!(format!("{:?}", seal(&descriptor)).contains("REDACTED"));
}
