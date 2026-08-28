use attached_session_sync_protocol::{
    AttachedVersion, Envelope, HerdrVersion, SessionAccessDescriptor, SessionAccessError,
    VerificationContext, decode_session_access_descriptor, encode_session_access_descriptor,
    seal_session_access_descriptor,
};
use attached_session_sync_protocol::{
    canonical::MAX_CANONICAL_SESSION_ACCESS_DESCRIPTOR_LEN,
    crypto::{
        open_session_access_descriptor_cursorless,
        open_session_access_descriptor_cursorless_for_native_upgrade,
    },
    limits::{MAX_SESSION_NAME_BYTES, MAX_SESSIONS},
};
use attached_tunnel_protocol::CapabilitySecret;
use chrono::{DateTime, Utc};

const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";
const ENDPOINT_ID: [u8; 32] = [
    0xae, 0x58, 0xff, 0x88, 0x33, 0x24, 0x1a, 0xc8, 0x2d, 0x6f, 0xf7, 0x61, 0x10, 0x46, 0xed, 0x67,
    0xb5, 0x07, 0x2d, 0x14, 0x2c, 0x58, 0x8d, 0x00, 0x63, 0xe9, 0x42, 0xd9, 0xa7, 0x55, 0x02, 0xb6,
];

fn timestamp(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).expect("fixture timestamp")
}

fn fixture() -> SessionAccessDescriptor {
    fixture_with(
        "office".into(),
        1_700_000_000,
        1_700_000_300,
        ENDPOINT.into(),
        HerdrVersion::new(1, 2, 3),
        vec!["alpha".into(), "build".into()],
    )
}

fn fixture_with(
    host_label: String,
    issued_at: i64,
    expires_at: i64,
    endpoint_ticket: String,
    version: HerdrVersion,
    sessions: Vec<String>,
) -> SessionAccessDescriptor {
    SessionAccessDescriptor::new(
        host_label,
        timestamp(issued_at),
        timestamp(expires_at),
        endpoint_ticket,
        CapabilitySecret::from_bytes([6; 32]),
        AttachedVersion::new(0, 2, 0),
        version,
        sessions,
    )
    .expect("valid fixture")
}

fn context(now: i64, version: HerdrVersion) -> VerificationContext {
    VerificationContext {
        account_id: [0xa1; 16],
        record_id: [0xb2; 16],
        now: timestamp(now),
        local_version: version,
    }
}

fn seal(descriptor: &SessionAccessDescriptor) -> Envelope {
    seal_session_access_descriptor(descriptor, &[8; 32], &[0xa1; 16], &[0xb2; 16])
        .expect("seal fixture")
}

fn position(input: &[u8], needle: &[u8]) -> usize {
    input
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture marker")
}

#[test]
fn canonical_cbor_rejects_truncation_trailing_reordering_and_nonshort_forms() {
    let canonical = encode_session_access_descriptor(&fixture()).expect("canonical");
    for length in 0..canonical.len() {
        assert!(
            decode_session_access_descriptor(&canonical[..length]).is_err(),
            "accepted truncation at {length}"
        );
    }

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        decode_session_access_descriptor(&trailing).err(),
        Some(SessionAccessError::Malformed)
    );

    let mut wrong_count = canonical.clone();
    wrong_count[0] = 0xa6;
    assert!(decode_session_access_descriptor(&wrong_count).is_err());
    let mut indefinite = canonical.clone();
    indefinite[0] = 0xbf;
    assert!(decode_session_access_descriptor(&indefinite).is_err());
    let mut wrong_first_key = canonical.clone();
    wrong_first_key[1] = 0;
    assert_eq!(
        decode_session_access_descriptor(&wrong_first_key).err(),
        Some(SessionAccessError::NonCanonical)
    );

    let mut nonshort_key = canonical.clone();
    nonshort_key.splice(1..2, [0x18, 0x01]);
    assert_eq!(
        decode_session_access_descriptor(&nonshort_key).err(),
        Some(SessionAccessError::NonCanonical)
    );

    let capability = position(&canonical, &[0x05, 0x58, 0x20]);
    let mut wrong_capability_length = canonical.clone();
    wrong_capability_length[capability + 2] = 0x1f;
    assert!(decode_session_access_descriptor(&wrong_capability_length).is_err());

    assert_eq!(
        decode_session_access_descriptor(&vec![0; MAX_CANONICAL_SESSION_ACCESS_DESCRIPTOR_LEN + 1])
            .err(),
        Some(SessionAccessError::Limit)
    );
}

#[test]
fn constructor_enforces_host_clock_endpoint_and_session_boundaries() {
    for label in ["a".to_owned(), "a".repeat(64)] {
        assert_eq!(
            fixture_with(
                label,
                10,
                70,
                ENDPOINT.into(),
                HerdrVersion::new(1, 2, 3),
                vec![]
            )
            .endpoint_identity(),
            ENDPOINT_ID
        );
    }
    for label in [
        String::new(),
        "a".repeat(65),
        "-bad".into(),
        "bad label".into(),
    ] {
        assert!(
            SessionAccessDescriptor::new(
                label,
                timestamp(10),
                timestamp(70),
                ENDPOINT.into(),
                CapabilitySecret::from_bytes([6; 32]),
                AttachedVersion::new(0, 2, 0),
                HerdrVersion::new(1, 2, 3),
                vec![],
            )
            .is_err()
        );
    }

    for lifetime in [60, 900] {
        assert!(
            SessionAccessDescriptor::new(
                "office".into(),
                timestamp(10),
                timestamp(10 + lifetime),
                ENDPOINT.into(),
                CapabilitySecret::from_bytes([6; 32]),
                AttachedVersion::new(0, 2, 0),
                HerdrVersion::new(1, 2, 3),
                vec![],
            )
            .is_ok()
        );
    }
    for (issued, expires) in [
        (timestamp(10), timestamp(10)),
        (timestamp(10), timestamp(69)),
        (timestamp(10), timestamp(911)),
        (timestamp(-1), timestamp(60)),
        (
            DateTime::from_timestamp(10, 1).expect("fractional fixture timestamp"),
            timestamp(70),
        ),
    ] {
        assert!(
            SessionAccessDescriptor::new(
                "office".into(),
                issued,
                expires,
                ENDPOINT.into(),
                CapabilitySecret::from_bytes([6; 32]),
                AttachedVersion::new(0, 2, 0),
                HerdrVersion::new(1, 2, 3),
                vec![],
            )
            .is_err()
        );
    }

    for endpoint in [
        String::new(),
        "not-a-ticket".into(),
        ENDPOINT.to_ascii_uppercase(),
        "x".repeat(4097),
    ] {
        assert!(
            SessionAccessDescriptor::new(
                "office".into(),
                timestamp(10),
                timestamp(70),
                endpoint,
                CapabilitySecret::from_bytes([6; 32]),
                AttachedVersion::new(0, 2, 0),
                HerdrVersion::new(1, 2, 3),
                vec![],
            )
            .is_err()
        );
    }

    let maximum = (0..MAX_SESSIONS)
        .map(|index| format!("session-{index:03}"))
        .collect::<Vec<_>>();
    assert!(
        SessionAccessDescriptor::new(
            "office".into(),
            timestamp(10),
            timestamp(70),
            ENDPOINT.into(),
            CapabilitySecret::from_bytes([6; 32]),
            AttachedVersion::new(0, 2, 0),
            HerdrVersion::new(1, 2, 3),
            maximum.clone(),
        )
        .is_ok()
    );
    let mut too_many = maximum;
    too_many.push("session-999".into());
    for sessions in [
        too_many,
        vec!["same".into(), "same".into()],
        vec!["z".into(), "a".into()],
        vec!["slash/name".into()],
        vec!["nul\0name".into()],
        vec!["line\nname".into()],
    ] {
        assert!(
            SessionAccessDescriptor::new(
                "office".into(),
                timestamp(10),
                timestamp(70),
                ENDPOINT.into(),
                CapabilitySecret::from_bytes([6; 32]),
                AttachedVersion::new(0, 2, 0),
                HerdrVersion::new(1, 2, 3),
                sessions,
            )
            .is_err()
        );
    }
}

#[test]
fn decoded_fields_revalidate_types_widths_utf8_and_numeric_ranges() {
    let canonical = encode_session_access_descriptor(&fixture()).unwrap();

    let host = position(&canonical, b"office");
    let mut invalid_host = canonical.clone();
    invalid_host[host] = b'-';
    assert_eq!(
        decode_session_access_descriptor(&invalid_host).err(),
        Some(SessionAccessError::InvalidField)
    );

    let endpoint = position(&canonical, ENDPOINT.as_bytes());
    let mut invalid_utf8 = canonical.clone();
    invalid_utf8[endpoint] = 0xff;
    assert_eq!(
        decode_session_access_descriptor(&invalid_utf8).err(),
        Some(SessionAccessError::Malformed)
    );

    let version = position(&canonical, &[0x06, 0x83, 0x01, 0x02, 0x03]);
    let mut oversized_version = canonical.clone();
    oversized_version.splice(version + 2..version + 3, [0x1a, 0x00, 0x01, 0x00, 0x00]);
    assert_eq!(
        decode_session_access_descriptor(&oversized_version).err(),
        Some(SessionAccessError::InvalidField)
    );

    let attached_version = position(&canonical, &[0x08, 0x83, 0x00, 0x02, 0x00]);
    let mut oversized_attached_version = canonical.clone();
    oversized_attached_version.splice(
        attached_version + 2..attached_version + 3,
        [0x1a, 0x00, 0x01, 0x00, 0x00],
    );
    assert_eq!(
        decode_session_access_descriptor(&oversized_attached_version).err(),
        Some(SessionAccessError::InvalidField)
    );

    let session = position(&canonical, b"alpha");
    let mut invalid_session = canonical;
    invalid_session[session] = b'/';
    assert_eq!(
        decode_session_access_descriptor(&invalid_session).err(),
        Some(SessionAccessError::InvalidField)
    );
}

#[test]
fn aggregate_session_access_descriptor_limit_is_enforced_after_semantic_validation() {
    let sessions = (0..MAX_SESSIONS)
        .map(|index| {
            let prefix = format!("{index:03}-");
            format!(
                "{prefix}{}",
                "x".repeat(MAX_SESSION_NAME_BYTES - prefix.len())
            )
        })
        .collect::<Vec<_>>();
    let descriptor = SessionAccessDescriptor::new(
        "office".into(),
        timestamp(10),
        timestamp(70),
        ENDPOINT.into(),
        CapabilitySecret::from_bytes([6; 32]),
        AttachedVersion::new(0, 2, 0),
        HerdrVersion::new(1, 2, 3),
        sessions,
    )
    .expect("individual fields are valid");
    assert_eq!(
        encode_session_access_descriptor(&descriptor).err(),
        Some(SessionAccessError::Limit)
    );
}

#[test]
fn aead_context_tampering_expiration_and_version_policy_fail_closed() {
    let envelope = seal(&fixture());
    let compatible = context(1_700_000_100, HerdrVersion::new(1, 2, 99));
    assert!(open_session_access_descriptor_cursorless(&envelope, &[8; 32], &compatible).is_ok());

    for wrong in [
        VerificationContext {
            account_id: [0xa2; 16],
            ..compatible
        },
        VerificationContext {
            record_id: [0xb3; 16],
            ..compatible
        },
    ] {
        assert_eq!(
            open_session_access_descriptor_cursorless(&envelope, &[8; 32], &wrong).err(),
            Some(SessionAccessError::Decryption)
        );
    }
    assert_eq!(
        open_session_access_descriptor_cursorless(&envelope, &[9; 32], &compatible).err(),
        Some(SessionAccessError::Decryption)
    );
    assert_eq!(
        open_session_access_descriptor_cursorless(
            &envelope,
            &[8; 32],
            &context(1_700_000_300, HerdrVersion::new(1, 2, 3)),
        )
        .err(),
        Some(SessionAccessError::Expired)
    );
    assert_eq!(
        open_session_access_descriptor_cursorless(
            &envelope,
            &[8; 32],
            &context(1_700_000_100, HerdrVersion::new(1, 3, 0)),
        )
        .err(),
        Some(SessionAccessError::IncompatibleVersion)
    );
    assert!(
        open_session_access_descriptor_cursorless_for_native_upgrade(
            &envelope,
            &[8; 32],
            &context(1_700_000_100, HerdrVersion::new(9, 9, 9)),
        )
        .is_ok()
    );

    let mut changed = envelope.ciphertext().to_vec();
    changed[0] ^= 1;
    let changed = Envelope::new(*envelope.nonce(), changed).unwrap();
    assert_eq!(
        open_session_access_descriptor_cursorless(&changed, &[8; 32], &compatible).err(),
        Some(SessionAccessError::Decryption)
    );
    let mut changed_nonce = *envelope.nonce();
    changed_nonce[0] ^= 1;
    let changed_nonce = Envelope::new(changed_nonce, envelope.ciphertext().to_vec()).unwrap();
    assert_eq!(
        open_session_access_descriptor_cursorless(&changed_nonce, &[8; 32], &compatible).err(),
        Some(SessionAccessError::Decryption)
    );
}

#[test]
fn plaintext_omits_external_context_and_debug_output_redacts_secrets() {
    let descriptor = fixture();
    let encoded = encode_session_access_descriptor(&descriptor).unwrap();
    assert!(!encoded.windows(16).any(|window| window == [0xa1; 16]));
    assert!(!encoded.windows(16).any(|window| window == [0xb2; 16]));

    let debug = format!("{descriptor:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(ENDPOINT));
    assert!(!debug.contains("alpha"));
    assert!(!debug.contains(&"Bg".repeat(20)));

    let envelope = seal(&descriptor);
    let envelope_debug = format!("{envelope:?}");
    assert!(envelope_debug.contains("REDACTED"));
    assert!(!envelope_debug.contains("alpha"));
    assert_eq!(
        SessionAccessError::Decryption.to_string(),
        "session access descriptor decryption failed"
    );
}
