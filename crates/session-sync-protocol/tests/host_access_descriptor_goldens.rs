use attached_session_sync_protocol::crypto::open_host_access_descriptor;
use attached_session_sync_protocol::{
    AttachedVersion, Envelope, HostAccessDescriptor, VerificationContext,
    decode_host_access_descriptor, derive_host_access_descriptor_key,
    encode_host_access_descriptor, envelope_aad, seal_host_access_descriptor,
};
use attached_tunnel_protocol::CapabilitySecret;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use sha2::Sha256;

const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";
const CBOR: &str = "a701666f6666696365021a6553f100031a6553f22c047868656e64706f696e746163786672373469676d73627673626e6e37337763656367357674336b627a6e63717766726469616d70757566776e686b75626c6d617161636275686935647168697873367a64666f6a796334336c66667978716361643761616161646161690558200606060606060606060606060606060606060606060606060606060606060606068304050607f5";
const HKDF_KEY: &str = "a678b5d19596e61c8e92394f3e96744b4f4f7e95aaa82f1dc144af84e8a51a9a";
const AAD: &str = "61747461636865642f686f73742d73796e632f656e76656c6f70652d6161642f76310001010101010101010101010101010101020202020202020202020202020202020001";

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("fixed hex"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

fn timestamp(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).expect("fixture timestamp")
}

fn fixture() -> HostAccessDescriptor {
    HostAccessDescriptor::new(
        "office".into(),
        timestamp(1_700_000_000),
        timestamp(1_700_000_300),
        ENDPOINT.into(),
        CapabilitySecret::from_bytes([6; 32]),
        AttachedVersion::new(4, 5, 6),
        true,
    )
    .expect("fixture")
}

#[test]
fn host_access_descriptor_matches_the_frozen_canonical_cbor() {
    let expected = decode_hex(CBOR);
    let encoded = encode_host_access_descriptor(&fixture()).expect("encode");
    assert_eq!(encoded, expected);
    let decoded = decode_host_access_descriptor(&expected).expect("decode");
    assert_eq!(decoded.host_label(), "office");
    assert_eq!(decoded.endpoint_ticket(), ENDPOINT);
    assert_eq!(decoded.attach_capability_bytes(), [6; 32]);
    assert_eq!(decoded.attached_version(), AttachedVersion::new(4, 5, 6));
    assert!(decoded.ssh_enabled());
    assert_eq!(
        encode_host_access_descriptor(&decoded).expect("re-encode"),
        expected
    );
}

#[test]
fn context_key_and_aad_match_independent_vectors() {
    let mut independent_key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&[1; 16]), &[8; 32])
        .expand(
            b"attached/host-sync/descriptor-aead-key/v1\0",
            &mut independent_key,
        )
        .expect("HKDF");
    assert_eq!(independent_key.as_slice(), decode_hex(HKDF_KEY));
    assert_eq!(
        derive_host_access_descriptor_key(&[8; 32], &[1; 16]).expect("key"),
        independent_key
    );

    let mut independent_aad = b"attached/host-sync/envelope-aad/v1\0".to_vec();
    independent_aad.extend_from_slice(&[1; 16]);
    independent_aad.extend_from_slice(&[2; 16]);
    independent_aad.extend_from_slice(&1_u16.to_be_bytes());
    assert_eq!(independent_aad, decode_hex(AAD));
    assert_eq!(envelope_aad(&[1; 16], &[2; 16]), independent_aad);

    let nonce = [9_u8; 24];
    let ciphertext = XChaCha20Poly1305::new((&independent_key).into())
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &decode_hex(CBOR),
                aad: &independent_aad,
            },
        )
        .expect("independent encryption");
    let envelope = Envelope::new(nonce, ciphertext).expect("fixed envelope");
    let opened = open_host_access_descriptor(
        &envelope,
        &[8; 32],
        &VerificationContext {
            account_id: [1; 16],
            record_id: [2; 16],
            now: timestamp(1_700_000_001),
        },
    )
    .expect("open independent envelope");
    assert_eq!(
        encode_host_access_descriptor(opened.descriptor()).unwrap(),
        decode_hex(CBOR)
    );
}

#[test]
fn public_sealing_generates_distinct_os_random_nonces() {
    let descriptor = fixture();
    let first =
        seal_host_access_descriptor(&descriptor, &[8; 32], &[1; 16], &[2; 16]).expect("first seal");
    let second = seal_host_access_descriptor(&descriptor, &[8; 32], &[1; 16], &[2; 16])
        .expect("second seal");
    assert_ne!(first.nonce(), second.nonce());
}
