use attached_session_sync_protocol::account::{
    AccountBundle, AccountId, AccountRootKey, ApiKeyScope, ApiToken, AuthorizedConsumerIdentity,
    ConsumerIdentitySecret, OwnerAccountBundle, RecordId, ScopedAccountBundle, ServiceOrigin,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroize;

const BEARER: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const ACCOUNT_ID: &str = "01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2";

#[test]
fn consumer_identity_secret_is_redacted_zeroizable_and_derives_public_identity() {
    let mut secret = ConsumerIdentitySecret::from_bytes([0x5a; 32]);
    let public = secret.authorized_identity();

    assert_eq!(format!("{secret:?}"), "ConsumerIdentitySecret([REDACTED])");
    assert_ne!(public.as_bytes(), secret.as_bytes());
    secret.zeroize();
    assert_eq!(secret.as_bytes(), &[0; 32]);
}

#[test]
fn owner_scopes_private_identity_only_to_owner_and_download_bundles() {
    let secret = ConsumerIdentitySecret::from_bytes([0x5a; 32]);
    let expected_public = secret.authorized_identity();
    let owner = OwnerAccountBundle::from_parts(
        ServiceOrigin::parse("https://sync.example").unwrap(),
        AccountId::parse(ACCOUNT_ID).unwrap(),
        ApiToken::from_bytes([1; 32]),
        ApiToken::from_bytes([2; 32]),
        AccountRootKey::from_bytes([3; 32]),
        secret,
    )
    .unwrap();

    let owner_encoded = AccountBundle::Owner(owner).encode();
    let owner_json: serde_json::Value =
        serde_json::from_slice(&decoded_bundle(&owner_encoded)).unwrap();
    assert!(owner_json.get("consumer_identity_secret").is_some());
    assert!(owner_json.get("authorized_consumer_identity").is_none());

    let owner = match AccountBundle::parse(owner_encoded.as_bytes()).unwrap() {
        AccountBundle::Owner(owner) => owner,
        AccountBundle::Scoped(_) => panic!("expected owner bundle"),
    };
    let publish = AccountBundle::Scoped(owner.scoped(ApiKeyScope::Publish)).encode();
    let download = AccountBundle::Scoped(owner.scoped(ApiKeyScope::Download)).encode();
    let publish_json: serde_json::Value =
        serde_json::from_slice(&decoded_bundle(&publish)).unwrap();
    let download_json: serde_json::Value =
        serde_json::from_slice(&decoded_bundle(&download)).unwrap();
    assert_eq!(
        publish_json["authorized_consumer_identity"],
        URL_SAFE_NO_PAD.encode(expected_public.as_bytes())
    );
    assert!(publish_json.get("consumer_identity_secret").is_none());
    assert!(download_json.get("authorized_consumer_identity").is_none());
    assert_eq!(
        download_json["consumer_identity_secret"],
        URL_SAFE_NO_PAD.encode([0x5a; 32])
    );
}

#[test]
fn legacy_owner_accepts_only_byte_exact_historical_canonical_encoding() {
    let publish = URL_SAFE_NO_PAD.encode([1; 32]);
    let download = URL_SAFE_NO_PAD.encode([2; 32]);
    let root = URL_SAFE_NO_PAD.encode([3; 32]);
    let canonical = format!(
        r#"{{"bundle_type":"owner","service_origin":"https://sync.example","account_id":"{ACCOUNT_ID}","publish_api_token":"{publish}","download_api_token":"{download}","account_root_key":"{root}"}}"#
    );
    assert!(
        AccountBundle::parse(URL_SAFE_NO_PAD.encode(&canonical).as_bytes()).is_ok(),
        "byte-exact historical owner encoding must remain accepted"
    );

    let noncanonical = [
        format!(
            r#"{{"service_origin":"https://sync.example","bundle_type":"owner","account_id":"{ACCOUNT_ID}","publish_api_token":"{publish}","download_api_token":"{download}","account_root_key":"{root}"}}"#
        ),
        format!(
            r#"{{ "bundle_type":"owner","service_origin":"https://sync.example","account_id":"{ACCOUNT_ID}","publish_api_token":"{publish}","download_api_token":"{download}","account_root_key":"{root}"}}"#
        ),
        format!(
            r#"{{"bundle_type":"owner","service_origin":"https://sync.example","account_id":"{ACCOUNT_ID}","publish_api_token":"{publish}","download_api_token":"{download}","account_root_key":"{root}","consumer_identity_secret":null}}"#
        ),
    ];
    for payload in noncanonical {
        assert!(
            AccountBundle::parse(URL_SAFE_NO_PAD.encode(payload).as_bytes()).is_err(),
            "noncanonical legacy owner encoding was accepted"
        );
    }
}

#[test]
fn legacy_owner_bundle_migrates_deterministically_but_legacy_scoped_bundles_fail_closed() {
    let publish = URL_SAFE_NO_PAD.encode([1; 32]);
    let download = URL_SAFE_NO_PAD.encode([2; 32]);
    let root = URL_SAFE_NO_PAD.encode([3; 32]);
    let legacy_owner = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"bundle_type":"owner","service_origin":"https://sync.example","account_id":"{ACCOUNT_ID}","publish_api_token":"{publish}","download_api_token":"{download}","account_root_key":"{root}"}}"#
    ));
    let first = AccountBundle::parse(legacy_owner.as_bytes()).unwrap();
    let first = AccountBundle::Owner(match first {
        AccountBundle::Owner(owner) => owner,
        AccountBundle::Scoped(_) => panic!("expected owner bundle"),
    })
    .encode();
    let second = AccountBundle::parse(legacy_owner.as_bytes()).unwrap();
    let second = AccountBundle::Owner(match second {
        AccountBundle::Owner(owner) => owner,
        AccountBundle::Scoped(_) => panic!("expected owner bundle"),
    })
    .encode();
    assert_eq!(first, second);
    let migrated: serde_json::Value = serde_json::from_slice(&decoded_bundle(&first)).unwrap();
    assert!(migrated.get("consumer_identity_secret").is_some());

    for scope in [ApiKeyScope::Publish, ApiKeyScope::Download] {
        let legacy_scoped = serde_json::json!({
            "bundle_type": "scoped",
            "service_origin": "https://sync.example",
            "account_id": ACCOUNT_ID,
            "api_key_scope": scope as u8,
            "api_token": URL_SAFE_NO_PAD.encode([1; 32]),
            "account_root_key": URL_SAFE_NO_PAD.encode([3; 32]),
        });
        assert!(AccountBundle::parse(&encode_json(&legacy_scoped)).is_err());
    }
}

#[test]
fn publish_bundle_carries_the_authorized_consumer_identity() {
    let identity = AuthorizedConsumerIdentity::from_bytes([0x5a; 32]);
    let bundle = ScopedAccountBundle::from_parts(
        ServiceOrigin::parse("https://sync.example").unwrap(),
        AccountId::parse(ACCOUNT_ID).unwrap(),
        ApiKeyScope::Publish,
        ApiToken::from_bytes([1; 32]),
        AccountRootKey::from_bytes([2; 32]),
        Some(identity),
    )
    .unwrap();

    let encoded = AccountBundle::Scoped(bundle).encode();
    let payload: serde_json::Value = serde_json::from_slice(&decoded_bundle(&encoded)).unwrap();
    assert_eq!(
        payload["authorized_consumer_identity"],
        URL_SAFE_NO_PAD.encode([0x5a; 32])
    );
    let reparsed = parse_scoped(&encoded);
    assert_eq!(reparsed.authorized_consumer_identity(), Some(identity));
}

#[test]
fn publish_bundle_rejects_missing_or_malformed_authorized_identity() {
    let bundle = ScopedAccountBundle::from_parts(
        ServiceOrigin::parse("https://sync.example").unwrap(),
        AccountId::parse(ACCOUNT_ID).unwrap(),
        ApiKeyScope::Publish,
        ApiToken::from_bytes([1; 32]),
        AccountRootKey::from_bytes([2; 32]),
        Some(AuthorizedConsumerIdentity::from_bytes([3; 32])),
    )
    .unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&decoded_bundle(&AccountBundle::Scoped(bundle).encode())).unwrap();

    let mut missing = original.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("authorized_consumer_identity");
    assert!(AccountBundle::parse(&encode_json(&missing)).is_err());

    for malformed in [serde_json::json!("bad"), serde_json::json!(null)] {
        assert!(
            AccountBundle::parse(&encode_json(&with_json_field(
                &original,
                "authorized_consumer_identity",
                malformed,
            )))
            .is_err()
        );
    }
}

fn scoped_credentials(
    bundle: ScopedAccountBundle,
) -> (String, AccountId, ApiKeyScope, [u8; 32], [u8; 32]) {
    let scope = bundle.api_key_scope();
    bundle.consume(|origin, account_id, api_token, root_key| {
        (
            origin.as_str().to_owned(),
            account_id,
            scope,
            *api_token,
            *root_key,
        )
    })
}

fn assert_same_account_with_distinct_tokens(
    publish: ScopedAccountBundle,
    download: ScopedAccountBundle,
) {
    let publish = scoped_credentials(publish);
    let download = scoped_credentials(download);
    assert_eq!(publish.0, download.0);
    assert_eq!(publish.1, download.1);
    assert_eq!(publish.2, ApiKeyScope::Publish);
    assert_eq!(download.2, ApiKeyScope::Download);
    assert_ne!(publish.3, download.3);
    assert_eq!(publish.4, download.4);
}

macro_rules! assert_not_clone {
    ($type:ty) => {
        const _: fn() = || {
            trait AmbiguousIfClone<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfClone<()> for T {}
            struct IfClone;
            impl<T: ?Sized + Clone> AmbiguousIfClone<IfClone> for T {}
            let _ = <$type as AmbiguousIfClone<_>>::check;
        };
    };
}

assert_not_clone!(ApiToken);
assert_not_clone!(AccountRootKey);
assert_not_clone!(AccountBundle);
assert_not_clone!(ScopedAccountBundle);
assert_not_clone!(OwnerAccountBundle);

#[test]
fn bearer_hashes_raw_32_bytes_without_prefix() {
    let token = ApiToken::parse_bare(BEARER).expect("fixed bearer parses");
    let expected = hex("60c2cec9685e63fea95d48fdb85322dec67eea312dae7d1ecf1a854a97fd3a17");
    assert_eq!(token.service_hash(), expected);
}

#[test]
fn bearer_and_authorization_grammar_is_exact() {
    let valid = format!("Bearer {BEARER}");
    assert_eq!(valid.len(), 50);
    assert!(ApiToken::parse_authorization(&[valid.as_bytes()]).is_ok());
    assert!(ApiToken::parse_authorization(&[]).is_err());
    assert!(ApiToken::parse_authorization(&[valid.as_bytes(), valid.as_bytes()]).is_err());
    let different = format!("Bearer {}", "A".repeat(43));
    assert!(ApiToken::parse_authorization(&[valid.as_bytes(), different.as_bytes()]).is_err());

    let short_decoded = URL_SAFE_NO_PAD.encode([0_u8; 31]);
    let long_decoded = URL_SAFE_NO_PAD.encode([0_u8; 33]);
    assert_eq!(short_decoded.len(), 42);
    assert_eq!(long_decoded.len(), 44);
    let mut invalid_terminal = BEARER.as_bytes().to_vec();
    *invalid_terminal.last_mut().expect("nonempty") = b'9';

    let mut rejected = vec![
        format!("bearer {BEARER}").into_bytes(),
        format!("BEARER {BEARER}").into_bytes(),
        format!("BeArEr {BEARER}").into_bytes(),
        format!(" Bearer {BEARER}").into_bytes(),
        format!("Bearer  {BEARER}").into_bytes(),
        format!("Bearer\t{BEARER}").into_bytes(),
        format!("Bearer {BEARER} ").into_bytes(),
        format!("Bearer {BEARER}=").into_bytes(),
        format!("Bearer {BEARER},Bearer {BEARER}").into_bytes(),
        format!("Bearer {BEARER}, Bearer {BEARER}").into_bytes(),
        format!("Basic {BEARER}").into_bytes(),
        [b"Bearer ".as_slice(), short_decoded.as_bytes()].concat(),
        [b"Bearer ".as_slice(), long_decoded.as_bytes()].concat(),
        [b"Bearer ".as_slice(), invalid_terminal.as_slice()].concat(),
        [b"Bearer ".as_slice(), b"+".repeat(43).as_slice()].concat(),
        [b"Bearer ".as_slice(), b"/".repeat(43).as_slice()].concat(),
    ];
    for control in [0_u8, 1, 9, 10, 13, 31, 127, 128, 133, 159] {
        let mut value = valid.as_bytes().to_vec();
        value[7] = control;
        rejected.push(value);
    }
    rejected.push([valid.as_bytes(), b"\r\n Bearer x"].concat());
    for value in rejected {
        assert!(
            ApiToken::parse_authorization(&[value.as_slice()]).is_err(),
            "invalid authorization category accepted"
        );
    }
}

#[test]
fn credential_wrappers_are_redacted_and_zeroizable() {
    let mut token = ApiToken::from_bytes([9; 32]);
    assert_eq!(format!("{token:?}"), "ApiToken([REDACTED])");
    token.zeroize();
    assert_eq!(
        token.service_hash(),
        ApiToken::from_bytes([0; 32]).service_hash()
    );

    let mut root = AccountRootKey::from_bytes([7; 32]);
    assert_eq!(format!("{root:?}"), "AccountRootKey([REDACTED])");
    root.zeroize();
}

#[test]
fn account_ids_are_canonical_uuid_v7_and_record_ids_remain_base64url() {
    let account = AccountId::parse(ACCOUNT_ID).expect("UUIDv7 account ID");
    assert!(account.is_uuid_v7());
    assert_eq!(account.to_string(), ACCOUNT_ID);
    assert_eq!(
        AccountId::from_bytes(*account.as_bytes()).to_string(),
        ACCOUNT_ID
    );

    for malformed in [
        "",
        "01890F9E-7B3A-7CC2-98C8-4DC0CBD2BBF2",
        "01890f9e7b3a7cc298c84dc0cbd2bbf2",
        "550e8400-e29b-41d4-a716-446655440000",
        "01890f9e-7b3a-7cc2-18c8-4dc0cbd2bbf2",
    ] {
        assert!(AccountId::parse(malformed).is_err(), "accepted {malformed}");
    }

    let record = RecordId::from_bytes(std::array::from_fn(|index| index as u8));
    assert_eq!(record.encode(), "AAECAwQFBgcICQoLDA0ODw");
    assert_eq!(RecordId::parse(&record.encode()).unwrap(), record);
}

#[test]
fn origins_reject_forbidden_https_hosts_before_url_semantics() {
    for value in ["https://localhost", "https://0x7f000001"] {
        assert!(
            ServiceOrigin::parse(value).is_err(),
            "forbidden HTTPS host was accepted"
        );
    }
}

#[test]
fn origins_accept_all_frozen_canonical_boundaries_byte_exactly() {
    let label63 = "a".repeat(63);
    let dns253 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(dns253.len(), 253);
    let accepted = vec![
        "https://a".to_owned(),
        format!("https://{label63}"),
        format!("https://{dns253}"),
        "https://0.1.2.255".to_owned(),
        "https://0.1.2.255:1".to_owned(),
        "https://[2001:db8::1]".to_owned(),
        "https://[2001:db8::1]:65535".to_owned(),
        "https://sync.example:8443".to_owned(),
        "http://127.0.0.1:1".to_owned(),
        "http://127.0.0.1:65535".to_owned(),
        "http://[::1]:1".to_owned(),
        "http://[::1]:65535".to_owned(),
    ];
    for value in accepted {
        assert_eq!(
            ServiceOrigin::parse(&value)
                .expect("accepted frozen origin")
                .as_str(),
            value
        );
    }
}

#[test]
fn origins_reject_every_noncanonical_and_ssrf_sensitive_class() {
    let label64 = "a".repeat(64);
    let dns254 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    assert_eq!(dns254.len(), 254);
    let rejected = vec![
        "".to_owned(),
        "sync.example".to_owned(),
        "HTTPS://sync.example".to_owned(),
        "https://SYNC.example".to_owned(),
        "https://".to_owned(),
        "https:///sync.example".to_owned(),
        "https://sync.example/".to_owned(),
        "https://sync.example//".to_owned(),
        "https://sync.example/path".to_owned(),
        "https://sync.example?q".to_owned(),
        "https://sync.example#x".to_owned(),
        "https://user@sync.example".to_owned(),
        "https://user:pass@sync.example".to_owned(),
        "https://@sync.example".to_owned(),
        "https://sync%2eexample".to_owned(),
        "https://sync.example%3a444".to_owned(),
        "https://sync\\example".to_owned(),
        "https://sync.example ".to_owned(),
        "https://sync\texample".to_owned(),
        "https://sync\nexample".to_owned(),
        "https://sync\0example".to_owned(),
        format!("https://sync{}example", char::from(127)),
        format!("https://sync{}example", char::from(128)),
        "https://bücher.example".to_owned(),
        "https://sync.example.".to_owned(),
        "https://.example".to_owned(),
        "https://sync..example".to_owned(),
        "https://-sync.example".to_owned(),
        "https://sync-.example".to_owned(),
        format!("https://{label64}.example"),
        format!("https://{dns254}"),
        "https://xn--bcher-kva.example".to_owned(),
        "https://localhost".to_owned(),
        "https://localhost:444".to_owned(),
        "http://localhost:444".to_owned(),
        "https://0.0.0.0".to_owned(),
        "https://[::]".to_owned(),
        "http://127.0.0.1".to_owned(),
        "http://[::1]".to_owned(),
        "http://sync.example:444".to_owned(),
        "http://192.168.1.1:444".to_owned(),
        "http://169.254.1.1:444".to_owned(),
        "http://0.0.0.0:444".to_owned(),
        "http://127.0.0.2:444".to_owned(),
        "http://[::]:444".to_owned(),
        "https://127.0.0".to_owned(),
        "https://127.0.0.1.2".to_owned(),
        "https://256.0.0.1".to_owned(),
        "https://127.00.0.1".to_owned(),
        "https://0x7f000001".to_owned(),
        "https://0xffffffff".to_owned(),
        "https://0x7f.0.0.1".to_owned(),
        "https://2130706433".to_owned(),
        "https://127.1".to_owned(),
        "https://127.0.1".to_owned(),
        "https://0177.0.0.1".to_owned(),
        "https://2001:db8::1".to_owned(),
        "https://[2001:DB8::1]".to_owned(),
        "https://[2001:db8:0:0:0:0:0:1]".to_owned(),
        "https://[2001:0db8::1]".to_owned(),
        "https://[::ffff:127.0.0.1]".to_owned(),
        "https://[fe80::1%25lo]".to_owned(),
        "https://sync.example:".to_owned(),
        "https://sync.example:0".to_owned(),
        "https://sync.example:-1".to_owned(),
        "https://sync.example:+1".to_owned(),
        "https://sync.example:01".to_owned(),
        "https://sync.example:abc".to_owned(),
        "https://sync.example:65536".to_owned(),
        "https://sync.example:1x".to_owned(),
        "https://sync.example:443".to_owned(),
        "http://127.0.0.1:80".to_owned(),
        "ftp://sync.example".to_owned(),
    ];
    for value in rejected {
        assert!(
            ServiceOrigin::parse(&value).is_err(),
            "rejected origin category was accepted"
        );
    }
}

#[test]
fn tagged_base64_bundle_has_a_stable_bounded_roundtrip() {
    let bundle = fixture_bundle();
    let account_id = bundle.account_id;
    let encoded = AccountBundle::Scoped(bundle).encode();
    assert!(
        encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );

    let payload = decoded_bundle(&encoded);
    let expected_root =
        URL_SAFE_NO_PAD.encode(std::array::from_fn::<_, 32, _>(|index| (index + 32) as u8));
    let expected_identity = URL_SAFE_NO_PAD.encode([64; 32]);
    assert_eq!(
        String::from_utf8(payload.clone()).unwrap(),
        format!(
            r#"{{"bundle_type":"scoped","service_origin":"https://sync.example:8443","account_id":"{ACCOUNT_ID}","api_key_scope":2,"api_token":"{BEARER}","account_root_key":"{expected_root}","consumer_identity_secret":"{expected_identity}"}}"#
        )
    );
    assert!(payload.len() <= attached_session_sync_protocol::limits::MAX_BUNDLE_BYTES);

    let reparsed = scoped_credentials(parse_scoped(&encoded));
    assert_eq!(reparsed.1, account_id);
    assert_eq!(reparsed.2, ApiKeyScope::Download);
    assert_eq!(reparsed.3, core::array::from_fn(|index| index as u8));
}

#[test]
fn tagged_owner_bundle_roundtrips_both_scopes() {
    let owner = OwnerAccountBundle::from_parts(
        ServiceOrigin::parse("https://sync.example").unwrap(),
        AccountId::parse(ACCOUNT_ID).unwrap(),
        ApiToken::from_bytes([1; 32]),
        ApiToken::from_bytes([2; 32]),
        AccountRootKey::from_bytes([3; 32]),
        ConsumerIdentitySecret::from_bytes([4; 32]),
    )
    .unwrap();
    let encoded = AccountBundle::Owner(owner).encode();
    let json: serde_json::Value = serde_json::from_slice(&decoded_bundle(&encoded)).unwrap();
    assert_eq!(json["bundle_type"], "owner");

    let owner = match AccountBundle::parse(encoded.as_bytes()).unwrap() {
        AccountBundle::Owner(owner) => owner,
        AccountBundle::Scoped(_) => panic!("expected owner bundle"),
    };
    let publish = owner.scoped(ApiKeyScope::Publish);
    let download = owner.scoped(ApiKeyScope::Download);
    assert_same_account_with_distinct_tokens(publish, download);
}

#[test]
fn bundle_accepts_the_maximum_canonical_origin() {
    let dns253 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let origin = ServiceOrigin::parse(&format!("https://{dns253}:65535")).unwrap();
    let account_id = AccountId::parse(ACCOUNT_ID).unwrap();
    let scoped = ScopedAccountBundle::from_download_parts(
        origin.clone(),
        account_id,
        ApiToken::from_bytes([3; 32]),
        AccountRootKey::from_bytes([4; 32]),
        ConsumerIdentitySecret::from_bytes([6; 32]),
    )
    .unwrap();
    let owner = OwnerAccountBundle::from_parts(
        origin,
        account_id,
        ApiToken::from_bytes([3; 32]),
        ApiToken::from_bytes([4; 32]),
        AccountRootKey::from_bytes([5; 32]),
        ConsumerIdentitySecret::from_bytes([6; 32]),
    )
    .unwrap();
    for encoded in [
        AccountBundle::Scoped(scoped).encode(),
        AccountBundle::Owner(owner).encode(),
    ] {
        assert!(
            decoded_bundle(&encoded).len()
                <= attached_session_sync_protocol::limits::MAX_BUNDLE_BYTES
        );
        assert!(AccountBundle::parse(encoded.as_bytes()).is_ok());
    }
}

#[test]
fn scoped_bundles_contain_only_their_own_api_token() {
    let account_id = AccountId::parse(ACCOUNT_ID).unwrap();
    let origin = ServiceOrigin::parse("https://sync.example").unwrap();
    let publish = ScopedAccountBundle::from_parts(
        origin.clone(),
        account_id,
        ApiKeyScope::Publish,
        ApiToken::from_bytes([1; 32]),
        AccountRootKey::from_bytes([3; 32]),
        Some(AuthorizedConsumerIdentity::from_bytes([4; 32])),
    )
    .unwrap();
    let download = ScopedAccountBundle::from_download_parts(
        origin,
        account_id,
        ApiToken::from_bytes([2; 32]),
        AccountRootKey::from_bytes([3; 32]),
        ConsumerIdentitySecret::from_bytes([4; 32]),
    )
    .unwrap();

    let publish_encoded = AccountBundle::Scoped(publish).encode();
    let download_encoded = AccountBundle::Scoped(download).encode();
    assert_same_account_with_distinct_tokens(
        parse_scoped(&publish_encoded),
        parse_scoped(&download_encoded),
    );
    let publish_payload = decoded_bundle(&publish_encoded);
    let download_payload = decoded_bundle(&download_encoded);
    let publish_token = ApiToken::from_bytes([1; 32]).encode();
    let download_token = ApiToken::from_bytes([2; 32]).encode();
    assert!(contains_window(&publish_payload, publish_token.as_bytes()));
    assert!(!contains_window(
        &publish_payload,
        download_token.as_bytes()
    ));
    assert!(contains_window(
        &download_payload,
        download_token.as_bytes()
    ));
    assert!(!contains_window(
        &download_payload,
        publish_token.as_bytes()
    ));
}

#[test]
fn bundle_parser_rejects_noncanonical_malformed_and_unknown_messages() {
    let encoded = AccountBundle::Scoped(fixture_bundle()).encode();
    for end in 0..encoded.len() {
        assert!(AccountBundle::parse(&encoded.as_bytes()[..end]).is_err());
    }
    for malformed in [
        Vec::new(),
        [encoded.as_bytes(), b"="].concat(),
        [encoded.as_bytes(), b"\n"].concat(),
        b"not-base64".to_vec(),
        b"+".to_vec(),
        vec![b'A'; 1025],
    ] {
        assert!(AccountBundle::parse(&malformed).is_err());
    }

    let original: serde_json::Value = serde_json::from_slice(&decoded_bundle(&encoded)).unwrap();
    for changed in [
        with_json_field(
            &original,
            "service_origin",
            serde_json::json!("https://SYNC.example"),
        ),
        with_json_field(
            &original,
            "account_id",
            serde_json::json!("550e8400-e29b-41d4-a716-446655440000"),
        ),
        with_json_field(&original, "api_key_scope", serde_json::json!(3)),
        with_json_field(&original, "bundle_type", serde_json::json!("future")),
        with_json_field(&original, "unknown", serde_json::json!(true)),
    ] {
        assert!(AccountBundle::parse(&encode_json(&changed)).is_err());
    }

    let mut trailing = decoded_bundle(&encoded);
    trailing.push(b'x');
    assert!(AccountBundle::parse(&URL_SAFE_NO_PAD.encode(trailing).into_bytes()).is_err());
}

#[test]
fn bundle_rejects_non_uuid_v7_account_ids_and_redacts_debug_output() {
    assert!(
        ScopedAccountBundle::from_parts(
            ServiceOrigin::parse("https://sync.example").unwrap(),
            AccountId::from_bytes([0; 16]),
            ApiKeyScope::Download,
            ApiToken::from_bytes([3; 32]),
            AccountRootKey::from_bytes([4; 32]),
            None,
        )
        .is_err()
    );

    let bundle = AccountBundle::Scoped(fixture_bundle());
    let debug = format!("{bundle:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(BEARER));
    let error = AccountBundle::parse(BEARER.as_bytes()).expect_err("not a bundle");
    assert!(!format!("{error:?}").contains(BEARER));
}

fn fixture_bundle() -> ScopedAccountBundle {
    ScopedAccountBundle::from_download_parts(
        ServiceOrigin::parse("https://sync.example:8443").unwrap(),
        AccountId::parse(ACCOUNT_ID).unwrap(),
        ApiToken::from_bytes(std::array::from_fn(|index| index as u8)),
        AccountRootKey::from_bytes(std::array::from_fn(|index| (index + 32) as u8)),
        ConsumerIdentitySecret::from_bytes([64; 32]),
    )
    .unwrap()
}

fn parse_scoped(encoded: &str) -> ScopedAccountBundle {
    match AccountBundle::parse(encoded.as_bytes()).unwrap() {
        AccountBundle::Scoped(bundle) => bundle,
        AccountBundle::Owner(_) => panic!("expected scoped bundle"),
    }
}

fn decoded_bundle(encoded: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(encoded).unwrap()
}

fn encode_json(value: &serde_json::Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(value).unwrap())
        .into_bytes()
}

fn with_json_field(
    original: &serde_json::Value,
    field: &str,
    value: serde_json::Value,
) -> serde_json::Value {
    let mut changed = original.clone();
    changed
        .as_object_mut()
        .expect("bundle wire is an object")
        .insert(field.to_owned(), value);
    changed
}

fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn hex(value: &str) -> [u8; 32] {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
