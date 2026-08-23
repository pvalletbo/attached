use attached_session_sync_protocol::{
    account::RecordId,
    api::{
        ACCOUNTS_PATH, ALLOW_ACCOUNTS, ALLOW_CURSORLESS_RECORDS, ALLOW_HEALTH, ALLOW_RECORD_INDEX,
        AUTHENTICATE_VALUE, ApiError, CACHE_CONTROL_VALUE, CreateAccountResponse, Envelope,
        ErrorCode, ErrorDto, HEALTH_PATH, LiveRecordIndex, LiveRecordIndexEntry,
        RECORD_INDEX_ROUTE, RECORDS_ROUTE, parse_live_record_index,
    },
    limits::{MAX_API_BODY_BYTES, MAX_CIPHERTEXT_TEXT_LEN, MAX_LIVE_RECORDS},
};

const VALID_ACCOUNT_RESPONSE_JSON: &str = r#"{"account_id":"01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2","publish_api_token":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","download_api_token":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"}"#;

#[test]
fn account_creation_response_is_bounded_strict_and_redacted() {
    let response = CreateAccountResponse::parse_json(VALID_ACCOUNT_RESPONSE_JSON.as_bytes())
        .expect("valid account-creation response");
    assert_eq!(
        serde_json::to_string(&response).expect("serialize account response"),
        VALID_ACCOUNT_RESPONSE_JSON
    );
    assert!(format!("{response:?}").contains("[REDACTED]"));

    for invalid in [
        VALID_ACCOUNT_RESPONSE_JSON.replacen('}', ",\"unknown\":0}", 1),
        VALID_ACCOUNT_RESPONSE_JSON.replacen(
            "01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2",
            "550e8400-e29b-41d4-a716-446655440000",
            1,
        ),
        VALID_ACCOUNT_RESPONSE_JSON.replacen(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "bad",
            1,
        ),
        VALID_ACCOUNT_RESPONSE_JSON.replacen(
            "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            1,
        ),
        format!(
            "{{\"account_id\":\"01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2\",{}",
            &VALID_ACCOUNT_RESPONSE_JSON[1..]
        ),
    ] {
        assert_eq!(
            CreateAccountResponse::parse_json(invalid.as_bytes()).err(),
            Some(ApiError::InvalidRequest)
        );
    }

    let mut exact = VALID_ACCOUNT_RESPONSE_JSON.as_bytes().to_vec();
    exact.resize(MAX_API_BODY_BYTES, b' ');
    assert!(CreateAccountResponse::parse_json(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(
        CreateAccountResponse::parse_json(&exact).err(),
        Some(ApiError::TooLarge)
    );
}

#[test]
fn envelope_parsing_rejects_noncanonical_and_oversized_input() {
    let valid =
        br#"{"envelope_version":1,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AQID"}"#;
    let envelope = Envelope::parse_json(valid).expect("valid envelope");
    assert_eq!(envelope.ciphertext, [1, 2, 3]);
    assert_eq!(
        serde_json::to_vec(&envelope).expect("serialize envelope"),
        valid
    );

    for invalid in [
        br#"{"envelope_version":2,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AQID"}"#.as_slice(),
        br#"{"envelope_version":1,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","ciphertext":"AQID"}"#,
        br#"{"envelope_version":1,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AQID","unknown":0}"#,
        br#"{"envelope_version":1,"envelope_version":1,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AQID"}"#,
        br#"{"envelope_version":1,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AQID"} trailing"#,
    ] {
        assert_eq!(Envelope::parse_json(invalid), Err(ApiError::InvalidRequest));
    }

    let oversized = "A".repeat(MAX_CIPHERTEXT_TEXT_LEN + 1);
    let oversized = format!(
        r#"{{"envelope_version":1,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"{oversized}"}}"#
    );
    assert_eq!(
        Envelope::parse_json(oversized.as_bytes()),
        Err(ApiError::TooLarge)
    );
}

#[test]
fn live_index_is_the_only_cursorless_synchronization_page() {
    let records = (0..MAX_LIVE_RECORDS)
        .map(|index| {
            let mut bytes = [0; 16];
            bytes[14..].copy_from_slice(&(index as u16).to_be_bytes());
            LiveRecordIndexEntry {
                record_id: RecordId::from_bytes(bytes),
                revision: index as u64 + 1,
            }
        })
        .collect::<Vec<_>>();
    let index = LiveRecordIndex::new(records.clone()).expect("maximum index");
    let encoded = serde_json::to_vec(&index).expect("serialize index");
    assert_eq!(parse_live_record_index(&encoded), Ok(index));

    let mut too_many = records;
    too_many.push(LiveRecordIndexEntry {
        record_id: RecordId::from_bytes([0xff; 16]),
        revision: 1,
    });
    assert!(LiveRecordIndex::new(too_many).is_err());
    assert_eq!(
        parse_live_record_index(
            br#"{"records":[{"record_id":"AAAAAAAAAAAAAAAAAAAAAA","revision":0}]}"#
        ),
        Err(ApiError::InvalidRequest)
    );
}

#[test]
fn errors_and_remaining_routes_are_compact_and_stable() {
    assert_eq!(
        serde_json::to_string(&ErrorDto::new(ErrorCode::InvalidRequest)).expect("error JSON"),
        r#"{"code":"invalid_request"}"#
    );
    assert!(serde_json::from_str::<ErrorDto>(r#"{"code":"invalid_request","unknown":0}"#).is_err());
    assert_eq!(
        (
            HEALTH_PATH,
            ACCOUNTS_PATH,
            RECORD_INDEX_ROUTE,
            RECORDS_ROUTE,
            ALLOW_HEALTH,
            ALLOW_ACCOUNTS,
            ALLOW_RECORD_INDEX,
            ALLOW_CURSORLESS_RECORDS,
        ),
        (
            "/healthz",
            "/v1/accounts",
            "/v1/accounts/{account_id}/records",
            "/v1/accounts/{account_id}/records/{record_id}",
            "GET",
            "POST",
            "GET",
            "GET, PUT",
        )
    );
    assert_eq!(CACHE_CONTROL_VALUE, "no-store");
    assert_eq!(AUTHENTICATE_VALUE, "Bearer realm=\"herdr-sync-v1\"");
}
