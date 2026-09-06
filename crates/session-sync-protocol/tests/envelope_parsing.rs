use attached_session_sync_protocol::{
    api::{ApiError, Envelope},
    limits::{MAX_API_BODY_BYTES, MAX_CIPHERTEXT_BYTES, MAX_CIPHERTEXT_TEXT_LEN},
};

const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn envelope(ciphertext: &str) -> String {
    format!(r#"{{"envelope_version":1,"nonce":"{NONCE}","ciphertext":"{ciphertext}"}}"#)
}

#[test]
fn ciphertext_boundaries_agree_between_json_and_serde_entry_points() {
    for length in [0, 1, 2, 3, MAX_CIPHERTEXT_BYTES - 1, MAX_CIPHERTEXT_BYTES] {
        let expected = Envelope::new([0; 24], vec![0xff; length]).unwrap();
        let json = serde_json::to_vec(&expected).unwrap();
        assert_eq!(Envelope::parse_json(&json), Ok(expected.clone()));
        assert_eq!(serde_json::from_slice::<Envelope>(&json).unwrap(), expected);
    }
    for excess in [1, 2, 3, 4] {
        let json = envelope(&"A".repeat(MAX_CIPHERTEXT_TEXT_LEN + excess));
        assert_eq!(
            Envelope::parse_json(json.as_bytes()),
            Err(ApiError::TooLarge)
        );
        assert!(serde_json::from_str::<Envelope>(&json).is_err());
    }
}

#[test]
fn invalid_structure_and_metadata_take_precedence_over_ciphertext_size() {
    let oversized = "A".repeat(MAX_CIPHERTEXT_TEXT_LEN + 1);
    let json = envelope(&oversized);
    let invalid = [
        json.replace("\"envelope_version\":1", "\"envelope_version\":2"),
        json.replace("\"envelope_version\":1,", ""),
        json.replace(NONCE, "invalid"),
        json.replace(&format!("\"nonce\":\"{NONCE}\","), ""),
        json.replace('}', ",\"unknown\":0}"),
        json.replace('}', ",\"ciphertext\":\"\"}"),
        json.replace('}', ",\"nonce\":\"invalid\"}"),
        format!("{json} trailing"),
        format!("{json} {{}}"),
        format!(r#"{{"ciphertext":"{oversized}","nonce":"invalid","envelope_version":1}}"#),
        format!(r#"{{"ciphertext":"{oversized}","nonce":"{NONCE}","envelope_version":2}}"#),
        format!(
            r#"{{"ciphertext":"{oversized}","nonce":"{NONCE}","envelope_version":1,"unknown":0}}"#
        ),
        format!(
            r#"{{"ciphertext":"{oversized}","ciphertext":"","nonce":"{NONCE}","envelope_version":1}}"#
        ),
    ];
    for (case, json) in invalid.iter().enumerate() {
        assert_eq!(
            Envelope::parse_json(json.as_bytes()),
            Err(ApiError::InvalidRequest),
            "case {case}"
        );
        assert!(
            serde_json::from_str::<Envelope>(json).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn envelope_requires_an_object_with_unescaped_canonical_values() {
    for json in [
        format!(r#"[1,"{NONCE}","AQID"]"#),
        envelope(r"\u0041QID"),
        envelope("AR"), // Nonzero trailing bits.
        envelope("AQ=="),
        envelope("+/8"),
        envelope("A"),
        envelope("AQID").replace(NONCE, r"\u0041AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        envelope("AQID").replace("\"AQID\"", "null"),
        envelope("AQID").replace("\"AQID\"", "[1,2,3]"),
    ] {
        assert_eq!(
            Envelope::parse_json(json.as_bytes()),
            Err(ApiError::InvalidRequest)
        );
        assert!(serde_json::from_str::<Envelope>(&json).is_err());
    }
}

#[test]
fn size_classification_uses_json_fields_not_a_text_search() {
    // JSON escapes are permitted in field names, but not in encoded values.
    let escaped_key = envelope("AQID").replace("ciphertext", r"\u0063iphertext");
    assert_eq!(
        Envelope::parse_json(escaped_key.as_bytes())
            .unwrap()
            .ciphertext,
        [1, 2, 3]
    );
    let oversized = "A".repeat(MAX_CIPHERTEXT_TEXT_LEN + 1);
    let escaped_key = envelope(&oversized).replace("ciphertext", r"\u0063iphertext");
    assert_eq!(
        Envelope::parse_json(escaped_key.as_bytes()),
        Err(ApiError::TooLarge)
    );

    // Rewriting a too-long value must not accidentally erase invalid JSON syntax.
    for control in ['\n', '\r', '\t', '\0'] {
        let malformed = envelope(&format!("{oversized}{control}"));
        assert_eq!(
            Envelope::parse_json(malformed.as_bytes()),
            Err(ApiError::InvalidRequest)
        );
    }
}

#[test]
fn body_limit_is_checked_before_json_syntax() {
    let mut json = envelope("").into_bytes();
    json.resize(MAX_API_BODY_BYTES, b' ');
    assert!(Envelope::parse_json(&json).is_ok());
    json.push(b' ');
    assert_eq!(Envelope::parse_json(&json), Err(ApiError::TooLarge));
    assert_eq!(
        Envelope::parse_json(&vec![b'x'; MAX_API_BODY_BYTES + 1]),
        Err(ApiError::TooLarge)
    );
}
