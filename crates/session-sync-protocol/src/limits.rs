pub const IDENTIFIER_BYTES: usize = 16;
pub const IDENTIFIER_TEXT_LEN: usize = 22;
pub const SECRET_BYTES: usize = 32;
pub const SECRET_TEXT_LEN: usize = 43;
pub const NONCE_BYTES: usize = 24;
pub const NONCE_TEXT_LEN: usize = 32;
pub const MAX_HOST_LABEL_BYTES: usize = 64;
pub const MAX_SESSION_NAME_BYTES: usize = 255;
pub const MAX_ENDPOINT_TICKET_BYTES: usize = 4_096;
pub const MAX_SESSIONS: usize = 256;
pub const MAX_SESSION_ACCESS_DESCRIPTOR_BYTES: usize = 65_536;
pub const MAX_CIPHERTEXT_BYTES: usize = 65_792;
pub const MAX_CIPHERTEXT_TEXT_LEN: usize = (MAX_CIPHERTEXT_BYTES * 4).div_ceil(3);
pub const MAX_API_BODY_BYTES: usize = 98_304;
pub const MAX_BUNDLE_BYTES: usize = 768;
pub const MAX_BUNDLE_ENCODED_BYTES: usize = (MAX_BUNDLE_BYTES * 4).div_ceil(3);
pub const MAX_LIVE_RECORDS: usize = 128;
pub const MAX_AGGREGATE_HEADER_BYTES: usize = 16_384;
pub const MAX_HEADER_FIELD_BYTES: usize = 8_192;

pub fn validate_host_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_HOST_LABEL_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub fn validate_session_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_SESSION_NAME_BYTES
        && !value
            .chars()
            .any(|character| character == '/' || character.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_names_accept_unicode_whose_utf8_contains_control_range_bytes() {
        for value in ["euro-€", "rocket-🚀"] {
            assert!(validate_session_name(value), "rejected {value:?}");
        }
    }

    #[test]
    fn session_names_reject_actual_control_characters() {
        for value in ["line\nbreak", "delete\u{7f}", "next\u{0085}line", "host/session"] {
            assert!(!validate_session_name(value), "accepted {value:?}");
        }
    }
}
