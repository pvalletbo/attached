use std::{fmt, marker::PhantomData};

use crate::{
    account::{AccountId, ApiToken, RecordId},
    limits::{
        MAX_API_BODY_BYTES, MAX_CIPHERTEXT_BYTES, MAX_CIPHERTEXT_TEXT_LEN, MAX_LIVE_RECORDS,
        NONCE_BYTES, NONCE_TEXT_LEN,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
};

pub const HEALTH_PATH: &str = "/healthz";
pub const ACCOUNTS_PATH: &str = "/v1/accounts";
pub const RECORD_INDEX_ROUTE: &str = "/v1/accounts/{account_id}/records";
pub const RECORDS_ROUTE: &str = "/v1/accounts/{account_id}/records/{record_id}";
pub const ALLOW_HEALTH: &str = "GET";
pub const ALLOW_ACCOUNTS: &str = "POST";
pub const ALLOW_RECORD_INDEX: &str = "GET";
pub const ALLOW_RECORDS: &str = "GET, PUT";
pub const ALLOW_CURSORLESS_RECORDS: &str = ALLOW_RECORDS;
pub const CACHE_CONTROL_VALUE: &str = "no-store";
pub const AUTHENTICATE_VALUE: &str = "Bearer realm=\"herdr-sync-v1\"";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const HEADER_ETAG: &str = "ETag";
pub const HEADER_RETRY_AFTER: &str = "Retry-After";
pub const STATUS_OK: u16 = 200;
pub const STATUS_CREATED: u16 = 201;
pub const STATUS_NO_CONTENT: u16 = 204;
pub const STATUS_BAD_REQUEST: u16 = 400;
pub const STATUS_UNAUTHORIZED: u16 = 401;
pub const STATUS_NOT_FOUND: u16 = 404;
pub const STATUS_METHOD_NOT_ALLOWED: u16 = 405;
pub const STATUS_PAYLOAD_TOO_LARGE: u16 = 413;
pub const STATUS_UNSUPPORTED_MEDIA_TYPE: u16 = 415;
pub const STATUS_TOO_MANY_REQUESTS: u16 = 429;
pub const STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE: u16 = 431;
pub const STATUS_UNAVAILABLE: u16 = 503;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiError {
    InvalidRequest,
    TooLarge,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    TooLarge,
    QuotaExceeded,
    RateLimited,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDto {
    pub code: ErrorCode,
}
impl ErrorDto {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

pub struct CreateAccountResponse {
    pub account_id: AccountId,
    publish_api_token: ApiToken,
    download_api_token: ApiToken,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccountResponseWire<'a> {
    account_id: AccountId,
    publish_api_token: &'a str,
    download_api_token: &'a str,
}

impl fmt::Debug for CreateAccountResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateAccountResponse")
            .field("account_id", &self.account_id)
            .field("api_tokens", &"[REDACTED]")
            .finish()
    }
}

impl CreateAccountResponse {
    pub fn new(
        account_id: AccountId,
        publish_api_token: ApiToken,
        download_api_token: ApiToken,
    ) -> Result<Self, ApiError> {
        if !account_id.is_uuid_v7()
            || publish_api_token.service_hash() == download_api_token.service_hash()
        {
            return Err(ApiError::InvalidRequest);
        }
        Ok(Self {
            account_id,
            publish_api_token,
            download_api_token,
        })
    }

    pub fn parse_json(input: &[u8]) -> Result<Self, ApiError> {
        parse_bounded(input)
    }

    pub fn into_parts(self) -> (AccountId, ApiToken, ApiToken) {
        (
            self.account_id,
            self.publish_api_token,
            self.download_api_token,
        )
    }
}

impl Serialize for CreateAccountResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let publish_token = self.publish_api_token.encode();
        let download_token = self.download_api_token.encode();
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("account_id", &self.account_id)?;
        map.serialize_entry("publish_api_token", &publish_token)?;
        map.serialize_entry("download_api_token", &download_token)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for CreateAccountResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CreateAccountResponseWire::deserialize(deserializer)?;
        let publish_token = ApiToken::parse_bare(wire.publish_api_token)
            .map_err(|_| de::Error::custom("invalid publish API token"))?;
        let download_token = ApiToken::parse_bare(wire.download_api_token)
            .map_err(|_| de::Error::custom("invalid download API token"))?;
        Self::new(wire.account_id, publish_token, download_token)
            .map_err(|_| de::Error::custom("invalid account-creation response"))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Envelope {
    pub envelope_version: u16,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}
impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("envelope_version", &self.envelope_version)
            .field("nonce", &"[OPAQUE]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}
impl Envelope {
    pub fn new(nonce: [u8; NONCE_BYTES], ciphertext: Vec<u8>) -> Result<Self, ApiError> {
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(ApiError::TooLarge);
        }
        Ok(Self {
            envelope_version: 1,
            nonce,
            ciphertext,
        })
    }
    pub fn parse_json(input: &[u8]) -> Result<Self, ApiError> {
        parse_bounded(input)
    }
}
impl Serialize for Envelope {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let nonce = encode_base64(&self.nonce);
        let ciphertext = encode_base64(&self.ciphertext);
        let mut map = s.serialize_map(Some(3))?;
        map.serialize_entry("envelope_version", &self.envelope_version)?;
        map.serialize_entry("nonce", nonce.as_str())?;
        map.serialize_entry("ciphertext", ciphertext.as_str())?;
        map.end()
    }
}
impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            EnvelopeVersion,
            Nonce,
            Ciphertext,
        }
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Envelope;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("envelope object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Envelope, A::Error> {
                let (mut version, mut nonce, mut ciphertext) = (None, None, None);
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::EnvelopeVersion => {
                            duplicate(&version, "envelope_version")?;
                            version = Some(map.next_value::<u16>()?);
                        }
                        Field::Nonce => {
                            duplicate(&nonce, "nonce")?;
                            let text = map.next_value_seed(BorrowedStrSeed::<NONCE_TEXT_LEN>)?;
                            let decoded = decode_fixed::<NONCE_BYTES>(text)
                                .map_err(|_| de::Error::custom("invalid nonce"))?;
                            nonce = Some(decoded);
                        }
                        Field::Ciphertext => {
                            duplicate(&ciphertext, "ciphertext")?;
                            let text =
                                map.next_value_seed(TooLargeStrSeed::<MAX_CIPHERTEXT_TEXT_LEN>)?;
                            ciphertext = Some(
                                decode_vec(text, MAX_CIPHERTEXT_BYTES)
                                    .map_err(|_| de::Error::custom("invalid ciphertext"))?,
                            );
                        }
                    }
                }
                if version != Some(1) {
                    return Err(de::Error::custom("invalid envelope version"));
                }
                Ok(Envelope {
                    envelope_version: 1,
                    nonce: nonce.ok_or_else(|| de::Error::missing_field("nonce"))?,
                    ciphertext: ciphertext.ok_or_else(|| de::Error::missing_field("ciphertext"))?,
                })
            }
        }
        d.deserialize_struct("Envelope", &["envelope_version", "nonce", "ciphertext"], V)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveRecordIndexEntry {
    pub record_id: RecordId,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LiveRecordIndex {
    pub records: Vec<LiveRecordIndexEntry>,
}

impl LiveRecordIndex {
    pub fn new(records: Vec<LiveRecordIndexEntry>) -> Result<Self, ApiError> {
        let index = Self { records };
        index.validate()?;
        Ok(index)
    }

    fn validate(&self) -> Result<(), ApiError> {
        if self.records.len() > MAX_LIVE_RECORDS {
            return Err(ApiError::InvalidRequest);
        }
        if self.records.iter().any(|record| record.revision == 0) {
            return Err(ApiError::InvalidRequest);
        }
        if self
            .records
            .windows(2)
            .any(|records| records[0].record_id >= records[1].record_id)
        {
            return Err(ApiError::InvalidRequest);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for LiveRecordIndex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            records: LiveRecordEntries,
        }

        let wire = Wire::deserialize(d)?;
        let index = Self {
            records: wire.records.0,
        };
        index
            .validate()
            .map_err(|_| de::Error::custom("invalid live-record index"))?;
        Ok(index)
    }
}

struct LiveRecordEntries(Vec<LiveRecordIndexEntry>);
impl<'de> Deserialize<'de> for LiveRecordEntries {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        BoundedVecSeed::<LiveRecordIndexEntry, MAX_LIVE_RECORDS>(PhantomData)
            .deserialize(d)
            .map(Self)
    }
}

pub fn parse_live_record_index(input: &[u8]) -> Result<LiveRecordIndex, ApiError> {
    parse_bounded(input)
}

struct BorrowedStrSeed<const MAX: usize>;
impl<'de, const MAX: usize> DeserializeSeed<'de> for BorrowedStrSeed<MAX> {
    type Value = &'de str;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<const M: usize>;
        impl<'de, const M: usize> Visitor<'de> for V<M> {
            type Value = &'de str;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "borrowed string of at most {M} bytes")
            }
            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                if v.len() > M {
                    Err(E::invalid_length(v.len(), &self))
                } else {
                    Ok(v)
                }
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Err(E::custom("escaped or copied string forbidden"))
            }
            fn visit_string<E: de::Error>(self, _: String) -> Result<Self::Value, E> {
                Err(E::custom("allocated string forbidden"))
            }
        }
        d.deserialize_str(V::<MAX>)
    }
}

struct TooLargeStrSeed<const MAX: usize>;
impl<'de, const MAX: usize> DeserializeSeed<'de> for TooLargeStrSeed<MAX> {
    type Value = &'de str;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<const M: usize>;
        impl<'de, const M: usize> Visitor<'de> for V<M> {
            type Value = &'de str;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "borrowed string of at most {M} bytes")
            }
            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                if v.len() > M {
                    Err(E::custom("ciphertext text exceeds limit"))
                } else {
                    Ok(v)
                }
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Err(E::custom("escaped or copied string forbidden"))
            }
            fn visit_string<E: de::Error>(self, _: String) -> Result<Self::Value, E> {
                Err(E::custom("allocated string forbidden"))
            }
        }
        d.deserialize_str(V::<MAX>)
    }
}

struct BoundedVecSeed<T, const MAX: usize>(PhantomData<T>);
impl<'de, T: Deserialize<'de>, const MAX: usize> DeserializeSeed<'de> for BoundedVecSeed<T, MAX> {
    type Value = Vec<T>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V<T, const M: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const M: usize> Visitor<'de> for V<T, M> {
            type Value = Vec<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "at most {M} items")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
                if seq.size_hint().is_some_and(|n| n > M) {
                    return Err(de::Error::custom("too many items"));
                }
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(M));
                while out.len() < M {
                    match seq.next_element()? {
                        Some(value) => out.push(value),
                        None => return Ok(out),
                    }
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("too many items"));
                }
                Ok(out)
            }
        }
        d.deserialize_seq(V::<T, MAX>(PhantomData))
    }
}

fn duplicate<T, E: de::Error>(slot: &Option<T>, name: &'static str) -> Result<(), E> {
    if slot.is_some() {
        Err(E::duplicate_field(name))
    } else {
        Ok(())
    }
}

fn parse_bounded<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T, ApiError> {
    if input.len() > MAX_API_BODY_BYTES {
        return Err(ApiError::TooLarge);
    }
    if let Ok(value) = deserialize_complete(input) {
        return Ok(value);
    }
    if normalize_oversized_ciphertexts(input)
        .is_some_and(|normalized| deserialize_complete::<T>(&normalized).is_ok())
    {
        return Err(ApiError::TooLarge);
    }
    Err(ApiError::InvalidRequest)
}

fn deserialize_complete<T: for<'de> Deserialize<'de>>(
    input: &[u8],
) -> Result<T, serde_json::Error> {
    let mut d = serde_json::Deserializer::from_slice(input);
    let value = T::deserialize(&mut d)?;
    d.end()?;
    Ok(value)
}

fn normalize_oversized_ciphertexts(input: &[u8]) -> Option<Vec<u8>> {
    const KEY: &[u8] = b"\"ciphertext\"";
    let mut ranges = Vec::new();
    let mut search_from = 0;
    while search_from < input.len() {
        let Some(relative) = input[search_from..]
            .windows(KEY.len())
            .position(|window| window == KEY)
        else {
            break;
        };
        let key_start = search_from.checked_add(relative)?;
        let mut cursor = key_start.checked_add(KEY.len())?;
        while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if input.get(cursor) != Some(&b':') {
            search_from = key_start + 1;
            continue;
        }
        cursor += 1;
        while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if input.get(cursor) != Some(&b'\"') {
            search_from = key_start + 1;
            continue;
        }
        let value_start = cursor + 1;
        cursor = value_start;
        while let Some(byte) = input.get(cursor) {
            match byte {
                b'\\' => break,
                b'\"' => {
                    if cursor - value_start > MAX_CIPHERTEXT_TEXT_LEN {
                        ranges.push(value_start..cursor);
                    }
                    break;
                }
                _ => cursor += 1,
            }
        }
        search_from = cursor.saturating_add(1);
    }
    if ranges.is_empty() {
        return None;
    }
    let mut normalized = Vec::with_capacity(input.len());
    normalized.extend_from_slice(input);
    for range in ranges.into_iter().rev() {
        normalized.drain(range);
    }
    Some(normalized)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], ApiError> {
    let mut decoded = [0u8; N];
    let n = URL_SAFE_NO_PAD
        .decode_slice(value.as_bytes(), &mut decoded)
        .map_err(|_| ApiError::InvalidRequest)?;
    if n != N || !canonical_matches(value, &decoded) {
        return Err(ApiError::InvalidRequest);
    }
    Ok(decoded)
}

fn decode_vec(value: &str, max: usize) -> Result<Vec<u8>, ApiError> {
    let upper = value
        .len()
        .checked_mul(3)
        .map(|n| n / 4)
        .ok_or(ApiError::TooLarge)?;
    if upper > max {
        return Err(ApiError::TooLarge);
    }
    let mut decoded = vec![0u8; upper];
    let n = URL_SAFE_NO_PAD
        .decode_slice(value.as_bytes(), decoded.as_mut_slice())
        .map_err(|_| ApiError::InvalidRequest)?;
    decoded.truncate(n);
    if !canonical_matches(value, &decoded) {
        return Err(ApiError::InvalidRequest);
    }
    Ok(decoded)
}

fn canonical_matches(value: &str, bytes: &[u8]) -> bool {
    encode_base64(bytes).as_bytes() == value.as_bytes()
}

fn encode_base64(bytes: &[u8]) -> String {
    let len = bytes.len().saturating_mul(4).saturating_add(2) / 3;
    let mut out = String::with_capacity(len);
    URL_SAFE_NO_PAD.encode_string(bytes, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_record_index_is_bounded_sorted_and_strict() {
        let entries = (0..MAX_LIVE_RECORDS)
            .map(|index| {
                let mut bytes = [0_u8; 16];
                bytes[14..].copy_from_slice(&(index as u16).to_be_bytes());
                LiveRecordIndexEntry {
                    record_id: RecordId::from_bytes(bytes),
                    revision: index as u64 + 1,
                }
            })
            .collect::<Vec<_>>();
        let index = LiveRecordIndex::new(entries.clone()).expect("maximum index");
        let encoded = serde_json::to_vec(&index).expect("encode index");
        assert_eq!(
            parse_live_record_index(&encoded).expect("parse index"),
            index
        );

        let mut oversized = entries.clone();
        oversized.push(LiveRecordIndexEntry {
            record_id: RecordId::from_bytes([0xff; 16]),
            revision: 1,
        });
        assert!(LiveRecordIndex::new(oversized).is_err());

        let mut unsorted = entries;
        unsorted.swap(0, 1);
        assert!(LiveRecordIndex::new(unsorted).is_err());
        assert!(parse_live_record_index(br#"{"records":[],"unknown":0}"#).is_err());
    }
}
