#![forbid(unsafe_code)]

//! Browser-facing, ephemeral client for the encrypted session-sync catalog.

use std::{collections::BTreeMap, fmt, str::FromStr as _};

use attached_session_sync_protocol::{
    account::{AccountBundle, AccountId, ApiKeyScope, ApiToken, RecordId},
    api::{Envelope as ApiEnvelope, parse_live_record_index},
    canonical::HerdrVersion as SessionAccessHerdrVersion,
    crypto::{
        Envelope as CryptoEnvelope, OpenedSessionAccessDescriptor, VerificationContext,
        open_session_access_descriptor_cursorless,
    },
};
use attached_tunnel_protocol::CapabilitySecret;
use chrono::{DateTime, Utc};
use iroh_tickets::endpoint::EndpointTicket;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const BROWSER_HERDR_VERSION: SessionAccessHerdrVersion = SessionAccessHerdrVersion::new(0, 7, 5);
const PROTOCOL_17_MINIMUM_PATCH: u16 = 4;

#[derive(Debug)]
enum SyncError {
    InvalidBundle,
    InvalidIndex,
    RefreshInProgress,
    NoRefresh,
    UnknownRecord,
    RevisionMismatch,
    InvalidEnvelope,
    RejectedSessionAccessDescriptor(String),
    IncompatibleProtocol,
    InvalidTime,
    SessionUnavailable,
    InvalidEndpoint,
    Encoding,
}

impl fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBundle => "invalid account bundle",
            Self::InvalidIndex => "invalid synchronized record index",
            Self::RefreshInProgress => "a synchronization refresh is already in progress",
            Self::NoRefresh => "no synchronization refresh is in progress",
            Self::UnknownRecord => "synchronized record is not in the current index",
            Self::RevisionMismatch => "synchronized record changed while refreshing",
            Self::InvalidEnvelope => "invalid synchronized record envelope",
            Self::RejectedSessionAccessDescriptor(reason) => {
                return write!(formatter, "session access descriptor rejected: {reason}");
            }
            Self::IncompatibleProtocol => {
                "synchronized host does not support Herdr TUI protocol 17"
            }
            Self::InvalidTime => "invalid browser clock",
            Self::SessionUnavailable => "synchronized session is unavailable",
            Self::InvalidEndpoint => "synchronized endpoint is invalid",
            Self::Encoding => "could not encode synchronized session data",
        })
    }
}

impl std::error::Error for SyncError {}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Credentials {
    api_token: [u8; 32],
    account_root_key: [u8; 32],
    consumer_identity_secret: Zeroizing<[u8; 32]>,
}

struct CatalogRecord {
    record_id: RecordId,
    service_revision: u64,
    host_id: String,
    host_label: String,
    expires_at: DateTime<Utc>,
    endpoint_ticket: String,
    endpoint_identity: [u8; 32],
    attach_capability: CapabilitySecret,
    herdr_version: [u16; 3],
    sessions: Vec<String>,
}

impl CatalogRecord {
    fn from_opened(
        record_id: RecordId,
        service_revision: u64,
        opened: &OpenedSessionAccessDescriptor,
    ) -> Result<Self, SyncError> {
        let descriptor = opened.descriptor();
        let version = descriptor.herdr_version();
        if version.major == 0 && version.minor == 7 && version.patch < PROTOCOL_17_MINIMUM_PATCH {
            return Err(SyncError::IncompatibleProtocol);
        }
        let endpoint = EndpointTicket::from_str(descriptor.endpoint_ticket())
            .map_err(|_| SyncError::InvalidEndpoint)?;
        Ok(Self {
            record_id,
            service_revision,
            host_id: endpoint.endpoint_addr().id.to_string(),
            host_label: descriptor.host_label().to_owned(),
            expires_at: descriptor.expires_at(),
            endpoint_ticket: descriptor.endpoint_ticket().to_owned(),
            endpoint_identity: descriptor.endpoint_identity(),
            attach_capability: CapabilitySecret::from_bytes(descriptor.attach_capability_bytes()),
            herdr_version: [version.major, version.minor, version.patch],
            sessions: descriptor.sessions().to_vec(),
        })
    }
}

#[derive(Serialize)]
struct RefreshPlan {
    records: Vec<RefreshRecord>,
}

#[derive(Serialize)]
struct RefreshRecord {
    record_id: String,
    revision: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
struct BrowserSession {
    record_id: String,
    host_id: String,
    host_label: String,
    session: String,
    herdr_version: [u16; 3],
    expires_at: String,
}

/// One selected session's connection parameters, transferred without a secret string.
#[derive(Zeroize, ZeroizeOnDrop)]
#[wasm_bindgen]
pub struct BrowserConnectionTarget {
    endpoint_ticket: String,
    session: String,
    capability: CapabilitySecret,
    consumer_identity_secret: Zeroizing<[u8; 32]>,
}

#[wasm_bindgen]
impl BrowserConnectionTarget {
    #[wasm_bindgen(getter)]
    pub fn endpoint_ticket(&self) -> String {
        self.endpoint_ticket.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn session(&self) -> String {
        self.session.clone()
    }

    /// Moves a copy into JavaScript and clears the Rust-owned capability.
    pub fn take_capability(&mut self) -> Vec<u8> {
        let capability = self.capability.to_bytes().to_vec();
        self.capability.zeroize();
        capability
    }

    /// Moves a copy into JavaScript and clears the Rust-owned Iroh identity.
    pub fn take_consumer_identity(&mut self) -> Vec<u8> {
        let secret = self.consumer_identity_secret.to_vec();
        self.consumer_identity_secret.zeroize();
        secret
    }
}

struct SyncClientCore {
    service_origin: String,
    account_id: AccountId,
    credentials: Credentials,
    records: BTreeMap<RecordId, CatalogRecord>,
    pending_index: Option<BTreeMap<RecordId, u64>>,
}

impl SyncClientCore {
    fn from_bundle(bundle_text: &str) -> Result<Self, SyncError> {
        let bundle = match AccountBundle::parse(bundle_text.as_bytes())
            .map_err(|_| SyncError::InvalidBundle)?
        {
            AccountBundle::Scoped(bundle) => bundle,
            AccountBundle::Owner(_) => return Err(SyncError::InvalidBundle),
        };
        if bundle.api_key_scope() != ApiKeyScope::Download {
            return Err(SyncError::InvalidBundle);
        }
        let consumer_identity_secret = Zeroizing::new(
            *bundle
                .consumer_identity_secret()
                .ok_or(SyncError::InvalidBundle)?
                .as_bytes(),
        );
        Ok(
            bundle.consume(|origin, account_id, api_token, account_root_key| Self {
                service_origin: origin.as_str().to_owned(),
                account_id,
                credentials: Credentials {
                    api_token: *api_token,
                    account_root_key: *account_root_key,
                    consumer_identity_secret,
                },
                records: BTreeMap::new(),
                pending_index: None,
            }),
        )
    }

    fn bearer_value(&self) -> String {
        let token = ApiToken::from_bytes(self.credentials.api_token);
        let encoded = token.encode();
        let mut bearer = String::with_capacity(7 + encoded.len());
        bearer.push_str("Bearer ");
        bearer.push_str(&encoded);
        bearer
    }

    fn begin_refresh(&mut self, index_json: &[u8]) -> Result<String, SyncError> {
        if self.pending_index.is_some() {
            return Err(SyncError::RefreshInProgress);
        }
        let index = parse_live_record_index(index_json).map_err(|_| SyncError::InvalidIndex)?;
        let pending = index
            .records
            .iter()
            .map(|record| (record.record_id, record.revision))
            .collect::<BTreeMap<_, _>>();
        let records = pending
            .iter()
            .filter(|(record_id, revision)| {
                self.records
                    .get(record_id)
                    .is_none_or(|record| record.service_revision != **revision)
            })
            .map(|(record_id, revision)| RefreshRecord {
                record_id: record_id.encode(),
                revision: revision.to_string(),
            })
            .collect();
        self.pending_index = Some(pending);
        serde_json::to_string(&RefreshPlan { records }).map_err(|_| SyncError::Encoding)
    }

    fn accept_record(
        &mut self,
        record_text: &str,
        etag: &str,
        envelope_json: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(), SyncError> {
        let record_id = RecordId::parse(record_text).map_err(|_| SyncError::UnknownRecord)?;
        let expected_revision = *self
            .pending_index
            .as_ref()
            .ok_or(SyncError::NoRefresh)?
            .get(&record_id)
            .ok_or(SyncError::UnknownRecord)?;
        if parse_read_revision_etag(etag)? != expected_revision {
            return Err(SyncError::RevisionMismatch);
        }
        let envelope =
            ApiEnvelope::parse_json(envelope_json).map_err(|_| SyncError::InvalidEnvelope)?;
        let envelope = CryptoEnvelope::new(envelope.nonce, envelope.ciphertext)
            .map_err(|_| SyncError::InvalidEnvelope)?;
        let context = VerificationContext {
            account_id: *self.account_id.as_bytes(),
            record_id: *record_id.as_bytes(),
            now,
            local_version: BROWSER_HERDR_VERSION,
        };
        let opened = open_session_access_descriptor_cursorless(
            &envelope,
            &self.credentials.account_root_key,
            &context,
        )
        .map_err(|error| SyncError::RejectedSessionAccessDescriptor(error.to_string()))?;
        let record = CatalogRecord::from_opened(record_id, expected_revision, &opened)?;
        self.records.insert(record_id, record);
        Ok(())
    }

    fn finish_refresh(&mut self, now: DateTime<Utc>) -> Result<String, SyncError> {
        let live_records = self.pending_index.take().ok_or(SyncError::NoRefresh)?;
        self.records
            .retain(|record_id, _| live_records.contains_key(record_id));
        self.sessions_json(now)
    }

    fn abort_refresh(&mut self) {
        self.pending_index = None;
    }

    fn sessions_json(&self, now: DateTime<Utc>) -> Result<String, SyncError> {
        let sessions = self
            .records
            .values()
            .filter(|record| now < record.expires_at)
            .flat_map(|record| {
                record.sessions.iter().map(|session| BrowserSession {
                    record_id: record.record_id.encode(),
                    host_id: record.host_id.clone(),
                    host_label: record.host_label.clone(),
                    session: session.clone(),
                    herdr_version: record.herdr_version,
                    expires_at: record.expires_at.timestamp().to_string(),
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&sessions).map_err(|_| SyncError::Encoding)
    }

    fn connection_for(
        &self,
        record_text: &str,
        session: &str,
        now: DateTime<Utc>,
    ) -> Result<BrowserConnectionTarget, SyncError> {
        let record_id = RecordId::parse(record_text).map_err(|_| SyncError::SessionUnavailable)?;
        let record = self
            .records
            .get(&record_id)
            .filter(|record| {
                now < record.expires_at
                    && record.sessions.iter().any(|candidate| candidate == session)
            })
            .ok_or(SyncError::SessionUnavailable)?;
        let endpoint = EndpointTicket::from_str(&record.endpoint_ticket)
            .map_err(|_| SyncError::InvalidEndpoint)?;
        if endpoint.endpoint_addr().id.as_bytes() != &record.endpoint_identity {
            return Err(SyncError::InvalidEndpoint);
        }
        Ok(BrowserConnectionTarget {
            endpoint_ticket: record.endpoint_ticket.clone(),
            session: session.to_owned(),
            capability: CapabilitySecret::from_bytes(record.attach_capability.to_bytes()),
            consumer_identity_secret: Zeroizing::new(*self.credentials.consumer_identity_secret),
        })
    }
}

// Intermediaries may weaken a strong origin ETag when applying a content
// encoding. For read responses the opaque decimal value remains the service
// revision.
fn parse_read_revision_etag(value: &str) -> Result<u64, SyncError> {
    let value = value.strip_prefix("W/").unwrap_or(value);
    let digits = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(SyncError::RevisionMismatch)?;
    if digits.is_empty()
        || digits == "0"
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SyncError::RevisionMismatch);
    }
    let revision = digits
        .parse::<u64>()
        .map_err(|_| SyncError::RevisionMismatch)?;
    if revision > i64::MAX as u64 {
        Err(SyncError::RevisionMismatch)
    } else {
        Ok(revision)
    }
}

fn parse_now(value: f64) -> Result<DateTime<Utc>, SyncError> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > i64::MAX as f64 {
        return Err(SyncError::InvalidTime);
    }
    DateTime::from_timestamp(value as i64, 0).ok_or(SyncError::InvalidTime)
}

fn js_error(error: impl fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

/// Ephemeral synchronization account and verified catalog held in WASM memory.
#[wasm_bindgen]
pub struct BrowserSyncClient {
    core: SyncClientCore,
}

#[wasm_bindgen]
impl BrowserSyncClient {
    /// Parses an account bundle without persisting it in browser storage.
    #[wasm_bindgen(constructor)]
    pub fn new(account_bundle: String) -> Result<BrowserSyncClient, JsError> {
        let trimmed = account_bundle.trim();
        SyncClientCore::from_bundle(trimmed)
            .map(|core| Self { core })
            .map_err(js_error)
    }

    #[wasm_bindgen(getter)]
    pub fn service_origin(&self) -> String {
        self.core.service_origin.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn account_id(&self) -> String {
        self.core.account_id.to_string()
    }

    /// Returns the bearer value needed for one browser Fetch request.
    pub fn bearer_value(&self) -> String {
        self.core.bearer_value()
    }

    /// Starts a complete-index refresh and returns changed record IDs as JSON.
    pub fn begin_refresh(&mut self, index_json: &[u8]) -> Result<String, JsError> {
        self.core.begin_refresh(index_json).map_err(js_error)
    }

    /// Decrypts and verifies one record from the current complete index.
    pub fn accept_record(
        &mut self,
        record_id: &str,
        etag: &str,
        envelope_json: &[u8],
        now_seconds: f64,
    ) -> Result<(), JsError> {
        let now = parse_now(now_seconds).map_err(js_error)?;
        self.core
            .accept_record(record_id, etag, envelope_json, now)
            .map_err(js_error)
    }

    /// Commits index deletions and returns all unexpired sessions as JSON.
    pub fn finish_refresh(&mut self, now_seconds: f64) -> Result<String, JsError> {
        let now = parse_now(now_seconds).map_err(js_error)?;
        self.core.finish_refresh(now).map_err(js_error)
    }

    /// Cancels an incomplete refresh without deleting cached verified records.
    pub fn abort_refresh(&mut self) {
        self.core.abort_refresh();
    }

    /// Returns cached, unexpired sessions without contacting the service.
    pub fn sessions(&self, now_seconds: f64) -> Result<String, JsError> {
        let now = parse_now(now_seconds).map_err(js_error)?;
        self.core.sessions_json(now).map_err(js_error)
    }

    /// Returns connection parameters only after the user selects a verified session.
    pub fn connection_for(
        &self,
        record_id: &str,
        session: &str,
        now_seconds: f64,
    ) -> Result<BrowserConnectionTarget, JsError> {
        let now = parse_now(now_seconds).map_err(js_error)?;
        self.core
            .connection_for(record_id, session, now)
            .map_err(js_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attached_session_sync_protocol::{
        account::{
            AccountRootKey, AuthorizedConsumerIdentity, ConsumerIdentitySecret,
            ScopedAccountBundle, ServiceOrigin,
        },
        api::{Envelope as ApiEnvelope, LiveRecordIndex, LiveRecordIndexEntry},
        canonical::{AttachedVersion as SessionAccessAttachedVersion, SessionAccessDescriptor},
        crypto::seal_session_access_descriptor,
    };

    const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";
    const ENDPOINT_ID: [u8; 32] = [
        0xae, 0x58, 0xff, 0x88, 0x33, 0x24, 0x1a, 0xc8, 0x2d, 0x6f, 0xf7, 0x61, 0x10, 0x46, 0xed,
        0x67, 0xb5, 0x07, 0x2d, 0x14, 0x2c, 0x58, 0x8d, 0x00, 0x63, 0xe9, 0x42, 0xd9, 0xa7, 0x55,
        0x02, 0xb6,
    ];

    fn timestamp(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).expect("fixture timestamp")
    }

    fn fixture_bundle() -> String {
        AccountBundle::Scoped(
            ScopedAccountBundle::from_download_parts(
                ServiceOrigin::parse("https://sync.example").unwrap(),
                AccountId::parse("01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2").unwrap(),
                ApiToken::from_bytes([3; 32]),
                AccountRootKey::from_bytes([8; 32]),
                ConsumerIdentitySecret::from_bytes([9; 32]),
            )
            .unwrap(),
        )
        .encode()
    }

    #[test]
    fn publish_bundle_is_rejected_by_the_browser_client() {
        let bundle = AccountBundle::Scoped(
            ScopedAccountBundle::from_parts(
                ServiceOrigin::parse("https://sync.example").unwrap(),
                AccountId::parse("01890f9e-7b3a-7cc2-98c8-4dc0cbd2bbf2").unwrap(),
                ApiKeyScope::Publish,
                ApiToken::from_bytes([7; 32]),
                AccountRootKey::from_bytes([8; 32]),
                Some(AuthorizedConsumerIdentity::from_bytes([9; 32])),
            )
            .unwrap(),
        )
        .encode();

        assert!(matches!(
            SyncClientCore::from_bundle(&bundle),
            Err(SyncError::InvalidBundle)
        ));
    }

    #[test]
    fn abandoned_connection_targets_zeroize_private_material_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<BrowserConnectionTarget>();
    }

    #[test]
    fn complete_refresh_opens_sessions_and_builds_a_connection_target() {
        let bundle = fixture_bundle();
        let mut client = SyncClientCore::from_bundle(&bundle).unwrap();
        let record_id = RecordId::from_bytes([4; 16]);
        let index = LiveRecordIndex::new(vec![LiveRecordIndexEntry {
            record_id,
            revision: 1,
        }])
        .unwrap();
        let plan = client
            .begin_refresh(&serde_json::to_vec(&index).unwrap())
            .unwrap();
        assert!(plan.contains(&record_id.encode()));

        let descriptor = SessionAccessDescriptor::new(
            "office".into(),
            timestamp(1_700_000_000),
            timestamp(1_700_000_300),
            ENDPOINT.into(),
            CapabilitySecret::from_bytes([6; 32]),
            SessionAccessAttachedVersion::new(0, 2, 0),
            SessionAccessHerdrVersion::new(0, 7, 5),
            vec!["alpha".into(), "build".into()],
        )
        .unwrap();
        let encrypted = seal_session_access_descriptor(
            &descriptor,
            &[8; 32],
            client.account_id.as_bytes(),
            record_id.as_bytes(),
        )
        .unwrap();
        let envelope =
            ApiEnvelope::new(*encrypted.nonce(), encrypted.ciphertext().to_vec()).unwrap();
        client
            .accept_record(
                &record_id.encode(),
                "W/\"1\"",
                &serde_json::to_vec(&envelope).unwrap(),
                timestamp(1_700_000_100),
            )
            .unwrap();

        let sessions = client.finish_refresh(timestamp(1_700_000_100)).unwrap();
        let sessions: Vec<BrowserSession> = serde_json::from_str(&sessions).unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].host_label, "office");
        assert_eq!(sessions[0].session, "alpha");

        let mut target = client
            .connection_for(&record_id.encode(), "alpha", timestamp(1_700_000_100))
            .unwrap();
        assert_eq!(target.endpoint_ticket, ENDPOINT);
        assert_eq!(target.session, "alpha");
        assert_eq!(target.take_capability(), [6; 32]);
        assert_eq!(target.capability.to_bytes(), [0; 32]);
        assert_eq!(target.take_consumer_identity(), [9; 32]);
        assert_eq!(target.consumer_identity_secret.as_ref(), &[0; 32]);
    }

    #[test]
    fn weak_read_etag_must_match_the_index_revision() {
        let bundle = fixture_bundle();
        let mut client = SyncClientCore::from_bundle(&bundle).unwrap();
        let record_id = RecordId::from_bytes([4; 16]);
        let index = LiveRecordIndex::new(vec![LiveRecordIndexEntry {
            record_id,
            revision: 1,
        }])
        .unwrap();
        client
            .begin_refresh(&serde_json::to_vec(&index).unwrap())
            .unwrap();

        let error = client
            .accept_record(
                &record_id.encode(),
                "W/\"2\"",
                b"{}",
                timestamp(1_700_000_100),
            )
            .unwrap_err();
        assert!(matches!(error, SyncError::RevisionMismatch));
    }

    #[test]
    fn unchanged_revisions_are_not_downloaded_again_and_index_absence_commits() {
        let bundle = fixture_bundle();
        let mut client = SyncClientCore::from_bundle(&bundle).unwrap();
        let record_id = RecordId::from_bytes([4; 16]);
        client.records.insert(
            record_id,
            CatalogRecord {
                record_id,
                service_revision: 9,
                host_id: "host".into(),
                host_label: "office".into(),
                expires_at: timestamp(1_800_000_000),
                endpoint_ticket: ENDPOINT.into(),
                endpoint_identity: ENDPOINT_ID,
                attach_capability: CapabilitySecret::from_bytes([6; 32]),
                herdr_version: [0, 7, 5],
                sessions: vec!["alpha".into()],
            },
        );
        let index = LiveRecordIndex::new(vec![LiveRecordIndexEntry {
            record_id,
            revision: 9,
        }])
        .unwrap();
        assert_eq!(
            client
                .begin_refresh(&serde_json::to_vec(&index).unwrap())
                .unwrap(),
            r#"{"records":[]}"#
        );
        client.finish_refresh(timestamp(1)).unwrap();
        assert!(client.records.contains_key(&record_id));

        let empty = LiveRecordIndex::new(Vec::new()).unwrap();
        client
            .begin_refresh(&serde_json::to_vec(&empty).unwrap())
            .unwrap();
        client.finish_refresh(timestamp(1)).unwrap();
        assert!(client.records.is_empty());
    }

    #[test]
    fn read_etags_and_browser_time_are_canonical_and_bounded() {
        assert_eq!(parse_read_revision_etag("\"42\"").unwrap(), 42);
        assert_eq!(parse_read_revision_etag("W/\"42\"").unwrap(), 42);
        for invalid in [
            "42",
            "w/\"42\"",
            "W/42",
            "W/W/\"42\"",
            "\"0\"",
            "\"01\"",
            "\"-1\"",
        ] {
            assert!(parse_read_revision_etag(invalid).is_err());
        }
        assert_eq!(parse_now(42.0).unwrap(), timestamp(42));
        assert!(parse_now(f64::NAN).is_err());
        assert!(parse_now(1.5).is_err());
    }
}
