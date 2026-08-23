use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use url::{Host, Url};
use uuid::{Uuid, Variant, Version};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::limits::{
    IDENTIFIER_TEXT_LEN, MAX_BUNDLE_BYTES, MAX_BUNDLE_ENCODED_BYTES, SECRET_TEXT_LEN,
};

const API_TOKEN_HASH_DOMAIN: &[u8] = b"herdr/session-sync/api-token/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountError {
    InvalidIdentifier,
    InvalidBearer,
    InvalidAuthorization,
    InvalidOrigin,
    InvalidBundle,
}

/// The synchronization-service operations authorized by an account API key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApiKeyScope {
    /// May create, replace, and delete encrypted session records, but may not read them.
    Publish = 1,
    /// May list and download encrypted session records, but may not mutate them.
    Download = 2,
}

impl TryFrom<u8> for ApiKeyScope {
    type Error = AccountError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Publish),
            2 => Ok(Self::Download),
            _ => Err(AccountError::InvalidBundle),
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId(Uuid);

impl AccountId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    pub fn parse(value: &str) -> Result<Self, AccountError> {
        if value.len() != 36 {
            return Err(AccountError::InvalidIdentifier);
        }
        let uuid = Uuid::parse_str(value).map_err(|_| AccountError::InvalidIdentifier)?;
        if uuid.hyphenated().to_string() != value
            || uuid.get_version() != Some(Version::SortRand)
            || uuid.get_variant() != Variant::RFC4122
        {
            return Err(AccountError::InvalidIdentifier);
        }
        Ok(Self(uuid))
    }

    pub fn is_uuid_v7(&self) -> bool {
        self.0.get_version() == Some(Version::SortRand) && self.0.get_variant() == Variant::RFC4122
    }
}

impl From<Uuid> for AccountId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountId")
    }
}
impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_hyphenated(), f)
    }
}
impl Serialize for AccountId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buffer = Uuid::encode_buffer();
        serializer.serialize_str(self.0.hyphenated().encode_lower(&mut buffer))
    }
}
impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <&str>::deserialize(deserializer)?;
        Self::parse(value).map_err(|_| de::Error::custom("invalid UUIDv7 account ID"))
    }
}

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
            pub fn parse(value: &str) -> Result<Self, AccountError> {
                if value.len() != IDENTIFIER_TEXT_LEN || value.as_bytes().contains(&b'=') {
                    return Err(AccountError::InvalidIdentifier);
                }
                let decoded = URL_SAFE_NO_PAD
                    .decode(value.as_bytes())
                    .map_err(|_| AccountError::InvalidIdentifier)?;
                let bytes: [u8; 16] = decoded
                    .try_into()
                    .map_err(|_| AccountError::InvalidIdentifier)?;
                if URL_SAFE_NO_PAD.encode(bytes) != value {
                    return Err(AccountError::InvalidIdentifier);
                }
                Ok(Self(bytes))
            }
            pub fn encode(&self) -> String {
                URL_SAFE_NO_PAD.encode(self.0)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.encode())
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.encode())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let value = <&str>::deserialize(d)?;
                Self::parse(value).map_err(|_| de::Error::custom("invalid identifier"))
            }
        }
    };
}
identifier!(RecordId);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ApiToken([u8; 32]);

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiToken([REDACTED])")
    }
}

impl ApiToken {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn parse_bare(value: &str) -> Result<Self, AccountError> {
        decode_api_token(value.as_bytes())
    }
    pub fn parse_authorization(values: &[&[u8]]) -> Result<Self, AccountError> {
        if values.len() != 1 {
            return Err(AccountError::InvalidAuthorization);
        }
        let value = values[0];
        if value.len() != 50 || !value.starts_with(b"Bearer ") {
            return Err(AccountError::InvalidAuthorization);
        }
        let text =
            std::str::from_utf8(&value[7..]).map_err(|_| AccountError::InvalidAuthorization)?;
        Self::parse_bare(text).map_err(|_| AccountError::InvalidAuthorization)
    }
    pub fn encode(&self) -> String {
        encode_base64(&self.0)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn service_hash(&self) -> [u8; 32] {
        domain_hash(API_TOKEN_HASH_DOMAIN, &[&self.0])
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AccountRootKey([u8; 32]);
impl fmt::Debug for AccountRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountRootKey([REDACTED])")
    }
}
impl AccountRootKey {
    /// Generates an independent 256-bit account key using the operating system CSPRNG.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut())?;
        Ok(Self(*bytes))
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceOrigin(String);
impl ServiceOrigin {
    pub fn parse(value: &str) -> Result<Self, AccountError> {
        if value.is_empty() || value.len() > 253 + 8 + 6 || !value.is_ascii() {
            return Err(AccountError::InvalidOrigin);
        }
        let (https, authority) = if let Some(rest) = value.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = value.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(AccountError::InvalidOrigin);
        };
        if authority.bytes().any(|byte| {
            byte <= b' ' || byte == 0x7f || matches!(byte, b'%' | b'\\' | b'/' | b'?' | b'#' | b'@')
        }) {
            return Err(AccountError::InvalidOrigin);
        }
        let (host, port_text) = split_authority(authority)?;
        let port = port_text.map(parse_port).transpose()?;
        if matches!((https, port), (true, Some(443)) | (false, Some(80))) {
            return Err(AccountError::InvalidOrigin);
        }
        if !https && port.is_none() {
            return Err(AccountError::InvalidOrigin);
        }

        enum StrictHost {
            Dns,
            V4(Ipv4Addr),
            V6(Ipv6Addr),
        }
        let strict_host = if host.starts_with('[') {
            if !host.ends_with(']') {
                return Err(AccountError::InvalidOrigin);
            }
            let inner = &host[1..host.len() - 1];
            let ip = Ipv6Addr::from_str(inner).map_err(|_| AccountError::InvalidOrigin)?;
            if ip.to_string() != inner || ip.to_ipv4_mapped().is_some() || ip.is_unspecified() {
                return Err(AccountError::InvalidOrigin);
            }
            StrictHost::V6(ip)
        } else if host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            let ip = parse_canonical_ipv4(host)?;
            if ip.is_unspecified() {
                return Err(AccountError::InvalidOrigin);
            }
            StrictHost::V4(ip)
        } else {
            validate_dns(host)?;
            if host == "localhost" {
                return Err(AccountError::InvalidOrigin);
            }
            StrictHost::Dns
        };
        if !https
            && !matches!(strict_host, StrictHost::V4(ip) if ip == Ipv4Addr::LOCALHOST)
            && !matches!(strict_host, StrictHost::V6(ip) if ip == Ipv6Addr::LOCALHOST)
        {
            return Err(AccountError::InvalidOrigin);
        }

        let parsed = Url::parse(value).map_err(|_| AccountError::InvalidOrigin)?;
        if parsed.scheme() != if https { "https" } else { "http" }
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AccountError::InvalidOrigin);
        }
        let same_host = match (strict_host, parsed.host()) {
            (StrictHost::Dns, Some(Host::Domain(actual))) => actual == host,
            (StrictHost::V4(expected), Some(Host::Ipv4(actual))) => expected == actual,
            (StrictHost::V6(expected), Some(Host::Ipv6(actual))) => expected == actual,
            _ => false,
        };
        if !same_host || parsed.port() != port {
            return Err(AccountError::InvalidOrigin);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Serialize for ServiceOrigin {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for ServiceOrigin {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = <&str>::deserialize(d)?;
        Self::parse(value).map_err(|_| de::Error::custom("invalid origin"))
    }
}

fn split_authority(value: &str) -> Result<(&str, Option<&str>), AccountError> {
    if value.starts_with('[') {
        let end = value.find(']').ok_or(AccountError::InvalidOrigin)?;
        let host = &value[..=end];
        let rest = &value[end + 1..];
        if rest.is_empty() {
            Ok((host, None))
        } else {
            Ok((
                host,
                Some(rest.strip_prefix(':').ok_or(AccountError::InvalidOrigin)?),
            ))
        }
    } else {
        match value.split_once(':') {
            Some((host, port)) if !port.contains(':') => Ok((host, Some(port))),
            None => Ok((value, None)),
            _ => Err(AccountError::InvalidOrigin),
        }
    }
}

fn parse_port(value: &str) -> Result<u16, AccountError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(AccountError::InvalidOrigin);
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| AccountError::InvalidOrigin)?;
    if port == 0 {
        return Err(AccountError::InvalidOrigin);
    }
    Ok(port)
}

fn parse_canonical_ipv4(value: &str) -> Result<Ipv4Addr, AccountError> {
    let mut parts = value.split('.');
    for _ in 0..4 {
        let part = parts.next().ok_or(AccountError::InvalidOrigin)?;
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return Err(AccountError::InvalidOrigin);
        }
    }
    if parts.next().is_some() {
        return Err(AccountError::InvalidOrigin);
    }
    let ip = Ipv4Addr::from_str(value).map_err(|_| AccountError::InvalidOrigin)?;
    if ip.to_string() != value {
        return Err(AccountError::InvalidOrigin);
    }
    Ok(ip)
}

fn validate_dns(value: &str) -> Result<(), AccountError> {
    if value.is_empty() || value.len() > 253 || value.ends_with('.') || value.starts_with('.') {
        return Err(AccountError::InvalidOrigin);
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with("xn--")
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AccountError::InvalidOrigin);
        }
    }
    Ok(())
}

pub enum AccountBundle {
    Scoped(ScopedAccountBundle),
    Owner(OwnerAccountBundle),
}

pub struct ScopedAccountBundle {
    pub service_origin: ServiceOrigin,
    pub account_id: AccountId,
    api_key_scope: ApiKeyScope,
    api_token: ApiToken,
    account_root_key: AccountRootKey,
}

pub struct OwnerAccountBundle {
    pub service_origin: ServiceOrigin,
    pub account_id: AccountId,
    publish_api_token: ApiToken,
    download_api_token: ApiToken,
    account_root_key: AccountRootKey,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "bundle_type", rename_all = "snake_case", deny_unknown_fields)]
enum AccountBundleWire {
    Scoped {
        #[zeroize(skip)]
        service_origin: String,
        #[zeroize(skip)]
        account_id: String,
        #[zeroize(skip)]
        api_key_scope: u8,
        api_token: String,
        account_root_key: String,
    },
    Owner {
        #[zeroize(skip)]
        service_origin: String,
        #[zeroize(skip)]
        account_id: String,
        publish_api_token: String,
        download_api_token: String,
        account_root_key: String,
    },
}

impl fmt::Debug for AccountBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scoped(bundle) => bundle.fmt(f),
            Self::Owner(bundle) => bundle.fmt(f),
        }
    }
}

impl fmt::Debug for ScopedAccountBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedAccountBundle")
            .field("service_origin", &self.service_origin)
            .field("account_id", &self.account_id)
            .field("api_key_scope", &self.api_key_scope)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for OwnerAccountBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerAccountBundle")
            .field("service_origin", &self.service_origin)
            .field("account_id", &self.account_id)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

impl ScopedAccountBundle {
    pub fn from_parts(
        service_origin: ServiceOrigin,
        account_id: AccountId,
        api_key_scope: ApiKeyScope,
        api_token: ApiToken,
        account_root_key: AccountRootKey,
    ) -> Result<Self, AccountError> {
        if !account_id.is_uuid_v7() {
            return Err(AccountError::InvalidBundle);
        }
        Ok(Self {
            service_origin,
            account_id,
            api_key_scope,
            api_token,
            account_root_key,
        })
    }

    pub const fn api_key_scope(&self) -> ApiKeyScope {
        self.api_key_scope
    }

    pub fn consume<R>(
        self,
        f: impl FnOnce(&ServiceOrigin, AccountId, &[u8; 32], &[u8; 32]) -> R,
    ) -> R {
        f(
            &self.service_origin,
            self.account_id,
            &self.api_token.0,
            &self.account_root_key.0,
        )
    }
}

impl OwnerAccountBundle {
    pub fn from_parts(
        service_origin: ServiceOrigin,
        account_id: AccountId,
        publish_api_token: ApiToken,
        download_api_token: ApiToken,
        account_root_key: AccountRootKey,
    ) -> Result<Self, AccountError> {
        if !account_id.is_uuid_v7()
            || publish_api_token.service_hash() == download_api_token.service_hash()
        {
            return Err(AccountError::InvalidBundle);
        }
        Ok(Self {
            service_origin,
            account_id,
            publish_api_token,
            download_api_token,
            account_root_key,
        })
    }

    pub fn scoped(&self, scope: ApiKeyScope) -> ScopedAccountBundle {
        let api_token = match scope {
            ApiKeyScope::Publish => &self.publish_api_token,
            ApiKeyScope::Download => &self.download_api_token,
        };
        ScopedAccountBundle {
            service_origin: self.service_origin.clone(),
            account_id: self.account_id,
            api_key_scope: scope,
            api_token: ApiToken::from_bytes(api_token.0),
            account_root_key: AccountRootKey::from_bytes(self.account_root_key.0),
        }
    }

    pub fn into_scoped(self, scope: ApiKeyScope) -> ScopedAccountBundle {
        let Self {
            service_origin,
            account_id,
            publish_api_token,
            download_api_token,
            account_root_key,
        } = self;
        let api_token = match scope {
            ApiKeyScope::Publish => publish_api_token,
            ApiKeyScope::Download => download_api_token,
        };
        ScopedAccountBundle {
            service_origin,
            account_id,
            api_key_scope: scope,
            api_token,
            account_root_key,
        }
    }
}

impl AccountBundle {
    pub fn encode(&self) -> String {
        let wire = match self {
            Self::Scoped(bundle) => AccountBundleWire::Scoped {
                service_origin: bundle.service_origin.as_str().to_owned(),
                account_id: bundle.account_id.to_string(),
                api_key_scope: bundle.api_key_scope as u8,
                api_token: bundle.api_token.encode(),
                account_root_key: encode_base64(&bundle.account_root_key.0),
            },
            Self::Owner(bundle) => AccountBundleWire::Owner {
                service_origin: bundle.service_origin.as_str().to_owned(),
                account_id: bundle.account_id.to_string(),
                publish_api_token: bundle.publish_api_token.encode(),
                download_api_token: bundle.download_api_token.encode(),
                account_root_key: encode_base64(&bundle.account_root_key.0),
            },
        };
        let payload = Zeroizing::new(
            serde_json::to_vec(&wire).expect("validated account bundle serializes as JSON"),
        );
        assert!(
            payload.len() <= MAX_BUNDLE_BYTES,
            "validated account bundle fits its bounded encoding"
        );
        encode_base64(payload.as_slice())
    }

    pub fn parse(input: &[u8]) -> Result<Self, AccountError> {
        if input.is_empty() || input.len() > MAX_BUNDLE_ENCODED_BYTES {
            return Err(AccountError::InvalidBundle);
        }
        let mut decoded = Zeroizing::new(vec![0; MAX_BUNDLE_BYTES]);
        let decoded_len = URL_SAFE_NO_PAD
            .decode_slice(input, decoded.as_mut_slice())
            .map_err(|_| AccountError::InvalidBundle)?;
        decoded.truncate(decoded_len);
        let wire: AccountBundleWire =
            serde_json::from_slice(decoded.as_slice()).map_err(|_| AccountError::InvalidBundle)?;
        let bundle = match &wire {
            AccountBundleWire::Scoped {
                service_origin,
                account_id,
                api_key_scope,
                api_token,
                account_root_key,
            } => Self::Scoped(ScopedAccountBundle::from_parts(
                ServiceOrigin::parse(service_origin).map_err(|_| AccountError::InvalidBundle)?,
                AccountId::parse(account_id).map_err(|_| AccountError::InvalidBundle)?,
                ApiKeyScope::try_from(*api_key_scope)?,
                ApiToken::from_bytes(decode_bundle_secret(api_token)?),
                AccountRootKey::from_bytes(decode_bundle_secret(account_root_key)?),
            )?),
            AccountBundleWire::Owner {
                service_origin,
                account_id,
                publish_api_token,
                download_api_token,
                account_root_key,
            } => Self::Owner(OwnerAccountBundle::from_parts(
                ServiceOrigin::parse(service_origin).map_err(|_| AccountError::InvalidBundle)?,
                AccountId::parse(account_id).map_err(|_| AccountError::InvalidBundle)?,
                ApiToken::from_bytes(decode_bundle_secret(publish_api_token)?),
                ApiToken::from_bytes(decode_bundle_secret(download_api_token)?),
                AccountRootKey::from_bytes(decode_bundle_secret(account_root_key)?),
            )?),
        };
        let canonical = Zeroizing::new(bundle.encode());
        if canonical.as_bytes() != input {
            return Err(AccountError::InvalidBundle);
        }
        Ok(bundle)
    }
}

fn decode_bundle_secret(input: &str) -> Result<[u8; 32], AccountError> {
    if input.len() != SECRET_TEXT_LEN {
        return Err(AccountError::InvalidBundle);
    }
    let mut decoded = Zeroizing::new([0_u8; 32]);
    let decoded_len = URL_SAFE_NO_PAD
        .decode_slice(input.as_bytes(), decoded.as_mut())
        .map_err(|_| AccountError::InvalidBundle)?;
    let canonical = Zeroizing::new(encode_base64(decoded.as_ref()));
    if decoded_len != decoded.len() || canonical.as_str() != input {
        return Err(AccountError::InvalidBundle);
    }
    Ok(*decoded)
}

fn decode_api_token(input: &[u8]) -> Result<ApiToken, AccountError> {
    if input.len() != SECRET_TEXT_LEN
        || !input
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AccountError::InvalidBearer);
    }
    let mut decoded = Zeroizing::new([0; 32]);
    let len = URL_SAFE_NO_PAD
        .decode_slice(input, decoded.as_mut())
        .map_err(|_| AccountError::InvalidBearer)?;
    let canonical = Zeroizing::new(encode_base64(decoded.as_ref()));
    if len != decoded.len() || canonical.as_bytes() != input {
        return Err(AccountError::InvalidBearer);
    }
    Ok(ApiToken::from_bytes(*decoded))
}

fn encode_base64(input: &[u8]) -> String {
    let mut output = String::with_capacity((input.len() * 4).div_ceil(3));
    URL_SAFE_NO_PAD.encode_string(input, &mut output);
    output
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
