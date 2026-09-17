use std::{fmt, str::FromStr, time::Duration};

use attached_tunnel_protocol::CapabilitySecret;
use chrono::{DateTime, Utc};
use iroh_tickets::endpoint::EndpointTicket;
use zeroize::Zeroizing;

pub const MAX_CANONICAL_HOST_ACCESS_DESCRIPTOR_LEN: usize =
    crate::limits::MAX_HOST_ACCESS_DESCRIPTOR_BYTES;
pub const MAX_ENDPOINT_TICKET_LEN: usize = crate::limits::MAX_ENDPOINT_TICKET_BYTES;
const MIN_DESCRIPTOR_LIFETIME: Duration = Duration::from_secs(60);
const MAX_DESCRIPTOR_LIFETIME: Duration = Duration::from_secs(900);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAccessError {
    Malformed,
    NonCanonical,
    Limit,
    InvalidField,
    Endpoint,
    Expired,
    Decryption,
    NonceReuse,
}

impl fmt::Display for HostAccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed host access descriptor",
            Self::NonCanonical => "non-canonical host access descriptor",
            Self::Limit => "host access descriptor limit exceeded",
            Self::InvalidField => "invalid host access descriptor field",
            Self::Endpoint => "invalid endpoint ticket",
            Self::Expired => "host access descriptor expired",
            Self::Decryption => "host access descriptor decryption failed",
            Self::NonceReuse => "host access descriptor nonce reuse",
        })
    }
}
impl std::error::Error for HostAccessError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachedVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}
impl AttachedVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

pub struct HostAccessDescriptor {
    host_label: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    endpoint_ticket: String,
    attach_capability: CapabilitySecret,
    attached_version: AttachedVersion,
    ssh_enabled: bool,
}

impl fmt::Debug for HostAccessDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostAccessDescriptor")
            .field("host_label", &self.host_label)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("attach_capability", &"REDACTED")
            .field("ssh_enabled", &self.ssh_enabled)
            .finish_non_exhaustive()
    }
}

impl HostAccessDescriptor {
    pub fn new(
        host_label: String,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        endpoint_ticket: String,
        attach_capability: CapabilitySecret,
        attached_version: AttachedVersion,
        ssh_enabled: bool,
    ) -> Result<Self, HostAccessError> {
        let descriptor = Self {
            host_label,
            issued_at,
            expires_at,
            endpoint_ticket,
            attach_capability,
            attached_version,
            ssh_enabled,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn validate(&self) -> Result<(), HostAccessError> {
        if !crate::limits::validate_host_label(&self.host_label)
            || self.issued_at.timestamp() < 0
            || self.expires_at.timestamp() < 0
            || self.issued_at.timestamp_subsec_nanos() != 0
            || self.expires_at.timestamp_subsec_nanos() != 0
            || self.issued_at >= self.expires_at
        {
            return Err(HostAccessError::InvalidField);
        }
        let lifetime = (self.expires_at - self.issued_at)
            .to_std()
            .map_err(|_| HostAccessError::InvalidField)?;
        if !(MIN_DESCRIPTOR_LIFETIME..=MAX_DESCRIPTOR_LIFETIME).contains(&lifetime) {
            return Err(HostAccessError::InvalidField);
        }
        if self.endpoint_ticket.is_empty()
            || self.endpoint_ticket.len() > MAX_ENDPOINT_TICKET_LEN
            || !self.endpoint_ticket.is_ascii()
        {
            return Err(HostAccessError::Limit);
        }
        let ticket = EndpointTicket::from_str(&self.endpoint_ticket)
            .map_err(|_| HostAccessError::Endpoint)?;
        if ticket.to_string() != self.endpoint_ticket {
            return Err(HostAccessError::Endpoint);
        }
        Ok(())
    }

    pub fn host_label(&self) -> &str {
        &self.host_label
    }
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    pub fn endpoint_ticket(&self) -> &str {
        &self.endpoint_ticket
    }
    pub fn endpoint_identity(&self) -> [u8; 32] {
        *EndpointTicket::from_str(&self.endpoint_ticket)
            .expect("a validated host access descriptor retains a canonical endpoint ticket")
            .endpoint_addr()
            .id
            .as_bytes()
    }
    pub const fn attach_capability_bytes(&self) -> [u8; 32] {
        self.attach_capability.to_bytes()
    }
    pub const fn attached_version(&self) -> AttachedVersion {
        self.attached_version
    }

    pub const fn ssh_enabled(&self) -> bool {
        self.ssh_enabled
    }
}

pub fn encode_host_access_descriptor(
    descriptor: &HostAccessDescriptor,
) -> Result<Vec<u8>, HostAccessError> {
    descriptor.validate()?;
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    put_head(&mut out, 5, 7);
    put_uint(&mut out, 1);
    put_text(&mut out, &descriptor.host_label);
    put_uint(&mut out, 2);
    put_uint(&mut out, unix_seconds(descriptor.issued_at)?);
    put_uint(&mut out, 3);
    put_uint(&mut out, unix_seconds(descriptor.expires_at)?);
    put_uint(&mut out, 4);
    put_text(&mut out, &descriptor.endpoint_ticket);
    put_uint(&mut out, 5);
    let capability = Zeroizing::new(descriptor.attach_capability.to_bytes());
    put_bytes(&mut out, capability.as_ref());
    put_uint(&mut out, 6);
    put_head(&mut out, 4, 3);
    put_uint(&mut out, u64::from(descriptor.attached_version.major));
    put_uint(&mut out, u64::from(descriptor.attached_version.minor));
    put_uint(&mut out, u64::from(descriptor.attached_version.patch));
    put_uint(&mut out, 7);
    out.push(if descriptor.ssh_enabled { 0xf5 } else { 0xf4 });
    if out.len() > MAX_CANONICAL_HOST_ACCESS_DESCRIPTOR_LEN {
        return Err(HostAccessError::Limit);
    }
    Ok(std::mem::take(&mut *out))
}

pub fn decode_host_access_descriptor(
    input: &[u8],
) -> Result<HostAccessDescriptor, HostAccessError> {
    if input.len() > MAX_CANONICAL_HOST_ACCESS_DESCRIPTOR_LEN {
        return Err(HostAccessError::Limit);
    }
    let mut decoder = Decoder::new(input);
    let field_count = decoder.head(5)?;
    if field_count != 7 {
        return Err(HostAccessError::Malformed);
    }
    decoder.key(1)?;
    let host_label = decoder
        .text(1, crate::limits::MAX_HOST_LABEL_BYTES)?
        .to_owned();
    decoder.key(2)?;
    let issued_at = datetime_from_unix_seconds(decoder.uint()?)?;
    decoder.key(3)?;
    let expires_at = datetime_from_unix_seconds(decoder.uint()?)?;
    decoder.key(4)?;
    let endpoint_ticket = decoder.text(1, MAX_ENDPOINT_TICKET_LEN)?.to_owned();
    decoder.key(5)?;
    let attach_capability = CapabilitySecret::from_bytes(decoder.fixed_bytes()?);
    decoder.key(6)?;
    if decoder.head(4)? != 3 {
        return Err(HostAccessError::Malformed);
    }
    let major = u16::try_from(decoder.uint()?).map_err(|_| HostAccessError::InvalidField)?;
    let minor = u16::try_from(decoder.uint()?).map_err(|_| HostAccessError::InvalidField)?;
    let patch = u16::try_from(decoder.uint()?).map_err(|_| HostAccessError::InvalidField)?;
    decoder.key(7)?;
    let ssh_enabled = match decoder.byte()? {
        0xf4 => false,
        0xf5 => true,
        _ => return Err(HostAccessError::InvalidField),
    };
    if decoder.position != input.len() {
        return Err(HostAccessError::Malformed);
    }
    let descriptor = HostAccessDescriptor::new(
        host_label,
        issued_at,
        expires_at,
        endpoint_ticket,
        attach_capability,
        AttachedVersion::new(major, minor, patch),
        ssh_enabled,
    )?;
    let canonical = Zeroizing::new(encode_host_access_descriptor(&descriptor)?);
    if canonical.as_slice() != input {
        return Err(HostAccessError::NonCanonical);
    }
    Ok(descriptor)
}

fn unix_seconds(timestamp: DateTime<Utc>) -> Result<u64, HostAccessError> {
    u64::try_from(timestamp.timestamp()).map_err(|_| HostAccessError::InvalidField)
}

fn datetime_from_unix_seconds(seconds: u64) -> Result<DateTime<Utc>, HostAccessError> {
    let seconds = i64::try_from(seconds).map_err(|_| HostAccessError::InvalidField)?;
    DateTime::from_timestamp(seconds, 0).ok_or(HostAccessError::InvalidField)
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}
impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }
    fn byte(&mut self) -> Result<u8, HostAccessError> {
        let value = *self
            .input
            .get(self.position)
            .ok_or(HostAccessError::Malformed)?;
        self.position += 1;
        Ok(value)
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], HostAccessError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(HostAccessError::Limit)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(HostAccessError::Malformed)?;
        self.position = end;
        Ok(value)
    }
    fn head(&mut self, expected_major: u8) -> Result<u64, HostAccessError> {
        let first = self.byte()?;
        if first >> 5 != expected_major {
            return Err(HostAccessError::Malformed);
        }
        let additional = first & 31;
        let value = match additional {
            0..=23 => u64::from(additional),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?
                    .try_into()
                    .map_err(|_| HostAccessError::Malformed)?,
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| HostAccessError::Malformed)?,
            )),
            27 => u64::from_be_bytes(
                self.take(8)?
                    .try_into()
                    .map_err(|_| HostAccessError::Malformed)?,
            ),
            _ => return Err(HostAccessError::Malformed),
        };
        if matches!(additional, 24) && value < 24
            || matches!(additional, 25) && value <= 255
            || matches!(additional, 26) && value <= 65_535
            || matches!(additional, 27) && value <= u64::from(u32::MAX)
        {
            return Err(HostAccessError::NonCanonical);
        }
        Ok(value)
    }
    fn uint(&mut self) -> Result<u64, HostAccessError> {
        self.head(0)
    }
    fn key(&mut self, expected: u64) -> Result<(), HostAccessError> {
        if self.uint()? == expected {
            Ok(())
        } else {
            Err(HostAccessError::NonCanonical)
        }
    }
    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], HostAccessError> {
        if self.head(2)? != N as u64 {
            return Err(HostAccessError::Malformed);
        }
        self.take(N)?
            .try_into()
            .map_err(|_| HostAccessError::Malformed)
    }
    fn text(&mut self, minimum: usize, maximum: usize) -> Result<&'a str, HostAccessError> {
        let length = usize::try_from(self.head(3)?).map_err(|_| HostAccessError::Limit)?;
        if length < minimum || length > maximum {
            return Err(HostAccessError::Limit);
        }
        std::str::from_utf8(self.take(length)?).map_err(|_| HostAccessError::Malformed)
    }
}

fn put_head(out: &mut Vec<u8>, major: u8, value: u64) {
    match value {
        0..=23 => out.push((major << 5) | value as u8),
        24..=0xff => {
            out.push((major << 5) | 24);
            out.push(value as u8)
        }
        0x100..=0xffff => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes())
        }
        0x1_0000..=0xffff_ffff => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes())
        }
        _ => {
            out.push((major << 5) | 27);
            out.extend_from_slice(&value.to_be_bytes())
        }
    }
}
fn put_uint(out: &mut Vec<u8>, value: u64) {
    put_head(out, 0, value)
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_head(out, 2, value.len() as u64);
    out.extend_from_slice(value)
}
fn put_text(out: &mut Vec<u8>, value: &str) {
    put_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes())
}
