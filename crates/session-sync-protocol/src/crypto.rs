use std::{fmt, time::Duration};

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{AeadInOut, Generate, KeyInit},
};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canonical::{
    HostAccessDescriptor, HostAccessError, decode_host_access_descriptor,
    encode_host_access_descriptor,
};

pub const ENVELOPE_VERSION: u16 = 1;
pub const NONCE_LEN: usize = 24;
pub const MAX_CIPHERTEXT_LEN: usize = crate::limits::MAX_CIPHERTEXT_BYTES;
const MAX_FUTURE_CLOCK_SKEW: Duration = Duration::from_secs(60);
const KEY_INFO: &[u8] = b"attached/host-sync/descriptor-aead-key/v1\0";
const AAD_DOMAIN: &[u8] = b"attached/host-sync/envelope-aad/v1\0";

pub struct Envelope {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}
impl Envelope {
    pub fn new(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Result<Self, HostAccessError> {
        if ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(HostAccessError::Limit);
        }
        Ok(Self { nonce, ciphertext })
    }
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn into_parts(self) -> ([u8; NONCE_LEN], Vec<u8>) {
        (self.nonce, self.ciphertext)
    }
}
impl fmt::Debug for Envelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Envelope")
            .field("nonce", &"REDACTED")
            .field("ciphertext", &"REDACTED")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationContext {
    pub account_id: [u8; 16],
    pub record_id: [u8; 16],
    pub now: DateTime<Utc>,
}

pub struct OpenedHostAccessDescriptor {
    descriptor: HostAccessDescriptor,
}
impl OpenedHostAccessDescriptor {
    pub const fn descriptor(&self) -> &HostAccessDescriptor {
        &self.descriptor
    }
}
impl fmt::Debug for OpenedHostAccessDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedHostAccessDescriptor")
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

pub fn derive_host_access_descriptor_key(
    account_root_key: &[u8; 32],
    account_id: &[u8; 16],
) -> Result<[u8; 32], HostAccessError> {
    let hkdf = Hkdf::<Sha256>::new(Some(account_id), account_root_key);
    let mut key = [0_u8; 32];
    hkdf.expand(KEY_INFO, &mut key)
        .map_err(|_| HostAccessError::InvalidField)?;
    Ok(key)
}

pub fn envelope_aad(account_id: &[u8; 16], record_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 34);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(account_id);
    aad.extend_from_slice(record_id);
    aad.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    aad
}

pub fn seal_host_access_descriptor(
    descriptor: &HostAccessDescriptor,
    account_root_key: &[u8; 32],
    account_id: &[u8; 16],
    record_id: &[u8; 16],
) -> Result<Envelope, HostAccessError> {
    let nonce = chacha20poly1305::XNonce::try_generate()
        .map_err(|_| HostAccessError::NonceReuse)?
        .into();
    seal_host_access_descriptor_with_nonce(
        descriptor,
        account_root_key,
        account_id,
        record_id,
        nonce,
    )
}

fn seal_host_access_descriptor_with_nonce(
    descriptor: &HostAccessDescriptor,
    account_root_key: &[u8; 32],
    account_id: &[u8; 16],
    record_id: &[u8; 16],
    nonce: [u8; NONCE_LEN],
) -> Result<Envelope, HostAccessError> {
    let mut ciphertext = Zeroizing::new(encode_host_access_descriptor(descriptor)?);
    let key = Zeroizing::new(derive_host_access_descriptor_key(
        account_root_key,
        account_id,
    )?);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let nonce_value = chacha20poly1305::XNonce::from(nonce);
    cipher
        .encrypt_in_place(
            &nonce_value,
            &envelope_aad(account_id, record_id),
            &mut *ciphertext,
        )
        .map_err(|_| HostAccessError::Decryption)?;
    Envelope::new(nonce, std::mem::take(&mut *ciphertext))
}

pub fn open_host_access_descriptor(
    envelope: &Envelope,
    account_root_key: &[u8; 32],
    context: &VerificationContext,
) -> Result<OpenedHostAccessDescriptor, HostAccessError> {
    if envelope.ciphertext.len() > MAX_CIPHERTEXT_LEN {
        return Err(HostAccessError::Limit);
    }
    let key = Zeroizing::new(derive_host_access_descriptor_key(
        account_root_key,
        &context.account_id,
    )?);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let nonce_value = chacha20poly1305::XNonce::from(envelope.nonce);
    let mut plaintext = Zeroizing::new(envelope.ciphertext.clone());
    cipher
        .decrypt_in_place(
            &nonce_value,
            &envelope_aad(&context.account_id, &context.record_id),
            &mut *plaintext,
        )
        .map_err(|_| HostAccessError::Decryption)?;
    let descriptor = decode_host_access_descriptor(&plaintext)?;
    let maximum_issued_at = context
        .now
        .checked_add_signed(
            chrono::Duration::from_std(MAX_FUTURE_CLOCK_SKEW)
                .map_err(|_| HostAccessError::InvalidField)?,
        )
        .ok_or(HostAccessError::InvalidField)?;
    if descriptor.issued_at() > maximum_issued_at || context.now >= descriptor.expires_at() {
        return Err(HostAccessError::Expired);
    }
    Ok(OpenedHostAccessDescriptor { descriptor })
}
