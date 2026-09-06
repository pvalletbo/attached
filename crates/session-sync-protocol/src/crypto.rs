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
    HerdrVersion, SessionAccessDescriptor, SessionAccessError, decode_session_access_descriptor,
    encode_session_access_descriptor,
};

pub const ENVELOPE_VERSION: u16 = 1;
pub const NONCE_LEN: usize = 24;
pub const MAX_CIPHERTEXT_LEN: usize = crate::limits::MAX_CIPHERTEXT_BYTES;
const MAX_FUTURE_CLOCK_SKEW: Duration = Duration::from_secs(60);
// This established domain label is retained so a terminology-only rename does not change keys.
const KEY_INFO: &[u8] = b"herdr/session-sync/manifest-aead-key/v1\0";
const AAD_DOMAIN: &[u8] = b"herdr/session-sync/envelope-aad/v1\0";

pub struct Envelope {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}
impl Envelope {
    pub fn new(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Result<Self, SessionAccessError> {
        if ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(SessionAccessError::Limit);
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
    pub local_version: HerdrVersion,
}

#[derive(Clone, Copy)]
enum VersionPolicy {
    Compatible,
    AnyStructured,
}

pub struct OpenedSessionAccessDescriptor {
    descriptor: SessionAccessDescriptor,
}
impl OpenedSessionAccessDescriptor {
    pub const fn descriptor(&self) -> &SessionAccessDescriptor {
        &self.descriptor
    }
}
impl fmt::Debug for OpenedSessionAccessDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedSessionAccessDescriptor")
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

pub fn derive_session_access_descriptor_key(
    account_root_key: &[u8; 32],
    account_id: &[u8; 16],
) -> Result<[u8; 32], SessionAccessError> {
    let hkdf = Hkdf::<Sha256>::new(Some(account_id), account_root_key);
    let mut key = [0_u8; 32];
    hkdf.expand(KEY_INFO, &mut key)
        .map_err(|_| SessionAccessError::InvalidField)?;
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

pub fn seal_session_access_descriptor(
    descriptor: &SessionAccessDescriptor,
    account_root_key: &[u8; 32],
    account_id: &[u8; 16],
    record_id: &[u8; 16],
) -> Result<Envelope, SessionAccessError> {
    let nonce = chacha20poly1305::XNonce::try_generate()
        .map_err(|_| SessionAccessError::NonceReuse)?
        .into();
    seal_session_access_descriptor_with_nonce(
        descriptor,
        account_root_key,
        account_id,
        record_id,
        nonce,
    )
}

fn seal_session_access_descriptor_with_nonce(
    descriptor: &SessionAccessDescriptor,
    account_root_key: &[u8; 32],
    account_id: &[u8; 16],
    record_id: &[u8; 16],
    nonce: [u8; NONCE_LEN],
) -> Result<Envelope, SessionAccessError> {
    let mut ciphertext = Zeroizing::new(encode_session_access_descriptor(descriptor)?);
    let key = Zeroizing::new(derive_session_access_descriptor_key(
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
        .map_err(|_| SessionAccessError::Decryption)?;
    Envelope::new(nonce, std::mem::take(&mut *ciphertext))
}

pub fn open_session_access_descriptor_cursorless(
    envelope: &Envelope,
    account_root_key: &[u8; 32],
    context: &VerificationContext,
) -> Result<OpenedSessionAccessDescriptor, SessionAccessError> {
    open_session_access_descriptor_with_policy(
        envelope,
        account_root_key,
        context,
        VersionPolicy::Compatible,
    )
}

/// Opens an unexpired session access descriptor for the native client's exact-version upgrade flow.
pub fn open_session_access_descriptor_cursorless_for_native_upgrade(
    envelope: &Envelope,
    account_root_key: &[u8; 32],
    context: &VerificationContext,
) -> Result<OpenedSessionAccessDescriptor, SessionAccessError> {
    open_session_access_descriptor_with_policy(
        envelope,
        account_root_key,
        context,
        VersionPolicy::AnyStructured,
    )
}

fn open_session_access_descriptor_with_policy(
    envelope: &Envelope,
    account_root_key: &[u8; 32],
    context: &VerificationContext,
    version_policy: VersionPolicy,
) -> Result<OpenedSessionAccessDescriptor, SessionAccessError> {
    if envelope.ciphertext.len() > MAX_CIPHERTEXT_LEN {
        return Err(SessionAccessError::Limit);
    }
    let key = Zeroizing::new(derive_session_access_descriptor_key(
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
        .map_err(|_| SessionAccessError::Decryption)?;
    let descriptor = decode_session_access_descriptor(&plaintext)?;
    let maximum_issued_at = context
        .now
        .checked_add_signed(
            chrono::Duration::from_std(MAX_FUTURE_CLOCK_SKEW)
                .map_err(|_| SessionAccessError::InvalidField)?,
        )
        .ok_or(SessionAccessError::InvalidField)?;
    if descriptor.issued_at() > maximum_issued_at || context.now >= descriptor.expires_at() {
        return Err(SessionAccessError::Expired);
    }
    let remote_version = descriptor.herdr_version();
    if matches!(version_policy, VersionPolicy::Compatible)
        && (remote_version.major, remote_version.minor)
            != (context.local_version.major, context.local_version.minor)
    {
        return Err(SessionAccessError::IncompatibleVersion);
    }
    Ok(OpenedSessionAccessDescriptor { descriptor })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::AttachedVersion;
    use attached_tunnel_protocol::CapabilitySecret;

    const ENDPOINT: &str = "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";

    fn timestamp(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).expect("fixture timestamp")
    }

    fn fixture_descriptor(version: HerdrVersion) -> SessionAccessDescriptor {
        SessionAccessDescriptor::new(
            "office".into(),
            timestamp(1_700_000_000),
            timestamp(1_700_000_300),
            ENDPOINT.into(),
            CapabilitySecret::from_bytes([6; 32]),
            AttachedVersion::new(0, 2, 0),
            version,
            vec!["alpha".into(), "build".into()],
        )
        .expect("unit fixture")
    }

    fn context(local_version: HerdrVersion) -> VerificationContext {
        VerificationContext {
            account_id: [1; 16],
            record_id: [2; 16],
            now: timestamp(1_700_000_100),
            local_version,
        }
    }

    #[test]
    fn native_upgrade_opening_retains_all_structured_version_mismatches() {
        let account_root_key = [8; 32];
        for remote in [
            HerdrVersion::new(2, 0, 1),
            HerdrVersion::new(2, 1, 0),
            HerdrVersion::new(3, 0, 0),
        ] {
            let descriptor = fixture_descriptor(remote);
            let envelope =
                seal_session_access_descriptor(&descriptor, &account_root_key, &[1; 16], &[2; 16])
                    .unwrap();
            let opened = open_session_access_descriptor_cursorless_for_native_upgrade(
                &envelope,
                &account_root_key,
                &context(HerdrVersion::new(2, 0, 0)),
            )
            .unwrap_or_else(|error| panic!("rejected {remote:?}: {error}"));
            assert_eq!(opened.descriptor().herdr_version(), remote);
        }
    }

    #[test]
    fn context_expiration_version_and_ciphertext_tampering_fail_closed() {
        let account_root_key = [8; 32];
        let descriptor = fixture_descriptor(HerdrVersion::new(1, 2, 3));
        let envelope =
            seal_session_access_descriptor(&descriptor, &account_root_key, &[1; 16], &[2; 16])
                .unwrap();

        let wrong_context = VerificationContext {
            record_id: [3; 16],
            ..context(HerdrVersion::new(1, 2, 9))
        };
        assert_eq!(
            open_session_access_descriptor_cursorless(&envelope, &account_root_key, &wrong_context)
                .err(),
            Some(SessionAccessError::Decryption)
        );
        let expired = VerificationContext {
            now: timestamp(1_700_000_300),
            ..context(HerdrVersion::new(1, 2, 9))
        };
        assert_eq!(
            open_session_access_descriptor_cursorless(&envelope, &account_root_key, &expired).err(),
            Some(SessionAccessError::Expired)
        );
        assert_eq!(
            open_session_access_descriptor_cursorless(
                &envelope,
                &account_root_key,
                &context(HerdrVersion::new(1, 3, 0)),
            )
            .err(),
            Some(SessionAccessError::IncompatibleVersion)
        );
        assert!(
            open_session_access_descriptor_cursorless(
                &envelope,
                &account_root_key,
                &context(HerdrVersion::new(1, 2, 9)),
            )
            .is_ok(),
            "browser compatibility still permits patch differences"
        );

        let mut tampered = envelope.ciphertext().to_vec();
        tampered[0] ^= 1;
        let tampered = Envelope::new(*envelope.nonce(), tampered).unwrap();
        assert_eq!(
            open_session_access_descriptor_cursorless(
                &tampered,
                &account_root_key,
                &context(HerdrVersion::new(1, 2, 9)),
            )
            .err(),
            Some(SessionAccessError::Decryption)
        );
    }

    #[test]
    fn private_deterministic_seal_seam_is_repeatable() {
        let descriptor = fixture_descriptor(HerdrVersion::new(1, 2, 3));
        let first = seal_session_access_descriptor_with_nonce(
            &descriptor,
            &[8; 32],
            &[1; 16],
            &[2; 16],
            [9; NONCE_LEN],
        )
        .expect("first deterministic seal");
        let second = seal_session_access_descriptor_with_nonce(
            &descriptor,
            &[8; 32],
            &[1; 16],
            &[2; 16],
            [9; NONCE_LEN],
        )
        .expect("second deterministic seal");
        assert_eq!(first.nonce(), &[9; NONCE_LEN]);
        assert_eq!(first.ciphertext(), second.ciphertext());
    }
}
