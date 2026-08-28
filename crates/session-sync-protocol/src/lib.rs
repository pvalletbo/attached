#![forbid(unsafe_code)]

pub mod account;
pub mod api;
#[cfg(feature = "session-access")]
pub mod canonical;
#[cfg(feature = "session-access")]
pub mod crypto;
pub mod limits;

#[cfg(feature = "session-access")]
pub use canonical::{
    AttachedVersion, HerdrVersion, SessionAccessDescriptor, SessionAccessError,
    decode_session_access_descriptor, encode_session_access_descriptor,
};
#[cfg(feature = "session-access")]
pub use crypto::{
    Envelope, OpenedSessionAccessDescriptor, VerificationContext,
    derive_session_access_descriptor_key, envelope_aad, seal_session_access_descriptor,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FoundationStatus {
    Pending,
}
