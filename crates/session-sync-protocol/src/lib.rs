#![forbid(unsafe_code)]

pub mod account;
pub mod api;
#[cfg(feature = "host-access")]
pub mod canonical;
#[cfg(feature = "host-access")]
pub mod crypto;
pub mod limits;

#[cfg(feature = "host-access")]
pub use canonical::{
    AttachedVersion, HostAccessDescriptor, HostAccessError, decode_host_access_descriptor,
    encode_host_access_descriptor,
};
#[cfg(feature = "host-access")]
pub use crypto::{
    Envelope, OpenedHostAccessDescriptor, VerificationContext, derive_host_access_descriptor_key,
    envelope_aad, seal_host_access_descriptor,
};
