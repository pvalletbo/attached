#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};

pub mod account;
pub mod attach;
pub mod attached_update;
pub mod http;
pub mod publisher;
pub mod refresh;
pub mod state;
pub mod state_catalog;

pub(super) fn utc_now_seconds() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp(now.timestamp(), 0)
        .expect("the current UTC time is representable at whole-second precision")
}
