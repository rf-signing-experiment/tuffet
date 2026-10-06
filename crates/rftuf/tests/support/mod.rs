//! Support code shared by the test targets.
//!
//! - [`keys`]: deterministic Ed25519 keys, so that key IDs and signatures are
//!   the same in every run.
//! - [`TestRepo`]: a TUF repository that publishes metadata, built with the
//!   public metadata API, and [`TestRepo::builder`] to configure it.
//! - [`Client`]: an `Updater` of a [`TestRepo`] with a fixed update start
//!   time.
//! - [`data`]: the fixtures in `tests/data`.
//!
//! Each test target includes this module with `#[path]`, and uses only part
//! of it.
#![allow(dead_code, unused_imports, unused_macros)]

pub mod client;
pub mod data;
pub mod keys;
pub mod repo;
pub mod transport;

use chrono::{DateTime, Duration, TimeZone, Utc};

pub use client::Client;
pub use repo::{Delegation, RepoBuilder, TestRepo};
pub use transport::RecordingTransport;

/// The fixed update start time (5.1) of the tests.
pub fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap()
}

/// A time before [`now`]: metadata that expires then has expired.
pub fn expired() -> DateTime<Utc> {
    now() - Duration::days(1)
}

/// The default expiry of test metadata: far enough after [`now`] that
/// metadata is also valid when an `Updater` refreshes at the actual current
/// time.
pub fn far_future() -> DateTime<Utc> {
    now() + Duration::days(100 * 365)
}

/// Asserts that `result` is an `Err` whose error matches `pattern` (and
/// `guard`), and shows what it is otherwise.
///
/// ```ignore
/// assert_err!(trusted.update_timestamp(&old), Error::Rollback { trusted: 2, new: 1, .. });
/// assert_err!(client.refresh(), Error::Expired { role, .. } if role == "snapshot");
/// ```
macro_rules! assert_err {
    ($result:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        match $result {
            Err($pattern) $(if $guard)? => {}
            Err(other) => panic!(
                "expected an error matching `{}`, got {other:?}",
                stringify!($pattern $(if $guard)?)
            ),
            Ok(_) => panic!(
                "expected an error matching `{}`, got Ok",
                stringify!($pattern $(if $guard)?)
            ),
        }
    };
}
pub(crate) use assert_err;
