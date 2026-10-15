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
#![allow(dead_code, unused_imports)]

pub mod client;
pub mod data;
pub mod keys;
pub mod repo;
pub mod transport;

use jiff::SignedDuration;

pub use client::Client;
pub use repo::{Delegation, RepoBuilder, TestRepo};
pub use transport::{RecordingTransport, read};

/// The fixed update start time (5.1) of the tests.
pub fn now() -> jiff::Timestamp {
    "2025-06-01T12:00:00Z".parse().unwrap()
}

/// A time before [`now`]: metadata that expires then has expired.
pub fn expired() -> jiff::Timestamp {
    now() - SignedDuration::from_hours(24)
}

/// The default expiry of test metadata: far enough after [`now`] that
/// metadata is also valid when an `Updater` refreshes at the actual current
/// time.
pub fn far_future() -> jiff::Timestamp {
    now() + SignedDuration::from_hours(100 * 365 * 24)
}
