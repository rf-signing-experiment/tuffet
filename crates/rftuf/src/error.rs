//! The crate-wide error type.

use std::error::Error as StdError;
use std::io;

use crate::crypto::CryptoError;

/// A specialized `Result` type for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors produced while decoding, verifying or fetching TUF metadata and targets.
///
/// Variants that describe failed security checks (signatures, versions,
/// expiry, lengths and hashes) indicate that the repository is misbehaving or
/// that an attack may be in progress. The update cycle must be aborted when
/// one of them is reported.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Metadata could not be parsed by the POUF.
    #[error("failed to decode metadata: {0}")]
    Decode(#[source] Box<dyn StdError + Send + Sync>),

    /// Metadata could not be serialized by the POUF.
    #[error("failed to encode metadata: {0}")]
    Encode(#[source] Box<dyn StdError + Send + Sync>),

    /// Metadata parsed, but violates the specification.
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),

    /// Metadata expired before the update start time.
    #[error("{role} metadata expired at {expires}")]
    Expired {
        role: String,
        expires: jiff::Timestamp,
    },

    /// Fewer than a threshold of authorized keys produced valid signatures.
    #[error("{role} metadata has {valid} valid signatures, but {threshold} are required")]
    SignatureThreshold {
        role: String,
        valid: u64,
        threshold: u64,
    },

    /// A metadata version differs from the one it was required to have.
    #[error("{role} metadata has version {actual}, expected {expected}")]
    VersionMismatch {
        role: String,
        expected: u64,
        actual: u64,
    },

    /// A metadata version is lower than the previously trusted version.
    #[error(
        "rollback attack: {role} metadata version {new} is lower than trusted version {trusted}"
    )]
    Rollback {
        role: String,
        trusted: u64,
        new: u64,
    },

    /// A metadata file listed in the trusted snapshot is missing from a new snapshot.
    #[error("{0} is listed in the trusted snapshot but missing from the new snapshot")]
    RemovedFromSnapshot(String),

    /// Snapshot metadata does not list a targets metadata file.
    #[error("{0} is not listed in snapshot metadata")]
    NotInSnapshot(String),

    /// Metadata was checked against a role that does not delegate to it.
    #[error("no delegation to role {0:?}")]
    UnknownDelegation(String),

    /// A file's length differs from the length listed in trusted metadata.
    #[error("{name} has length {actual}, expected {expected}")]
    LengthMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },

    /// A file's hash differs from the hash listed in trusted metadata.
    #[error("{name} does not match its trusted {algorithm} hash")]
    HashMismatch { name: String, algorithm: String },

    /// None of the hash algorithms listed for a file are supported.
    #[error("{name} lists no supported hash algorithm")]
    NoSupportedHash { name: String },

    /// A download exceeded its maximum allowed length.
    #[error("{name} exceeds the maximum allowed length of {max} bytes")]
    TooLarge { name: String, max: u64 },

    /// A target path from metadata cannot be safely fetched, as it could
    /// escape the repository's targets location.
    #[error("unsafe path {0:?}")]
    UnsafePath(String),

    /// No trusted root metadata was supplied or found in local storage.
    #[error("no trusted root metadata is available")]
    NoTrustedRoot,

    /// An API was called out of order (for example, loading snapshot metadata
    /// before timestamp metadata).
    #[error("invalid state: {0}")]
    InvalidState(&'static str),

    /// Metadata that the update requires, such as `timestamp.json` or the
    /// metadata of a delegated role, does not exist on the remote repository.
    #[error("metadata {0} not found")]
    MetadataNotFound(String),

    /// A target that trusted metadata describes does not exist on the remote
    /// repository.
    #[error("target {0} not found")]
    TargetNotFound(String),

    /// Fetching a file from the remote repository failed.
    #[error("failed to fetch {name}")]
    Transport {
        name: String,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },

    /// Reading or writing local metadata storage failed.
    #[error("local metadata storage failed for {name}")]
    Store {
        name: String,
        #[source]
        source: io::Error,
    },

    /// A local I/O operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
