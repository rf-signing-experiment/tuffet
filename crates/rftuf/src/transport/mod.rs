//! Fetching files from a repository.
//!
//! This crate deliberately contains no HTTP client. Implement [`Transport`] to
//! fetch files with the client of your choice (the `rftuf-http` crate provides
//! one), or use the built-in [`FilesystemTransport`] or [`MemoryTransport`].

use std::error::Error as StdError;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use futures_core::Stream;

mod filesystem;
mod memory;

pub use filesystem::FilesystemTransport;
pub use memory::MemoryTransport;

/// The body of a fetched file, as a stream of chunks.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, TransportError>> + Send>>;

/// Fetches metadata and target files from a TUF repository.
///
/// The `max_length` parameter is a hint to indicate the max number of bytes
/// to read. If the file is larger than `max_length`, the transport MAY reject
/// it as [`TransportError::TooLarge`].
pub trait Transport: Send + Sync {
    /// Fetches a metadata file, such as `timestamp.json` or `3.root.json`,
    /// from the repository's metadata location.
    ///
    /// `name` is a single path component consisting of unreserved URL
    /// characters and `%`-escapes (role names are percent-encoded), so it can
    /// be appended to a URL or a directory as is.
    fn fetch_metadata(
        &self,
        name: &str,
        max_length: u64,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send;

    /// Fetches a target file from below the repository's targets location.
    ///
    /// `path` comes from signed metadata. It is `/`-separated, and its
    /// segments are never empty, `.` or `..` and never contain `\`, `:` or
    /// NUL, but it is otherwise arbitrary: implementations must encode each
    /// segment as needed (for example by percent-encoding it in a URL), so
    /// that characters like `?`, `#` and `%` cannot change its meaning.
    fn fetch_target(
        &self,
        path: &str,
        max_length: u64,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send;
}

/// Errors from a [`Transport`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The file does not exist.
    ///
    /// The updater relies on this to detect the end of the chain of root
    /// metadata versions, so report "not found" responses (such as HTTP 404
    /// or 403) this way.
    #[error("the file does not exist")]
    NotFound,

    /// The file is longer than the `max_length` the caller accepts.
    #[error("the file exceeds the maximum length")]
    TooLarge,

    /// Any other failure, such as a network error or an unexpected HTTP
    /// status.
    #[error(transparent)]
    Other(Box<dyn StdError + Send + Sync>),
}

impl TransportError {
    pub fn other(source: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        TransportError::Other(source.into())
    }
}

impl<T: Transport> Transport for &T {
    fn fetch_metadata(
        &self,
        name: &str,
        max_length: u64,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send {
        (**self).fetch_metadata(name, max_length)
    }

    fn fetch_target(
        &self,
        path: &str,
        max_length: u64,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send {
        (**self).fetch_target(path, max_length)
    }
}

impl<T: Transport> Transport for Arc<T> {
    fn fetch_metadata(
        &self,
        name: &str,
        max_length: u64,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send {
        (**self).fetch_metadata(name, max_length)
    }

    fn fetch_target(
        &self,
        path: &str,
        max_length: u64,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send {
        (**self).fetch_target(path, max_length)
    }
}
