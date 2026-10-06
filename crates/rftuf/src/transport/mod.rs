//! Fetching files from a remote repository.
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
/// Implementations only move bytes. The caller enforces size limits and
/// verifies content while it reads the returned stream, so return the body as
/// it arrives rather than buffering it: that lets oversized responses be cut
/// off early.
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
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send;

    /// Fetches a target file from the repository's targets location.
    ///
    /// `path` comes from signed metadata. It is `/`-separated but otherwise
    /// arbitrary: implementations must encode it as needed (for example by
    /// percent-encoding each URL path segment) and must not let it escape the
    /// targets location.
    fn fetch_target(
        &self,
        path: &str,
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
    #[error("{0} not found")]
    NotFound(String),

    /// Any other failure.
    #[error("failed to fetch {path}")]
    Other {
        path: String,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
}

impl TransportError {
    pub fn other(
        path: impl Into<String>,
        source: impl Into<Box<dyn StdError + Send + Sync>>,
    ) -> Self {
        TransportError::Other {
            path: path.into(),
            source: source.into(),
        }
    }
}

impl<T: Transport> Transport for &T {
    fn fetch_metadata(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send {
        (**self).fetch_metadata(name)
    }

    fn fetch_target(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send {
        (**self).fetch_target(path)
    }
}

impl<T: Transport> Transport for Arc<T> {
    fn fetch_metadata(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send {
        (**self).fetch_metadata(name)
    }

    fn fetch_target(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<ByteStream, TransportError>> + Send {
        (**self).fetch_target(path)
    }
}
