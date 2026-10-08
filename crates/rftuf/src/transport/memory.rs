//! A transport that serves a repository from memory.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use bytes::Bytes;
use futures_util::{future, stream};

use super::{ByteStream, Transport, TransportError};

/// Serves a repository held in memory.
///
/// Files can be added and removed at any time through a shared reference,
/// which makes it convenient for tests and for repositories that are
/// obtained by other means. Share it with an updater through `Arc` or `&`.
#[derive(Debug, Default)]
pub struct MemoryTransport {
    metadata: RwLock<HashMap<String, Bytes>>,
    targets: RwLock<HashMap<String, Bytes>>,
}

impl MemoryTransport {
    pub fn new() -> Self {
        MemoryTransport::default()
    }

    /// Adds or replaces a metadata file, such as `timestamp.json`.
    pub fn insert_metadata(&self, name: impl Into<String>, data: impl Into<Bytes>) {
        write(&self.metadata).insert(name.into(), data.into());
    }

    pub fn remove_metadata(&self, name: &str) {
        write(&self.metadata).remove(name);
    }

    /// Adds or replaces a target file.
    pub fn insert_target(&self, path: impl Into<String>, data: impl Into<Bytes>) {
        write(&self.targets).insert(path.into(), data.into());
    }

    pub fn remove_target(&self, path: &str) {
        write(&self.targets).remove(path);
    }
}

impl Transport for MemoryTransport {
    async fn fetch_metadata(
        &self,
        name: &str,
        _max_length: u64,
    ) -> Result<ByteStream, TransportError> {
        fetch(&self.metadata, name)
    }

    async fn fetch_target(
        &self,
        path: &str,
        _max_length: u64,
    ) -> Result<ByteStream, TransportError> {
        fetch(&self.targets, path)
    }
}

fn fetch(files: &RwLock<HashMap<String, Bytes>>, name: &str) -> Result<ByteStream, TransportError> {
    let files = files.read().unwrap_or_else(PoisonError::into_inner);
    let data = files.get(name).cloned().ok_or(TransportError::NotFound)?;
    Ok(Box::pin(stream::once(future::ready(Ok(data)))))
}

fn write(
    files: &RwLock<HashMap<String, Bytes>>,
) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Bytes>> {
    files.write().unwrap_or_else(PoisonError::into_inner)
}
