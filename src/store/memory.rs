//! Metadata storage in memory.

use std::collections::HashMap;
use std::io;
use std::sync::{Mutex, PoisonError};

use super::MetadataStore;

/// Keeps metadata in memory, for clients that do not persist state between
/// runs (they start each run from their shipped root metadata) and for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore::default()
    }

    fn files(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl MetadataStore for MemoryStore {
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(self.files().get(name).cloned())
    }

    fn store(&self, name: &str, data: &[u8]) -> io::Result<()> {
        self.files().insert(name.to_owned(), data.to_vec());
        Ok(())
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        self.files().remove(name);
        Ok(())
    }
}
