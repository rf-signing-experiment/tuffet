//! Local storage for trusted metadata.
//!
//! The client workflow persists every metadata file it accepts, so that the
//! next update starts from it: the latest root is the trust anchor, and the
//! others protect against rollback attacks and avoid needless downloads.

use std::io;
use std::sync::Arc;

mod filesystem;
mod memory;

pub use filesystem::FilesystemStore;
pub use memory::MemoryStore;

/// Persists trusted metadata between updates.
///
/// Files are identified by name, e.g. `root.json`. Names are single path
/// components consisting of unreserved URL characters and `%`-escapes (role
/// names are percent-encoded).
///
/// Local storage is trusted: anyone who can write to it can make the client
/// trust arbitrary metadata.
pub trait MetadataStore: Send + Sync {
    /// Loads a file, or returns `None` if it does not exist.
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>>;

    /// Stores a file, replacing any previous contents. This should be atomic,
    /// so that a crash cannot leave a partially written file behind.
    fn store(&self, name: &str, data: &[u8]) -> io::Result<()>;

    /// Removes a file. Removing a file that does not exist is not an error.
    fn remove(&self, name: &str) -> io::Result<()>;
}

impl<S: MetadataStore + ?Sized> MetadataStore for &S {
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        (**self).load(name)
    }

    fn store(&self, name: &str, data: &[u8]) -> io::Result<()> {
        (**self).store(name, data)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        (**self).remove(name)
    }
}

impl<S: MetadataStore + ?Sized> MetadataStore for Arc<S> {
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        (**self).load(name)
    }

    fn store(&self, name: &str, data: &[u8]) -> io::Result<()> {
        (**self).store(name, data)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        (**self).remove(name)
    }
}

impl<S: MetadataStore + ?Sized> MetadataStore for Box<S> {
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        (**self).load(name)
    }

    fn store(&self, name: &str, data: &[u8]) -> io::Result<()> {
        (**self).store(name, data)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        (**self).remove(name)
    }
}
