//! Metadata storage in a local directory.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use super::MetadataStore;
use crate::paths;

/// Stores metadata files in a directory. Writes are atomic.
#[derive(Debug, Clone)]
pub struct FilesystemStore {
    dir: PathBuf,
}

impl FilesystemStore {
    /// Stores files in `dir`, creating it if necessary.
    pub fn new(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(FilesystemStore { dir })
    }

    fn path(&self, name: &str) -> io::Result<PathBuf> {
        let file_name = paths::file_name(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid metadata file name {name:?}"),
            )
        })?;
        Ok(self.dir.join(file_name))
    }
}

impl MetadataStore for FilesystemStore {
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.path(name)?) {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn store(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let path = self.path(name)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.dir)?;
        file.write_all(data)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|error| error.error)?;
        Ok(())
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        match fs::remove_file(self.path(name)?) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_loads_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemStore::new(dir.path().join("nested/metadata")).unwrap();
        assert_eq!(store.load("root.json").unwrap(), None);
        store.store("root.json", b"one").unwrap();
        store.store("root.json", b"two").unwrap();
        assert_eq!(
            store.load("root.json").unwrap().as_deref(),
            Some(&b"two"[..])
        );
        store.remove("root.json").unwrap();
        store.remove("root.json").unwrap();
        assert_eq!(store.load("root.json").unwrap(), None);
    }

    #[test]
    fn rejects_names_that_escape_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemStore::new(dir.path().join("metadata")).unwrap();
        assert!(store.store("../root.json", b"x").is_err());
        assert!(store.load("a/b.json").is_err());
        assert!(!dir.path().join("root.json").exists());
    }
}
