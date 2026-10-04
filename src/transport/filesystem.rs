//! A transport that reads a repository from local directories.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use futures_util::stream;

use super::{ByteStream, Transport, TransportError};
use crate::paths;

const CHUNK_SIZE: usize = 64 * 1024;

/// Reads a repository from local directories, for example a mounted mirror.
///
/// Reads are blocking. That is fine for local disks, but if it matters to
/// your executor, drive the updater from a thread that may block.
#[derive(Debug, Clone)]
pub struct FilesystemTransport {
    metadata_dir: PathBuf,
    targets_dir: PathBuf,
}

impl FilesystemTransport {
    pub fn new(metadata_dir: impl Into<PathBuf>, targets_dir: impl Into<PathBuf>) -> Self {
        FilesystemTransport {
            metadata_dir: metadata_dir.into(),
            targets_dir: targets_dir.into(),
        }
    }
}

impl Transport for FilesystemTransport {
    async fn fetch_metadata(&self, name: &str) -> Result<ByteStream, TransportError> {
        let file_name = paths::file_name(name)
            .ok_or_else(|| TransportError::other(name, "invalid metadata file name"))?;
        open(&self.metadata_dir.join(file_name), name)
    }

    async fn fetch_target(&self, path: &str) -> Result<ByteStream, TransportError> {
        let relative = paths::relative_path(path)
            .ok_or_else(|| TransportError::other(path, "unsafe target path"))?;
        open(&self.targets_dir.join(relative), path)
    }
}

fn open(path: &Path, name: &str) -> Result<ByteStream, TransportError> {
    let mut file = Some(File::open(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => TransportError::NotFound(name.to_owned()),
        _ => TransportError::other(name, error),
    })?);
    let name = name.to_owned();
    let chunks = std::iter::from_fn(move || {
        let mut chunk = vec![0; CHUNK_SIZE];
        let result = loop {
            match file.as_mut()?.read(&mut chunk) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result,
            }
        };
        match result {
            Ok(0) => {
                file = None;
                None
            }
            Ok(len) => {
                chunk.truncate(len);
                Some(Ok(Bytes::from(chunk)))
            }
            Err(error) => {
                file = None;
                Some(Err(TransportError::other(name.clone(), error)))
            }
        }
    });
    Ok(Box::pin(stream::iter(chunks)))
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;
    use futures_util::TryStreamExt;

    use super::*;

    fn read(stream: ByteStream) -> Vec<u8> {
        block_on(stream.map_ok(|chunk| chunk.to_vec()).try_concat()).unwrap()
    }

    #[test]
    fn reads_metadata_and_targets() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("targets/sub")).unwrap();
        std::fs::write(dir.path().join("timestamp.json"), b"meta").unwrap();
        let large = vec![7u8; CHUNK_SIZE * 2 + 3];
        std::fs::write(dir.path().join("targets/sub/file.bin"), &large).unwrap();

        let transport = FilesystemTransport::new(dir.path(), dir.path().join("targets"));
        assert_eq!(
            read(block_on(transport.fetch_metadata("timestamp.json")).unwrap()),
            b"meta"
        );
        assert_eq!(
            read(block_on(transport.fetch_target("sub/file.bin")).unwrap()),
            large
        );
    }

    #[test]
    fn reports_missing_files_and_rejects_escaping_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret"), b"x").unwrap();
        let transport = FilesystemTransport::new(dir.path(), dir.path().join("targets"));

        let missing = block_on(transport.fetch_metadata("2.root.json"));
        assert!(matches!(missing, Err(TransportError::NotFound(name)) if name == "2.root.json"));
        assert!(matches!(
            block_on(transport.fetch_target("../secret")),
            Err(TransportError::Other { .. })
        ));
        assert!(matches!(
            block_on(transport.fetch_metadata("../secret")),
            Err(TransportError::Other { .. })
        ));
    }
}
