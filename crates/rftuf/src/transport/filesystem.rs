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
    async fn fetch_metadata(
        &self,
        name: &str,
        _max_length: u64,
    ) -> Result<ByteStream, TransportError> {
        let file_name = paths::file_name(name)
            .ok_or_else(|| TransportError::other("invalid metadata file name"))?;
        open(&self.metadata_dir.join(file_name))
    }

    async fn fetch_target(
        &self,
        path: &str,
        _max_length: u64,
    ) -> Result<ByteStream, TransportError> {
        let relative = paths::relative_path(path)
            .ok_or_else(|| TransportError::other("unsafe target path"))?;
        open(&self.targets_dir.join(relative))
    }
}

fn open(path: &Path) -> Result<ByteStream, TransportError> {
    let mut file = Some(File::open(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => TransportError::NotFound,
        _ => TransportError::other(error),
    })?);
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
                Some(Err(TransportError::other(error)))
            }
        }
    });
    Ok(Box::pin(stream::iter(chunks)))
}
