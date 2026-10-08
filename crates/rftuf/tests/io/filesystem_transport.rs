//! `FilesystemTransport` reads a repository from local directories: metadata
//! files by name, and target files by path below the targets directory.
//! Names and paths come from metadata, so they must not escape their
//! directory.

use futures_executor::block_on;
use futures_util::TryStreamExt;
use rftuf::transport::{FilesystemTransport, Transport, TransportError};

use crate::support::{assert_err, read};

/// A transport whose metadata directory holds `secret` and `timestamp.json`
/// and whose targets directory holds `sub/file.bin`.
fn transport() -> (tempfile::TempDir, FilesystemTransport) {
    let dir = tempfile::tempdir().unwrap();
    let (metadata, targets) = (dir.path().join("metadata"), dir.path().join("targets"));
    std::fs::create_dir_all(targets.join("sub")).unwrap();
    std::fs::create_dir_all(&metadata).unwrap();
    std::fs::write(dir.path().join("secret"), b"secret").unwrap();
    std::fs::write(metadata.join("secret"), b"secret").unwrap();
    std::fs::write(metadata.join("timestamp.json"), b"metadata").unwrap();
    std::fs::write(targets.join("sub/file.bin"), b"target").unwrap();
    (dir, FilesystemTransport::new(metadata, targets))
}

#[test]
fn reads_metadata_and_targets() {
    let (_dir, transport) = transport();
    assert_eq!(
        read(block_on(
            transport.fetch_metadata("timestamp.json", u64::MAX)
        )),
        b"metadata"
    );
    assert_eq!(
        read(block_on(transport.fetch_target("sub/file.bin", u64::MAX))),
        b"target"
    );
}

/// Files are streamed in chunks, so a client can stop reading a file that is
/// too long (5.4.1, 5.7.3).
#[test]
fn reads_large_files_in_chunks() {
    let (dir, transport) = transport();
    let large: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    std::fs::write(dir.path().join("targets/large.bin"), &large).unwrap();

    let stream = block_on(transport.fetch_target("large.bin", u64::MAX)).unwrap();
    let chunks: Vec<_> = block_on(stream.try_collect::<Vec<_>>()).unwrap();
    assert!(chunks.len() > 1);
    assert_eq!(chunks.concat(), large);
}

/// Missing files are reported as "not found", which ends the chain of root
/// versions (5.3.3).
#[test]
fn reports_missing_files_as_not_found() {
    let (_dir, transport) = transport();
    assert_err!(
        block_on(transport.fetch_metadata("2.root.json", u64::MAX)),
        TransportError::NotFound
    );
    assert_err!(
        block_on(transport.fetch_target("missing", u64::MAX)),
        TransportError::NotFound
    );
}

#[test]
fn names_and_paths_cannot_escape_their_directory() {
    let (_dir, transport) = transport();
    for name in ["../secret", "sub/secret", "", ".", "..", "nul\0"] {
        assert_err!(
            block_on(transport.fetch_metadata(name, u64::MAX)),
            TransportError::Other(_)
        );
    }
    for path in [
        "../secret",
        "../metadata/secret",
        "/etc/passwd",
        "sub/../../secret",
        "sub//file.bin",
        "./sub/file.bin",
        "sub/",
        "",
        "sub/nul\0",
    ] {
        assert_err!(
            block_on(transport.fetch_target(path, u64::MAX)),
            TransportError::Other(_)
        );
    }
}

/// A path that names a directory cannot be read: the error is reported, when
/// the file is opened or when it is read, rather than taken for "not found".
#[test]
fn reports_files_that_cannot_be_read() {
    let (_dir, transport) = transport();
    let result = block_on(async {
        let stream = transport.fetch_target("sub", u64::MAX).await?;
        stream.map_ok(|chunk| chunk.to_vec()).try_concat().await
    });
    assert_err!(result, TransportError::Other(_));

    // A path that goes through a file cannot be opened.
    if cfg!(unix) {
        assert_err!(
            block_on(transport.fetch_target("sub/file.bin/inside", u64::MAX)),
            TransportError::Other(_)
        );
    }
}
