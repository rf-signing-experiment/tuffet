//! `FilesystemTransport` reads a repository from local directories: metadata
//! files by name, and target files by path below the targets directory.
//! Names and paths come from metadata, so they must not escape their
//! directory.

use futures_executor::block_on;
use futures_util::TryStreamExt;
use rftuf::transport::{ByteStream, FilesystemTransport, Transport, TransportError};

use crate::support::assert_err;

fn read(stream: ByteStream) -> Vec<u8> {
    block_on(stream.map_ok(|chunk| chunk.to_vec()).try_concat()).unwrap()
}

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
        read(block_on(transport.fetch_metadata("timestamp.json")).unwrap()),
        b"metadata"
    );
    assert_eq!(
        read(block_on(transport.fetch_target("sub/file.bin")).unwrap()),
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

    let stream = block_on(transport.fetch_target("large.bin")).unwrap();
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
        block_on(transport.fetch_metadata("2.root.json")),
        TransportError::NotFound(name) if name == "2.root.json"
    );
    assert_err!(
        block_on(transport.fetch_target("missing")),
        TransportError::NotFound(name) if name == "missing"
    );
}

#[test]
fn names_and_paths_cannot_escape_their_directory() {
    let (_dir, transport) = transport();
    for name in ["../secret", "sub/secret", "", ".", "..", "nul\0"] {
        assert_err!(
            block_on(transport.fetch_metadata(name)),
            TransportError::Other { .. }
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
    ] {
        assert_err!(
            block_on(transport.fetch_target(path)),
            TransportError::Other { .. }
        );
    }
}

/// A path that names a directory cannot be read: the error is reported, when
/// the file is opened or when it is read.
#[test]
fn reports_files_that_cannot_be_read() {
    let (_dir, transport) = transport();
    let result = block_on(async {
        let stream = transport.fetch_target("sub").await?;
        stream.map_ok(|chunk| chunk.to_vec()).try_concat().await
    });
    assert_err!(result, TransportError::Other { path, .. } if path == "sub");

    // A path that goes through a file cannot be opened.
    if cfg!(unix) {
        assert_err!(
            block_on(transport.fetch_target("sub/file.bin/inside")),
            TransportError::Other { .. }
        );
    }
}
