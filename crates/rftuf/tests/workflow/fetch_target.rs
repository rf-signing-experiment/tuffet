//! 5.7 Fetch target.
//!
//! A target is downloaded only once trusted targets metadata describes it,
//! and only accepted if it has the length and hashes that metadata lists.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_executor::block_on;
use futures_util::stream;
use rftuf::metadata::Hashes;
use rftuf::store::MemoryStore;
use rftuf::transport::{ByteStream, Transport, TransportError};
use rftuf::{Error, Updater};
use serde_json::json;

use crate::support::{RecordingTransport, TestRepo, assert_err, now};

/// A repository with one target, `file`, whose content is `genuine`, and a
/// client that trusts its metadata.
fn repo_with_target() -> (TestRepo, crate::support::Client) {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file", b"genuine");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();
    (repo, client)
}

/// 5.7.1, 5.7.3: the target the search found is downloaded and verified
/// against its targets metadata.
#[test]
fn downloads_and_verifies_a_target() {
    let mut repo = TestRepo::new();
    let listed = repo.add_target("targets", "dir/file.txt", b"hello");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();

    let target = client.get_target_info("dir/file.txt").unwrap().unwrap();
    assert_eq!(target.path, "dir/file.txt");
    assert_eq!(target.role, "targets");
    assert_eq!(target.file, listed);
    assert_eq!(client.download(&target).unwrap(), b"hello");
}

/// 5.7.2: "If there is no targets metadata about this target, abort the
/// update cycle and report that there is no such target."
#[test]
fn reports_that_there_is_no_such_target() {
    let (repo, mut client) = repo_with_target();
    repo.requests();
    assert!(client.get_target_info("missing").unwrap().is_none());
    assert!(repo.requests().is_empty());
}

/// A target that its targets metadata describes, but that the repository
/// does not have, is reported as a missing target, not as missing metadata.
#[test]
fn reports_a_target_that_the_repository_does_not_have() {
    let (repo, mut client) = repo_with_target();
    let target = client.get_target_info("file").unwrap().unwrap();
    repo.transport.inner.remove_target("file");
    assert_err!(
        client.download(&target),
        Error::TargetNotFound(path) if path == "file"
    );
}

/// 5.7.3: the target's hashes must match its targets metadata, so a file
/// other than the one the repository's keys vouch for is rejected
/// (arbitrary installation attacks).
#[test]
fn rejects_a_target_with_other_content() {
    let (mut repo, mut client) = repo_with_target();
    let target = client.get_target_info("file").unwrap().unwrap();
    repo.serve_target("file", b"forged!");
    assert_err!(
        client.download(&target),
        Error::HashMismatch { name, algorithm } if name == "file" && algorithm == "sha256"
    );
}

/// 5.7.3: the target is downloaded "up to the number of bytes specified in
/// the targets metadata", so a server cannot send endless data (endless
/// data attacks).
#[test]
fn stops_downloading_a_target_at_its_listed_length() {
    let (mut repo, mut client) = repo_with_target();
    let target = client.get_target_info("file").unwrap().unwrap();
    repo.serve_target("file", b"genuine, followed by endless data");
    assert_err!(
        client.download(&target),
        Error::TooLarge { name, max: 7 } if name == "file"
    );
}

/// 5.7.3: a target shorter than its listed length is rejected.
#[test]
fn rejects_a_truncated_target() {
    let (mut repo, mut client) = repo_with_target();
    let target = client.get_target_info("file").unwrap().unwrap();
    repo.serve_target("file", b"genuin");
    assert_err!(
        client.download(&target),
        Error::LengthMismatch { name, expected: 7, actual: 6 } if name == "file"
    );
}

/// 5.7.3: "verify that its hashes match": every listed hash that rftuf
/// supports must match, not just one of them.
#[test]
fn every_supported_hash_must_match() {
    let mut repo = TestRepo::new();
    let mut listed = repo.add_target("targets", "file", b"genuine");
    listed.hashes.insert("sha512", vec![0; 64]);
    repo.targets_mut("targets")
        .targets
        .insert("file".to_owned(), listed);
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();

    let target = client.get_target_info("file").unwrap().unwrap();
    assert_err!(
        client.download(&target),
        Error::HashMismatch { algorithm, .. } if algorithm == "sha512"
    );
}

/// 5.7.3: rftuf verifies SHA-256 and SHA-512 hashes. Hashes of other
/// algorithms are ignored, and a target listed only with those cannot be
/// verified, so it is not downloaded at all.
#[test]
fn a_target_without_a_supported_hash_is_not_downloaded() {
    let mut repo = TestRepo::new();
    let mut listed = repo.add_target("targets", "file", b"genuine");
    listed.hashes = Hashes::new();
    listed.hashes.insert("md5", vec![0; 16]);
    repo.targets_mut("targets")
        .targets
        .insert("file".to_owned(), listed);
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();

    let target = client.get_target_info("file").unwrap().unwrap();
    repo.requests();
    assert_err!(client.download(&target), Error::NoSupportedHash { name } if name == "file");
    assert!(repo.requests().is_empty());
}

/// A target whose path could escape the repository's targets location when
/// it is mapped to a URL or a directory is not fetched, whatever the
/// transport and the platform.
#[test]
fn a_target_whose_path_could_escape_the_targets_location_is_not_fetched() {
    let paths = [
        "../file",
        "/file",
        "dir//file",
        "dir\\..\\..\\file",
        "c:file",
    ];
    let mut repo = TestRepo::new();
    for path in paths {
        repo.add_target("targets", path, b"genuine");
    }
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();

    repo.requests();
    for path in paths {
        let target = client.get_target_info(path).unwrap().unwrap();
        assert_err!(client.download(&target), Error::UnsafePath(unsafe_path) if unsafe_path == path);
    }
    assert!(repo.requests().is_empty());
}

/// Transport errors while a target is read are reported with the target's
/// path, as transports need not name the file, and with the transport's own
/// error as their source. A transport that rejects the target as too long
/// partway through reports it as too long, but one that reports it as not
/// found partway through has failed: the file was found.
#[test]
fn reports_transport_errors_while_reading_a_target() {
    /// A transport whose target files fail with the error the function
    /// returns after their first chunk.
    struct FailingTransport(Arc<RecordingTransport>, fn() -> TransportError);

    impl Transport for FailingTransport {
        async fn fetch_metadata(
            &self,
            name: &str,
            max_length: u64,
        ) -> Result<ByteStream, TransportError> {
            self.0.fetch_metadata(name, max_length).await
        }

        async fn fetch_target(&self, _: &str, _: u64) -> Result<ByteStream, TransportError> {
            let chunks = [Ok(Bytes::from_static(b"gen")), Err((self.1)())];
            Ok(Box::pin(stream::iter(chunks)))
        }
    }

    let (repo, _client) = repo_with_target();
    let download = |error: fn() -> TransportError| {
        let transport = FailingTransport(repo.transport.clone(), error);
        let mut updater = Updater::builder(&transport, MemoryStore::new())
            .initial_root(repo.initial_root())
            .build()
            .unwrap();
        block_on(updater.refresh_at(now())).unwrap();
        let target = block_on(updater.get_target_info("file")).unwrap().unwrap();
        block_on(updater.download_target(&target))
    };
    let reset = io::ErrorKind::ConnectionReset;
    assert_err!(
        download(|| TransportError::other(io::Error::from(io::ErrorKind::ConnectionReset))),
        Error::Transport { name, source } if name == "file"
            && source.downcast_ref::<io::Error>().map(io::Error::kind) == Some(reset)
    );
    assert_err!(
        download(|| TransportError::TooLarge),
        Error::TooLarge { name, max: 7 } if name == "file"
    );
    assert_err!(
        download(|| TransportError::NotFound),
        Error::Transport { name, .. } if name == "file"
    );
}

/// 5.7.3: "the client MUST write the file to non-volatile storage as
/// FILENAME.EXT". `download_target_to` writes it where the application asks,
/// and only once it has been verified: on failure, no file is left behind.
#[test]
fn downloading_to_a_file_writes_only_verified_data() {
    let (mut repo, mut client) = repo_with_target();
    let target = client.get_target_info("file").unwrap().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("file");

    block_on(client.updater.download_target_to(&target, &destination)).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"genuine");

    std::fs::remove_file(&destination).unwrap();
    repo.serve_target("file", b"forged!");
    assert_err!(
        block_on(client.updater.download_target_to(&target, &destination)),
        Error::HashMismatch { .. }
    );
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "neither the file nor a temporary file is left"
    );
}

/// `download_target_to` writes the target to a temporary file in the
/// destination's directory, so that moving it into place once it is verified
/// is atomic, and the destination never holds unverified data.
#[test]
fn downloading_to_a_file_writes_a_temporary_file_next_to_it() {
    /// A transport that lists a directory when it fetches a target.
    struct ListingTransport {
        inner: Arc<RecordingTransport>,
        dir: PathBuf,
        listed: Mutex<Vec<String>>,
    }

    impl Transport for ListingTransport {
        async fn fetch_metadata(
            &self,
            name: &str,
            max_length: u64,
        ) -> Result<ByteStream, TransportError> {
            self.inner.fetch_metadata(name, max_length).await
        }

        async fn fetch_target(
            &self,
            path: &str,
            max_length: u64,
        ) -> Result<ByteStream, TransportError> {
            let files = std::fs::read_dir(&self.dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            *self.listed.lock().unwrap() = files;
            self.inner.fetch_target(path, max_length).await
        }
    }

    let (repo, _client) = repo_with_target();
    let dir = tempfile::tempdir().unwrap();
    let transport = ListingTransport {
        inner: repo.transport.clone(),
        dir: dir.path().to_owned(),
        listed: Mutex::default(),
    };
    let mut updater = Updater::builder(&transport, MemoryStore::new())
        .initial_root(repo.initial_root())
        .build()
        .unwrap();
    block_on(updater.refresh_at(now())).unwrap();
    let target = block_on(updater.get_target_info("file")).unwrap().unwrap();
    let destination = dir.path().join("file");
    block_on(updater.download_target_to(&target, &destination)).unwrap();

    let listed = transport.listed.lock().unwrap().clone();
    let [temporary] = &listed[..] else {
        panic!("one temporary file expected, found {listed:?}");
    };
    assert_ne!(temporary, "file");
    assert_eq!(std::fs::read(&destination).unwrap(), b"genuine");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

/// A verified target that cannot be moved into place (here, because the
/// destination is a directory) is reported, and leaves no temporary file.
#[test]
fn downloading_to_a_file_reports_when_the_file_cannot_be_written() {
    let (_repo, mut client) = repo_with_target();
    let target = client.get_target_info("file").unwrap().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("file");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("inside"), b"").unwrap();

    assert_err!(
        block_on(client.updater.download_target_to(&target, &destination)),
        Error::Io(_)
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

/// `TargetInfo::verify` checks a target downloaded by other means against its
/// targets metadata (5.7.3).
#[test]
fn targets_downloaded_by_other_means_can_be_verified() {
    let (_repo, mut client) = repo_with_target();
    let target = client.get_target_info("file").unwrap().unwrap();
    target.verify(b"genuine").unwrap();
    assert_err!(target.verify(b"forged!"), Error::HashMismatch { .. });
    assert_err!(target.verify(b"genuine!"), Error::TooLarge { .. });
}

/// `TargetInfo::matches_file` checks a file against the trusted length and
/// hashes, for example to skip downloading a target again.
#[test]
fn matches_file_checks_length_and_hashes() {
    let (_repo, mut client) = repo_with_target();
    let target = client.get_target_info("file").unwrap().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");

    assert!(!target.matches_file(&path).unwrap(), "missing");
    std::fs::write(&path, b"genuine").unwrap();
    assert!(target.matches_file(&path).unwrap());
    std::fs::write(&path, b"Genuine").unwrap();
    assert!(!target.matches_file(&path).unwrap(), "other content");
    std::fs::write(&path, b"genuine and more").unwrap();
    assert!(!target.matches_file(&path).unwrap(), "longer");

    // Without a supported hash, no file can be shown to be the target.
    let mut unverifiable = target.clone();
    unverifiable.file.hashes = Hashes::new();
    unverifiable.file.hashes.insert("md5", vec![0; 16]);
    std::fs::write(&path, b"genuine").unwrap();
    assert!(
        !unverifiable.matches_file(&path).unwrap(),
        "no supported hash"
    );

    // Other errors than a missing file are reported (here, a path that goes
    // through a file).
    if cfg!(unix) {
        assert!(target.matches_file(&path.join("inside")).is_err());
    }
}

/// 4.5 (CUSTOM): "the elements and values of the CUSTOM object will be made
/// available to the client application".
#[test]
fn custom_target_metadata_is_made_available_to_the_application() {
    let mut repo = TestRepo::new();
    let mut listed = repo.add_target("targets", "file", b"genuine");
    listed.custom = Some(json!({"version": "1.2", "requires": ["libc"]}));
    repo.targets_mut("targets")
        .targets
        .insert("file".to_owned(), listed);
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();

    let target = client.get_target_info("file").unwrap().unwrap();
    assert_eq!(
        target.file.custom,
        Some(json!({"version": "1.2", "requires": ["libc"]}))
    );
}
