//! 5.7 Fetch target.
//!
//! A target is downloaded only once trusted targets metadata describes it,
//! and only accepted if it has the length and hashes that metadata lists.

use futures_executor::block_on;
use rftuf::Error;
use rftuf::metadata::Hashes;
use serde_json::json;

use crate::support::{TestRepo, assert_err};

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
