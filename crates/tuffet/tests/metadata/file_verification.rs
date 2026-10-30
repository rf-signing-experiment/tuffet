//! Checking files against the LENGTH and HASHES that trusted metadata lists
//! for them: metadata files against METAFILES (5.5.2, 5.6.2) and target
//! files against TARGETS (5.7.3).
//!
//! `FileVerifier` checks a file as it is downloaded, so that a download can
//! be cut off as soon as it is longer than allowed (endless data attacks).

use std::assert_matches;

use tuffet::Error;
use tuffet::crypto::HashAlgorithm;
use tuffet::metadata::{FileVerifier, Hashes, MetaFile, TargetFile};

fn target(data: &[u8]) -> TargetFile {
    TargetFile::from_bytes(data, &HashAlgorithm::ALL)
}

#[test]
fn accepts_a_matching_file_in_chunks() {
    let data = b"hello world";
    let mut verifier = FileVerifier::for_target("t", &target(data)).unwrap();
    verifier.update(&data[..5]).unwrap();
    verifier.update(&data[5..]).unwrap();
    verifier.finish().unwrap();
    target(data).verify("t", data).unwrap();
}

/// A file is rejected as soon as it is longer than its LENGTH, before it has
/// been read to the end.
#[test]
fn rejects_a_file_as_soon_as_it_is_too_long() {
    let mut verifier = FileVerifier::for_target("t", &target(b"hello world")).unwrap();
    verifier.update(b"hello world").unwrap();
    assert_matches!(
        verifier.update(b"!"),
        Err(Error::TooLarge { name, max: 11 }) if name == "t"
    );
}

#[test]
fn rejects_a_file_shorter_than_its_length() {
    let result = target(b"hello world").verify("t", b"hello");
    assert_matches!(
        result,
        Err(Error::LengthMismatch {
            expected: 11,
            actual: 5,
            ..
        })
    );
}

#[test]
fn rejects_a_file_with_other_content() {
    let result = target(b"hello world").verify("t", b"hello World");
    assert_matches!(
        result,
        Err(Error::HashMismatch { name, algorithm }) if name == "t" && algorithm == "sha256"
    );
}

/// Every listed hash tuffet supports must match, not just one of them.
#[test]
fn every_supported_hash_must_match() {
    let mut expected = target(b"data");
    expected.hashes.insert("sha512", vec![0; 64]);
    let result = expected.verify("t", b"data");
    assert_matches!(
        result,
        Err(Error::HashMismatch { algorithm, .. }) if algorithm == "sha512"
    );
}

/// Hashes of algorithms tuffet does not support are ignored, but a file can
/// only be verified if at least one supported hash is listed.
#[test]
fn unsupported_hashes_are_ignored_but_one_must_be_supported() {
    let mut expected = target(b"data");
    expected.hashes.insert("blake2b-256", vec![1; 32]);
    expected.verify("t", b"data").unwrap();

    let mut unverifiable = Hashes::new();
    unverifiable.insert("md5", vec![0; 16]);
    expected.hashes = unverifiable;
    assert_matches!(
        FileVerifier::for_target("t", &expected),
        Err(Error::NoSupportedHash { name }) if name == "t"
    );
}

/// METAFILES LENGTH: when it is omitted, "the client MUST use a custom
/// download limit for the listed metadata".
#[test]
fn metadata_without_a_listed_length_is_limited_by_a_maximum() {
    let meta = MetaFile::new(1);
    FileVerifier::for_meta("m", &meta, 4)
        .unwrap()
        .verify(b"1234")
        .unwrap();
    let result = FileVerifier::for_meta("m", &meta, 4)
        .unwrap()
        .verify(b"12345");
    assert_matches!(result, Err(Error::TooLarge { max: 4, .. }));
}

/// METAFILES LENGTH and HASHES are checked when they are listed, and a
/// listed length takes precedence over the maximum.
#[test]
fn metadata_is_checked_against_a_listed_length_and_hashes() {
    let meta = MetaFile::from_bytes(1, b"metadata", &[HashAlgorithm::Sha256]);
    meta.verify("m", b"metadata").unwrap();
    assert_matches!(
        meta.verify("m", b"Metadata"),
        Err(Error::HashMismatch { .. })
    );
    assert_matches!(
        meta.verify("m", b"meta"),
        Err(Error::LengthMismatch {
            expected: 8,
            actual: 4,
            ..
        })
    );
    assert_matches!(
        FileVerifier::for_meta("m", &meta, 1000)
            .unwrap()
            .verify(b"metadata, longer"),
        Err(Error::TooLarge { max: 8, .. })
    );
}

/// METAFILES HASHES: when they are omitted, "the repository MUST guarantee
/// that VERSION alone unambiguously identifies the metadata", so the content
/// is not checked (the client checks the version in it instead).
#[test]
fn metadata_listed_by_version_only_is_not_checked() {
    MetaFile::new(1).verify("m", b"anything").unwrap();
}

/// Where one digest is needed, such as the file name of a target with
/// consistent snapshots (5.7.3), SHA-256 is preferred.
#[test]
fn sha256_is_the_preferred_hash() {
    let both = Hashes::compute(b"x", &[HashAlgorithm::Sha512, HashAlgorithm::Sha256]);
    assert_eq!(both.preferred(), both.get("sha256"));
    let sha512 = Hashes::compute(b"x", &[HashAlgorithm::Sha512]);
    assert_eq!(sha512.preferred(), sha512.get("sha512"));
    let mut unsupported = Hashes::new();
    unsupported.insert("md5", vec![0; 16]);
    assert_eq!(unsupported.preferred(), None);
}
