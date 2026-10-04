//! File hashes, and verification of files against trusted metadata.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{HexBytes, MetaFile, TargetFile};
use crate::crypto::{HashAlgorithm, Hasher};
use crate::error::{Error, Result};

/// A `HASHES` object: digests of a file, keyed by hash algorithm name.
///
/// Algorithms this implementation does not support are preserved but ignored
/// during verification. A file can only be verified if at least one supported
/// algorithm is listed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hashes(BTreeMap<String, HexBytes>);

impl Hashes {
    pub fn new() -> Self {
        Hashes::default()
    }

    /// Hashes `data` with each of `algorithms`.
    pub fn compute(data: &[u8], algorithms: &[HashAlgorithm]) -> Self {
        let digests = algorithms
            .iter()
            .map(|alg| (alg.name().to_owned(), HexBytes::new(alg.digest(data))))
            .collect();
        Hashes(digests)
    }

    pub fn insert(&mut self, algorithm: impl Into<String>, digest: impl Into<HexBytes>) {
        self.0.insert(algorithm.into(), digest.into());
    }

    pub fn get(&self, algorithm: &str) -> Option<&HexBytes> {
        self.0.get(algorithm)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &HexBytes)> {
        self.0.iter().map(|(alg, digest)| (alg.as_str(), digest))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The digest to use where a single one is needed, such as the file name
    /// prefix of a target with consistent snapshots: that of the most
    /// preferred supported algorithm.
    pub fn preferred(&self) -> Option<&HexBytes> {
        self.supported().next().map(|(_, digest)| digest)
    }

    /// The listed digests whose algorithms are supported, most preferred first.
    fn supported(&self) -> impl Iterator<Item = (HashAlgorithm, &HexBytes)> {
        HashAlgorithm::ALL
            .into_iter()
            .filter_map(|alg| Some((alg, self.0.get(alg.name())?)))
    }
}

/// Checks a file against the length and hashes listed for it in trusted
/// metadata, incrementally as it is downloaded.
///
/// [`update`](Self::update) fails as soon as more data arrives than the file
/// may have, so that an attacker cannot send endless data;
/// [`finish`](Self::finish) then checks the exact length and the hashes.
pub struct FileVerifier {
    name: String,
    max_length: u64,
    expected_length: Option<u64>,
    received: u64,
    hashers: Vec<(HashAlgorithm, Hasher, HexBytes)>,
}

impl FileVerifier {
    /// Only checks that the file is at most `max_length` bytes; for files
    /// whose length is unknown, such as timestamp and root metadata.
    pub fn new(name: impl Into<String>, max_length: u64) -> Self {
        FileVerifier {
            name: name.into(),
            max_length,
            expected_length: None,
            received: 0,
            hashers: Vec::new(),
        }
    }

    /// Checks a target file against its exact length and its hashes.
    pub fn for_target(name: impl Into<String>, target: &TargetFile) -> Result<Self> {
        Self::new(name, target.length)
            .expect_length(target.length)
            .expect_hashes(&target.hashes)
    }

    /// Checks a metadata file against the length and hashes, if any, listed
    /// for it in snapshot or timestamp metadata. `max_length` limits the file
    /// if its length is not listed.
    pub fn for_meta(name: impl Into<String>, meta: &MetaFile, max_length: u64) -> Result<Self> {
        let mut verifier = Self::new(name, max_length);
        if let Some(length) = meta.length {
            verifier = verifier.expect_length(length);
        }
        match &meta.hashes {
            Some(hashes) => verifier.expect_hashes(hashes),
            None => Ok(verifier),
        }
    }

    fn expect_length(mut self, length: u64) -> Self {
        self.expected_length = Some(length);
        self.max_length = length;
        self
    }

    fn expect_hashes(mut self, hashes: &Hashes) -> Result<Self> {
        self.hashers = hashes
            .supported()
            .map(|(alg, digest)| (alg, alg.hasher(), digest.clone()))
            .collect();
        if self.hashers.is_empty() {
            return Err(Error::NoSupportedHash { name: self.name });
        }
        Ok(self)
    }

    /// Processes the next chunk of the file.
    pub fn update(&mut self, chunk: &[u8]) -> Result<()> {
        self.received = self.received.saturating_add(chunk.len() as u64);
        if self.received > self.max_length {
            return Err(Error::TooLarge {
                name: self.name.clone(),
                max: self.max_length,
            });
        }
        for (_, hasher, _) in &mut self.hashers {
            hasher.update(chunk);
        }
        Ok(())
    }

    /// Checks the length and hashes of the complete file.
    pub fn finish(self) -> Result<()> {
        if let Some(expected) = self.expected_length
            && self.received != expected
        {
            return Err(Error::LengthMismatch {
                name: self.name,
                expected,
                actual: self.received,
            });
        }
        for (alg, hasher, expected) in self.hashers {
            if hasher.finalize() != *expected {
                return Err(Error::HashMismatch {
                    name: self.name,
                    algorithm: alg.name().to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Checks a complete file held in memory.
    pub fn verify(mut self, data: &[u8]) -> Result<()> {
        self.update(data)?;
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(data: &[u8]) -> TargetFile {
        TargetFile::from_bytes(data, &HashAlgorithm::ALL)
    }

    #[test]
    fn accepts_matching_files_in_chunks() {
        let data = b"hello world";
        let mut verifier = FileVerifier::for_target("t", &target(data)).unwrap();
        verifier.update(&data[..5]).unwrap();
        verifier.update(&data[5..]).unwrap();
        verifier.finish().unwrap();
    }

    #[test]
    fn rejects_wrong_length_and_content() {
        let expected = target(b"hello world");
        let too_long = FileVerifier::for_target("t", &expected)
            .unwrap()
            .verify(b"hello world!");
        assert!(matches!(too_long, Err(Error::TooLarge { max: 11, .. })));
        let too_short = FileVerifier::for_target("t", &expected)
            .unwrap()
            .verify(b"hello");
        assert!(matches!(
            too_short,
            Err(Error::LengthMismatch {
                expected: 11,
                actual: 5,
                ..
            })
        ));
        let tampered = FileVerifier::for_target("t", &expected)
            .unwrap()
            .verify(b"hello World");
        assert!(
            matches!(tampered, Err(Error::HashMismatch { algorithm, .. }) if algorithm == "sha256")
        );
    }

    #[test]
    fn every_supported_hash_must_match() {
        let mut expected = target(b"data");
        expected.hashes.insert("sha512", vec![0; 64]);
        let result = FileVerifier::for_target("t", &expected)
            .unwrap()
            .verify(b"data");
        assert!(
            matches!(result, Err(Error::HashMismatch { algorithm, .. }) if algorithm == "sha512")
        );
    }

    #[test]
    fn unsupported_hashes_are_ignored_but_one_must_be_supported() {
        let mut expected = target(b"data");
        expected.hashes.insert("blake2b-256", vec![1; 32]);
        FileVerifier::for_target("t", &expected)
            .unwrap()
            .verify(b"data")
            .unwrap();

        let mut unverifiable = Hashes::new();
        unverifiable.insert("md5", vec![0; 16]);
        expected.hashes = unverifiable;
        assert!(matches!(
            FileVerifier::for_target("t", &expected),
            Err(Error::NoSupportedHash { .. })
        ));
    }

    #[test]
    fn meta_files_without_length_are_bounded_by_the_limit() {
        let meta = MetaFile::new(1);
        FileVerifier::for_meta("m", &meta, 4)
            .unwrap()
            .verify(b"1234")
            .unwrap();
        let result = FileVerifier::for_meta("m", &meta, 4)
            .unwrap()
            .verify(b"12345");
        assert!(matches!(result, Err(Error::TooLarge { max: 4, .. })));
    }

    #[test]
    fn preferred_digest_is_sha256() {
        let hashes = Hashes::compute(b"x", &[HashAlgorithm::Sha512, HashAlgorithm::Sha256]);
        assert_eq!(hashes.preferred().unwrap().len(), 32);
    }
}
