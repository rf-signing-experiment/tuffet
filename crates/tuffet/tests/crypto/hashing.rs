//! The hash algorithms of HASHES objects (4.4, 4.5) and key IDs (4.2.1):
//! SHA-256 and SHA-512, named as in metadata.

use tuffet::crypto::HashAlgorithm;

/// The "abc" examples of FIPS 180-2.
#[test]
fn digests_match_known_values() {
    assert_eq!(
        hex::encode(HashAlgorithm::Sha256.digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex::encode(HashAlgorithm::Sha512.digest(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
}

#[test]
fn digests_can_be_computed_incrementally() {
    for algorithm in HashAlgorithm::ALL {
        let mut hasher = algorithm.hasher();
        hasher.update(b"a");
        hasher.update(b"");
        hasher.update(b"bc");
        assert_eq!(hasher.finalize(), algorithm.digest(b"abc"), "{algorithm:?}");
    }
}

#[test]
fn algorithms_are_named_as_in_metadata() {
    for (name, algorithm) in [
        ("sha256", HashAlgorithm::Sha256),
        ("sha512", HashAlgorithm::Sha512),
    ] {
        assert_eq!(algorithm.name(), name);
        assert_eq!(HashAlgorithm::from_name(name), Some(algorithm));
    }
    for unsupported in ["md5", "sha1", "SHA256", "blake2b-256"] {
        assert_eq!(HashAlgorithm::from_name(unsupported), None);
    }
}
