//! The fixtures in `tests/data`; see `tests/data/README.md`.

use std::path::PathBuf;

/// The path of a file in `tests/data`.
pub fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// A metadata file of the reference implementation's (python-tuf's) test
/// repository, such as `root.json`.
pub fn python_tuf(name: &str) -> Vec<u8> {
    read(&format!("python-tuf/metadata/{name}"))
}

/// A key or signature in `tests/data/crypto`, such as `p256.pub.pem`.
pub fn crypto(name: &str) -> Vec<u8> {
    read(&format!("crypto/{name}"))
}

/// A text file in `tests/data/crypto` (such as a PEM key or a hex-encoded
/// Ed25519 public key), without surrounding whitespace.
pub fn crypto_text(name: &str) -> String {
    String::from_utf8(crypto(name)).unwrap().trim().to_owned()
}

fn read(name: &str) -> Vec<u8> {
    let path = path(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}
