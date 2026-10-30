//! Cryptography: the key types and signature schemes of 4.2.2 and TAP 21,
//! and hashing, through the public API of the `crypto` module.
//!
//! Keys and signatures made with OpenSSL (`tests/data/crypto`; see its
//! README) check that tuffet interoperates with other implementations. These
//! tests run against the cryptography backend the crate is built with: run
//! them with `--no-default-features -F aws-lc-rs` too. Where the backends
//! behave differently (see "Features" in the README), the tests say so.

#[path = "../support/mod.rs"]
mod support;

// SHA-256 and SHA-512
mod hashing;

// What every signature scheme does
mod schemes;

// 4.2.2 "ed25519"
mod ed25519;

// 4.2.2 "ecdsa"
mod ecdsa;

// 4.2.2 "rsa"
mod rsa;

// TAP 21 ML-DSA
mod ml_dsa;

// Keys held elsewhere: `public_key_from_spki` and `public_key_from_pem`
mod public_keys;

// `PrivateKey` and custom `Signer`s
mod signers;

use tuffet::metadata::{Key, SignatureScheme};

/// The message that the OpenSSL signatures in `tests/data/crypto` sign.
fn message() -> Vec<u8> {
    support::data::crypto("message.txt")
}

/// A key as metadata lists it: for `scheme`, with the public key in the
/// file `public` of `tests/data/crypto`.
fn key(scheme: SignatureScheme, public: &str) -> Key {
    Key::new(
        scheme.key_type().unwrap(),
        scheme,
        support::data::crypto_text(public),
    )
}
