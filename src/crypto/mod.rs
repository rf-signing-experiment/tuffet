//! Cryptographic operations: hashing, signature verification and signing.
//!
//! This module is the only part of the crate that touches cryptography; all
//! other modules use the backend-neutral API defined here. The primitives are
//! implemented by a backend module selected at compile time with a cargo
//! feature. The only backend today is `rustcrypto` (the default).
//!
//! # Adding a backend
//!
//! A backend is a module that provides the same items as `rustcrypto.rs`:
//!
//! - `Hasher`, with `new(HashAlgorithm)`, `update(&mut self, &[u8])` and
//!   `finalize(self) -> Vec<u8>`;
//! - `verify(&SignatureScheme, public_key: &str, message, signature)`, which
//!   decodes the TUF `keyval.public` string for the scheme and verifies;
//! - `SigningKey`, with `generate`, `from_pkcs8_der`, `from_pkcs8_pem`,
//!   `scheme`, `public_key` and `sign`.
//!
//! Gate it behind a new cargo feature and select it below.

use std::error::Error as StdError;

use crate::metadata::{Key, SignatureScheme};

mod signer;

pub use signer::{PrivateKey, Signer};

#[cfg(not(feature = "rustcrypto"))]
compile_error!("rftuf needs a cryptography backend: enable the `rustcrypto` feature");

#[cfg(feature = "rustcrypto")]
mod rustcrypto;
#[cfg(feature = "rustcrypto")]
use rustcrypto as backend;

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The key type or signature scheme is not supported, or they do not belong together.
    #[error("unsupported key type {keytype:?} with signature scheme {scheme:?}")]
    UnsupportedScheme { keytype: String, scheme: String },

    /// A public key could not be decoded, or is too weak.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// A private key could not be decoded or generated.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// A signature is not correctly encoded for its scheme.
    #[error("malformed signature")]
    MalformedSignature,

    /// A signature does not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// A [`Signer`] failed to produce a signature.
    #[error("signing failed")]
    Signing(#[source] Box<dyn StdError + Send + Sync>),
}

/// A cryptographic hash algorithm usable in TUF `hashes` objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    /// All supported algorithms, in order of preference.
    pub const ALL: [HashAlgorithm; 2] = [HashAlgorithm::Sha256, HashAlgorithm::Sha512];

    /// The name used for this algorithm in metadata (e.g. `"sha256"`).
    pub fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        }
    }

    /// Looks up an algorithm by its metadata name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.name() == name)
    }

    /// Starts an incremental hash computation.
    pub fn hasher(self) -> Hasher {
        Hasher(backend::Hasher::new(self))
    }

    /// Hashes `data` in one step.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let mut hasher = self.hasher();
        hasher.update(data);
        hasher.finalize()
    }
}

/// An incremental hash computation, created with [`HashAlgorithm::hasher`].
pub struct Hasher(backend::Hasher);

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize()
    }
}

/// Verifies `signature` over `message` with a public key from metadata.
///
/// The key's `keytype` must match its `scheme`. Supported combinations are
/// those defined by the specification (`ed25519`/`ed25519`,
/// `ecdsa`/`ecdsa-sha2-nistp256`, `rsa`/`rsassa-pss-sha256`) and
/// `ecdsa`/`ecdsa-sha2-nistp384`. RSA keys must be at least 2048 bits, ECDSA
/// signatures are DER-encoded, and RSA-PSS accepts any salt length.
pub fn verify_signature(key: &Key, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    if key.scheme.key_type().as_ref() != Some(&key.keytype) {
        return Err(unsupported(key));
    }
    backend::verify(&key.scheme, &key.keyval.public, message, signature)
}

fn unsupported(key: &Key) -> CryptoError {
    CryptoError::UnsupportedScheme {
        keytype: key.keytype.as_str().to_owned(),
        scheme: key.scheme.as_str().to_owned(),
    }
}

/// The error for a scheme the backend does not implement.
fn unsupported_scheme(scheme: &SignatureScheme) -> CryptoError {
    CryptoError::UnsupportedScheme {
        keytype: scheme
            .key_type()
            .map_or_else(String::new, |kt| kt.as_str().to_owned()),
        scheme: scheme.as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests;
