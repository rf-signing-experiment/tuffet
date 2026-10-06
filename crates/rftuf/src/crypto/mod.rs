//! Cryptographic operations: hashing, signature verification and signing.
//!
//! This module is the only part of the crate that touches cryptography; all
//! other modules use the backend-neutral API defined here. This module also
//! owns the TUF-specific rules: which schemes exist, how `keyval.public`
//! strings encode keys (hex for Ed25519, PEM for the others), the allowed RSA
//! key sizes, and the message ML-DSA signs ([TAP 21]). The primitives
//! themselves come from a backend module selected with a cargo feature:
//!
//! - `rustcrypto` (default): the RustCrypto crates.
//! - `aws-lc-rs`: [AWS-LC](https://github.com/aws/aws-lc) through `aws-lc-rs`.
//!   It takes precedence if both features are enabled; disable default
//!   features to avoid building the RustCrypto crates. For FIPS mode, enable
//!   the `fips` feature of `aws-lc-rs` in your own manifest.
//!
//! The backends behave identically, except that the `aws-lc-rs` backend only
//! verifies RSA-PSS signatures whose salt is as long as the digest, the
//! length that python-tuf, go-tuf and this crate sign with. (`aws-lc-rs`
//! does not support other lengths; the `rustcrypto` backend accepts any.)
//! Also, the `rustcrypto` backend only loads ML-DSA private keys that include
//! the seed; `aws-lc-rs` also loads the expanded form alone.
//!
//! [TAP 21]: https://github.com/theupdateframework/taps/blob/master/tap21.md
//!
//! # Adding a backend
//!
//! A backend is a module that provides these items (see `rustcrypto.rs` and
//! `aws_lc.rs`), gated behind a new cargo feature and selected below:
//!
//! - `Hasher`, with `new(HashAlgorithm)`, `update(&mut self, &[u8])` and
//!   `finalize(self) -> Vec<u8>`.
//! - `verify(Algorithm, public_key: &[u8], message, signature)`. Ed25519
//!   public keys are the raw 32 bytes; other public keys are DER
//!   `SubjectPublicKeyInfo`; ECDSA signatures are DER. ML-DSA is the pure
//!   variant with an empty context (the TAP 21 message is built here). Fails
//!   with `InvalidPublicKey` or `BadSignature`.
//! - `check_public_key(Algorithm, public_key: &[u8])`, which fails with
//!   `InvalidPublicKey` unless `public_key` (encoded as for `verify`) is a
//!   valid key for the algorithm.
//! - `rsa_modulus_bits(public_key: &[u8]) -> Result<usize, CryptoError>`: the
//!   size of the modulus in bits, exactly (not its length in bytes times 8:
//!   a 2047-bit key is not a 2048-bit key).
//! - `SigningKey`, with `generate(Algorithm)`, `from_pkcs8_der(&[u8])`,
//!   `algorithm(&self)`, `public_key(&self)` (encoded as for `verify`) and
//!   `sign(&self, message)`. Generated RSA keys have 3072 bits, RSA keys
//!   loaded from PKCS#8 use RSA-PSS with SHA-256, and RSA-PSS signatures use a
//!   digest-length salt.

use std::borrow::Cow;
use std::error::Error as StdError;
use std::ops::RangeInclusive;

use crate::metadata::{Key, SignatureScheme};

mod signer;

pub use signer::{PrivateKey, Signer};

#[cfg(not(any(feature = "rustcrypto", feature = "aws-lc-rs")))]
compile_error!("rftuf needs a cryptography backend: enable `rustcrypto` or `aws-lc-rs`");

#[cfg(feature = "aws-lc-rs")]
mod aws_lc;
#[cfg(feature = "aws-lc-rs")]
use aws_lc as backend;

// With both features, the RustCrypto backend is compiled but only used by
// tests that compare the two backends.
#[cfg(feature = "rustcrypto")]
#[cfg_attr(feature = "aws-lc-rs", allow(dead_code))]
mod rustcrypto;
#[cfg(all(feature = "rustcrypto", not(feature = "aws-lc-rs")))]
use rustcrypto as backend;

/// RSA key sizes, in bits, that are accepted. The specification requires at
/// least 2048 bits; the upper bound limits the cost of verification.
const RSA_KEY_BITS: RangeInclusive<usize> = 2048..=8192;

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The key type or signature scheme is not supported, or they do not belong together.
    #[error("unsupported key type {keytype:?} with signature scheme {scheme:?}")]
    UnsupportedScheme { keytype: String, scheme: String },

    /// A public key could not be decoded, or has an unacceptable size.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// A private key could not be decoded or generated.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// A signature is malformed or does not verify.
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
/// `ecdsa`/`ecdsa-sha2-nistp256`, `rsa`/`rsassa-pss-sha256`), plus
/// `ecdsa`/`ecdsa-sha2-nistp384`, `rsa`/`rsassa-pss-sha384` and
/// `rsa`/`rsassa-pss-sha512`, which other implementations use, and
/// `ml-dsa`/`ml-dsa-44/1`, `ml-dsa-65/1` and `ml-dsa-87/1` as defined by
/// [TAP 21]. Public keys other than Ed25519 ones are PEM-encoded
/// `SubjectPublicKeyInfo`, RSA keys must have 2048 to 8192 bits, and ECDSA
/// signatures are DER-encoded.
///
/// [TAP 21]: https://github.com/theupdateframework/taps/blob/master/tap21.md
pub fn verify_signature(key: &Key, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let algorithm = Algorithm::from_scheme(&key.scheme)
        .filter(|_| key.scheme.key_type().as_ref() == Some(&key.keytype))
        .ok_or_else(|| CryptoError::UnsupportedScheme {
            keytype: key.keytype.as_str().to_owned(),
            scheme: key.scheme.as_str().to_owned(),
        })?;
    let public_key = algorithm.decode_public_key(&key.keyval.public)?;
    backend::verify(
        algorithm,
        &public_key,
        &algorithm.message(message),
        signature,
    )
}

/// The message that an ML-DSA key signs for a metadata payload (its
/// canonical form), as defined by version 1 of [TAP 21]:
/// `"tuf" || 0x01 || SHA-512(payload)`.
///
/// [`PrivateKey`] and signature verification apply this themselves; a custom
/// [`Signer`] for an ML-DSA key signs this message with pure ML-DSA and an
/// empty context.
///
/// [TAP 21]: https://github.com/theupdateframework/taps/blob/master/tap21.md
pub fn ml_dsa_message(payload: &[u8]) -> Vec<u8> {
    let mut message = b"tuf\x01".to_vec();
    message.extend(HashAlgorithm::Sha512.digest(payload));
    message
}

/// Describes a public key that signs with `scheme` the way metadata lists
/// keys, given its DER-encoded `SubjectPublicKeyInfo`.
///
/// Use this for keys held outside the process, such as in an HSM, a cloud
/// KMS or a hardware token: to implement [`Signer::public_key`] for them, or
/// to list them in metadata. The key is checked to be valid for `scheme`
/// (RSA keys must have 2048 to 8192 bits), and is encoded the way
/// [`PrivateKey`] encodes keys, so that a key always gets the same key ID.
pub fn public_key_from_spki(scheme: &SignatureScheme, der: &[u8]) -> Result<Key, CryptoError> {
    let algorithm = Algorithm::from_scheme(scheme).ok_or_else(|| unsupported_scheme(scheme))?;
    let public_key = match algorithm {
        // Backends take Ed25519 keys as their raw 32 bytes.
        Algorithm::Ed25519 => der
            .strip_prefix(ED25519_SPKI_PREFIX.as_slice())
            .filter(|key| key.len() == 32)
            .ok_or_else(|| {
                CryptoError::InvalidPublicKey("not an Ed25519 SubjectPublicKeyInfo".into())
            })?,
        _ => der,
    };
    backend::check_public_key(algorithm, public_key)?;
    if let Algorithm::RsaPss(_) = algorithm {
        check_rsa_key_size(backend::rsa_modulus_bits(public_key)?)
            .map_err(CryptoError::InvalidPublicKey)?;
    }
    Ok(algorithm.key(public_key))
}

/// Like [`public_key_from_spki`], for a PEM-encoded key
/// (`-----BEGIN PUBLIC KEY-----`).
pub fn public_key_from_pem(scheme: &SignatureScheme, pem: &str) -> Result<Key, CryptoError> {
    let der = decode_pem(pem, "PUBLIC KEY").map_err(CryptoError::InvalidPublicKey)?;
    public_key_from_spki(scheme, &der)
}

/// The DER encoding of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410) up to
/// the key itself: the algorithm identifier and the bit string's header.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The error for a scheme that has no [`Algorithm`] (and so no known key
/// type).
fn unsupported_scheme(scheme: &SignatureScheme) -> CryptoError {
    CryptoError::UnsupportedScheme {
        keytype: String::new(),
        scheme: scheme.to_string(),
    }
}

/// The signature algorithms that backends implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Ed25519,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    RsaPss(RsaPssHash),
    MlDsa(MlDsaParameterSet),
}

/// The hash function of an RSA-PSS algorithm, used both for the message
/// digest and for MGF1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsaPssHash {
    Sha256,
    Sha384,
    Sha512,
}

/// An ML-DSA parameter set (FIPS 204).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MlDsaParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl Algorithm {
    fn from_scheme(scheme: &SignatureScheme) -> Option<Self> {
        match scheme {
            SignatureScheme::Ed25519 => Some(Algorithm::Ed25519),
            SignatureScheme::EcdsaSha2Nistp256 => Some(Algorithm::EcdsaP256Sha256),
            SignatureScheme::EcdsaSha2Nistp384 => Some(Algorithm::EcdsaP384Sha384),
            SignatureScheme::RsassaPssSha256 => Some(Algorithm::RsaPss(RsaPssHash::Sha256)),
            SignatureScheme::RsassaPssSha384 => Some(Algorithm::RsaPss(RsaPssHash::Sha384)),
            SignatureScheme::RsassaPssSha512 => Some(Algorithm::RsaPss(RsaPssHash::Sha512)),
            SignatureScheme::MlDsa44V1 => Some(Algorithm::MlDsa(MlDsaParameterSet::MlDsa44)),
            SignatureScheme::MlDsa65V1 => Some(Algorithm::MlDsa(MlDsaParameterSet::MlDsa65)),
            SignatureScheme::MlDsa87V1 => Some(Algorithm::MlDsa(MlDsaParameterSet::MlDsa87)),
            SignatureScheme::Other(_) => None,
        }
    }

    fn scheme(self) -> SignatureScheme {
        match self {
            Algorithm::Ed25519 => SignatureScheme::Ed25519,
            Algorithm::EcdsaP256Sha256 => SignatureScheme::EcdsaSha2Nistp256,
            Algorithm::EcdsaP384Sha384 => SignatureScheme::EcdsaSha2Nistp384,
            Algorithm::RsaPss(RsaPssHash::Sha256) => SignatureScheme::RsassaPssSha256,
            Algorithm::RsaPss(RsaPssHash::Sha384) => SignatureScheme::RsassaPssSha384,
            Algorithm::RsaPss(RsaPssHash::Sha512) => SignatureScheme::RsassaPssSha512,
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa44) => SignatureScheme::MlDsa44V1,
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa65) => SignatureScheme::MlDsa65V1,
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa87) => SignatureScheme::MlDsa87V1,
        }
    }

    /// The message this algorithm signs for a metadata payload: the payload
    /// itself, except for ML-DSA (TAP 21).
    fn message(self, payload: &[u8]) -> Cow<'_, [u8]> {
        match self {
            Algorithm::MlDsa(_) => Cow::Owned(ml_dsa_message(payload)),
            _ => Cow::Borrowed(payload),
        }
    }

    /// Decodes a `keyval.public` string into the form backends take.
    fn decode_public_key(self, encoded: &str) -> Result<Vec<u8>, CryptoError> {
        if self == Algorithm::Ed25519 {
            return hex::decode(encoded)
                .ok()
                .filter(|key| key.len() == 32)
                .ok_or_else(|| {
                    CryptoError::InvalidPublicKey(
                        "ed25519 public keys must be 32 hex-encoded bytes".into(),
                    )
                });
        }
        let key = decode_pem(encoded, "PUBLIC KEY").map_err(CryptoError::InvalidPublicKey)?;
        if let Algorithm::RsaPss(_) = self {
            check_rsa_key_size(backend::rsa_modulus_bits(&key)?)
                .map_err(CryptoError::InvalidPublicKey)?;
        }
        Ok(key)
    }

    /// Describes a public key, in the form backends take, the way metadata
    /// lists keys.
    fn key(self, public_key: &[u8]) -> Key {
        let scheme = self.scheme();
        let public = match self {
            Algorithm::Ed25519 => hex::encode(public_key),
            _ => pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, public_key)
                .expect("PEM encoding of in-memory data cannot fail"),
        };
        let keytype = scheme
            .key_type()
            .expect("supported schemes have a key type");
        Key::new(keytype, scheme, public)
    }
}

/// Decodes PEM with the expected label, such as `PUBLIC KEY`.
fn decode_pem(pem: &str, expected_label: &str) -> Result<Vec<u8>, String> {
    let (label, der) = pem_rfc7468::decode_vec(pem.trim().as_bytes())
        .map_err(|error| format!("invalid PEM: {error}"))?;
    if label != expected_label {
        return Err(format!(
            "expected PEM label {expected_label:?}, found {label:?}"
        ));
    }
    Ok(der)
}

fn check_rsa_key_size(bits: usize) -> Result<(), String> {
    if !RSA_KEY_BITS.contains(&bits) {
        return Err(format!(
            "RSA keys must have {} to {} bits, got {bits}",
            RSA_KEY_BITS.start(),
            RSA_KEY_BITS.end()
        ));
    }
    Ok(())
}

// The tests of this module are in `tests/crypto`. This one compares the
// backends with each other, which needs both of them, and their private API.
#[cfg(all(test, feature = "rustcrypto", feature = "aws-lc-rs"))]
mod backend_parity;
