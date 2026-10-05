//! Signing metadata.

use std::fmt;

use super::{Algorithm, CryptoError, backend, check_rsa_key_size, decode_pem, unsupported_scheme};
use crate::metadata::{Key, SignatureScheme};

/// Something that can sign metadata.
///
/// [`PrivateKey`] implements this for in-memory keys. Implement it yourself
/// to sign with keys held elsewhere, such as in an HSM or a cloud KMS;
/// [`public_key_from_spki`](super::public_key_from_spki) describes their
/// public keys.
pub trait Signer: Send + Sync {
    /// The public half of the signing key, as it appears in metadata.
    fn public_key(&self) -> &Key;

    /// Signs `message` (the canonical form of a metadata payload) and returns
    /// the raw signature bytes, encoded as required by the key's scheme.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// An in-memory private key.
pub struct PrivateKey {
    inner: backend::SigningKey,
    public: Key,
}

impl PrivateKey {
    /// Generates a new random key for `scheme`.
    ///
    /// RSA keys are 3072 bits.
    pub fn generate(scheme: &SignatureScheme) -> Result<Self, CryptoError> {
        let algorithm = Algorithm::from_scheme(scheme).ok_or_else(|| unsupported_scheme(scheme))?;
        Self::from_backend(backend::SigningKey::generate(algorithm)?)
    }

    /// Loads a DER-encoded PKCS#8 private key (Ed25519, ECDSA P-256/P-384 or RSA).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        Self::from_backend(backend::SigningKey::from_pkcs8_der(der)?)
    }

    /// Loads a PEM-encoded PKCS#8 private key (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let der = decode_pem(pem, "PRIVATE KEY").map_err(CryptoError::InvalidPrivateKey)?;
        Self::from_pkcs8_der(&der)
    }

    fn from_backend(inner: backend::SigningKey) -> Result<Self, CryptoError> {
        let algorithm = inner.algorithm();
        let public_key = inner.public_key()?;
        if algorithm == Algorithm::RsaPssSha256 {
            check_rsa_key_size(backend::rsa_modulus_bits(&public_key)?)
                .map_err(CryptoError::InvalidPrivateKey)?;
        }
        let public = Key::new(
            algorithm.key_type(),
            algorithm.scheme(),
            algorithm.encode_public_key(&public_key),
        );
        Ok(PrivateKey { inner, public })
    }
}

impl Signer for PrivateKey {
    fn public_key(&self) -> &Key {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.sign(message)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
