//! Signing metadata.

use std::fmt;

use super::{CryptoError, backend};
use crate::metadata::{Key, SignatureScheme};

/// Something that can sign metadata.
///
/// [`PrivateKey`] implements this for in-memory keys. Implement it yourself
/// to sign with keys held elsewhere, such as in an HSM or a cloud KMS.
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
        Self::from_backend(backend::SigningKey::generate(scheme)?)
    }

    /// Loads a DER-encoded PKCS#8 private key (Ed25519, ECDSA P-256/P-384 or RSA).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        Self::from_backend(backend::SigningKey::from_pkcs8_der(der)?)
    }

    /// Loads a PEM-encoded PKCS#8 private key (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        Self::from_backend(backend::SigningKey::from_pkcs8_pem(pem)?)
    }

    fn from_backend(inner: backend::SigningKey) -> Result<Self, CryptoError> {
        let scheme = inner.scheme();
        let keytype = scheme.key_type().expect("backend keys use known schemes");
        let public = Key::new(keytype, scheme, inner.public_key()?);
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
