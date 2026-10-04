//! The cryptography backend built on the RustCrypto crates.

use ed25519_dalek as ed25519;
use getrandom::SysRng;
use p256::elliptic_curve::Generate;
use rand_core::UnwrapErr;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer as _, Verifier as _};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};

use super::{CryptoError, HashAlgorithm, unsupported_scheme};
use crate::metadata::SignatureScheme;

/// The specification requires RSA keys of at least 2048 bits.
const MIN_RSA_BITS: usize = 2048;
const GENERATED_RSA_BITS: usize = 3072;

pub(super) enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    pub(super) fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha256 => Hasher::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    pub(super) fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(hasher) => hasher.update(data),
            Hasher::Sha512(hasher) => hasher.update(data),
        }
    }

    pub(super) fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha512(hasher) => hasher.finalize().to_vec(),
        }
    }
}

pub(super) fn verify(
    scheme: &SignatureScheme,
    public_key: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    match scheme {
        SignatureScheme::Ed25519 => verify_ed25519(public_key, message, signature),
        SignatureScheme::EcdsaSha2Nistp256 => verify_p256(public_key, message, signature),
        SignatureScheme::EcdsaSha2Nistp384 => verify_p384(public_key, message, signature),
        SignatureScheme::RsassaPssSha256 => verify_rsa_pss_sha256(public_key, message, signature),
        other => Err(unsupported_scheme(other)),
    }
}

fn verify_ed25519(public_key: &str, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let bytes: [u8; ed25519::PUBLIC_KEY_LENGTH] = hex::decode(public_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| invalid_public_key("ed25519 public keys must be 32 hex-encoded bytes"))?;
    let key = ed25519::VerifyingKey::from_bytes(&bytes).map_err(invalid_public_key)?;
    let signature =
        ed25519::Signature::from_slice(signature).map_err(|_| CryptoError::MalformedSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

fn verify_p256(public_key: &str, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    use p256::ecdsa::{Signature, VerifyingKey};
    let key = VerifyingKey::from_public_key_pem(public_key.trim()).map_err(invalid_public_key)?;
    let signature = Signature::from_der(signature).map_err(|_| CryptoError::MalformedSignature)?;
    key.verify(message, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

fn verify_p384(public_key: &str, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    use p384::ecdsa::{Signature, VerifyingKey};
    let key = VerifyingKey::from_public_key_pem(public_key.trim()).map_err(invalid_public_key)?;
    let signature = Signature::from_der(signature).map_err(|_| CryptoError::MalformedSignature)?;
    key.verify(message, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

fn verify_rsa_pss_sha256(
    public_key: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let key = decode_rsa_public_key(public_key)?;
    // Signers disagree on the PSS salt length (python-tuf and go-tuf use the
    // digest length, OpenSSL defaults to the maximum), so detect it.
    let key = rsa::pss::VerifyingKey::<Sha256>::new_with_auto_salt_len(key);
    let signature =
        rsa::pss::Signature::try_from(signature).map_err(|_| CryptoError::MalformedSignature)?;
    key.verify(message, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

/// Decodes an RSA public key from SubjectPublicKeyInfo PEM (or, failing that,
/// PKCS#1 PEM) and enforces the minimum key size.
fn decode_rsa_public_key(pem: &str) -> Result<RsaPublicKey, CryptoError> {
    let pem = pem.trim();
    let key = RsaPublicKey::from_public_key_pem(pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(pem))
        .map_err(invalid_public_key)?;
    let bits = key.size() * 8;
    if bits < MIN_RSA_BITS {
        return Err(invalid_public_key(format!(
            "RSA keys must be at least {MIN_RSA_BITS} bits, got {bits}"
        )));
    }
    Ok(key)
}

pub(super) enum SigningKey {
    Ed25519(ed25519::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    RsaPssSha256(RsaPrivateKey),
}

impl SigningKey {
    pub(super) fn generate(scheme: &SignatureScheme) -> Result<Self, CryptoError> {
        let mut rng = rng();
        Ok(match scheme {
            SignatureScheme::Ed25519 => Self::Ed25519(ed25519::SigningKey::generate(&mut rng)),
            SignatureScheme::EcdsaSha2Nistp256 => {
                Self::P256(p256::ecdsa::SigningKey::generate_from_rng(&mut rng))
            }
            SignatureScheme::EcdsaSha2Nistp384 => {
                Self::P384(p384::ecdsa::SigningKey::generate_from_rng(&mut rng))
            }
            SignatureScheme::RsassaPssSha256 => Self::RsaPssSha256(
                RsaPrivateKey::new(&mut rng, GENERATED_RSA_BITS).map_err(invalid_private_key)?,
            ),
            other => return Err(unsupported_scheme(other)),
        })
    }

    pub(super) fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        // The PKCS#8 structure names its algorithm, so at most one parser accepts it.
        if let Ok(key) = ed25519::SigningKey::from_pkcs8_der(der) {
            return Ok(Self::Ed25519(key));
        }
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Self::P256(key));
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Self::P384(key));
        }
        match RsaPrivateKey::from_pkcs8_der(der) {
            Ok(key) => Self::rsa(key),
            Err(_) => Err(invalid_private_key("unsupported or malformed PKCS#8 key")),
        }
    }

    pub(super) fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let pem = pem.trim();
        if let Ok(key) = ed25519::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::Ed25519(key));
        }
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::P256(key));
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::P384(key));
        }
        match RsaPrivateKey::from_pkcs8_pem(pem) {
            Ok(key) => Self::rsa(key),
            Err(_) => Err(invalid_private_key("unsupported or malformed PKCS#8 key")),
        }
    }

    fn rsa(key: RsaPrivateKey) -> Result<Self, CryptoError> {
        let bits = key.size() * 8;
        if bits < MIN_RSA_BITS {
            return Err(invalid_private_key(format!(
                "RSA keys must be at least {MIN_RSA_BITS} bits, got {bits}"
            )));
        }
        Ok(Self::RsaPssSha256(key))
    }

    pub(super) fn scheme(&self) -> SignatureScheme {
        match self {
            Self::Ed25519(_) => SignatureScheme::Ed25519,
            Self::P256(_) => SignatureScheme::EcdsaSha2Nistp256,
            Self::P384(_) => SignatureScheme::EcdsaSha2Nistp384,
            Self::RsaPssSha256(_) => SignatureScheme::RsassaPssSha256,
        }
    }

    /// The public key, encoded as a TUF `keyval.public` string.
    pub(super) fn public_key(&self) -> Result<String, CryptoError> {
        match self {
            Self::Ed25519(key) => Ok(hex::encode(key.verifying_key().to_bytes())),
            Self::P256(key) => key.verifying_key().to_public_key_pem(LineEnding::LF),
            Self::P384(key) => key.verifying_key().to_public_key_pem(LineEnding::LF),
            Self::RsaPssSha256(key) => key.to_public_key().to_public_key_pem(LineEnding::LF),
        }
        .map_err(invalid_private_key)
    }

    pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(match self {
            Self::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_der().to_vec()
            }
            Self::P384(key) => {
                let signature: p384::ecdsa::Signature = key.sign(message);
                signature.to_der().to_vec()
            }
            Self::RsaPssSha256(key) => {
                // Salt length equals the digest length, as in other TUF implementations.
                rsa::pss::SigningKey::<Sha256>::new(key.clone())
                    .sign_with_rng(&mut rng(), message)
                    .to_vec()
            }
        })
    }
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn invalid_public_key(error: impl ToString) -> CryptoError {
    CryptoError::InvalidPublicKey(error.to_string())
}

fn invalid_private_key(error: impl ToString) -> CryptoError {
    CryptoError::InvalidPrivateKey(error.to_string())
}
