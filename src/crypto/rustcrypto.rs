//! The cryptography backend built on the RustCrypto crates.

use ed25519_dalek as ed25519;
use getrandom::SysRng;
use p256::elliptic_curve::Generate;
use rand_core::UnwrapErr;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer as _, Verifier as _};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};

use super::{Algorithm, CryptoError, HashAlgorithm};

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
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let result = match algorithm {
        Algorithm::Ed25519 => {
            let public_key = public_key.try_into().map_err(invalid_public_key)?;
            let key = ed25519::VerifyingKey::from_bytes(public_key).map_err(invalid_public_key)?;
            let Ok(signature) = ed25519::Signature::from_slice(signature) else {
                return Err(CryptoError::BadSignature);
            };
            key.verify_strict(message, &signature)
        }
        Algorithm::EcdsaP256Sha256 => {
            use p256::ecdsa::{Signature, VerifyingKey};
            let key = VerifyingKey::from_public_key_der(public_key).map_err(invalid_public_key)?;
            Signature::from_der(signature).and_then(|signature| key.verify(message, &signature))
        }
        Algorithm::EcdsaP384Sha384 => {
            use p384::ecdsa::{Signature, VerifyingKey};
            let key = VerifyingKey::from_public_key_der(public_key).map_err(invalid_public_key)?;
            Signature::from_der(signature).and_then(|signature| key.verify(message, &signature))
        }
        Algorithm::RsaPssSha256 => {
            let key = RsaPublicKey::from_public_key_der(public_key).map_err(invalid_public_key)?;
            // Signers disagree on the PSS salt length (python-tuf and go-tuf
            // use the digest length, OpenSSL defaults to the maximum), so
            // detect it.
            let key = rsa::pss::VerifyingKey::<Sha256>::new_with_auto_salt_len(key);
            rsa::pss::Signature::try_from(signature)
                .and_then(|signature| key.verify(message, &signature))
        }
    };
    result.map_err(|_| CryptoError::BadSignature)
}

pub(super) fn rsa_modulus_bits(public_key: &[u8]) -> Result<usize, CryptoError> {
    let key = RsaPublicKey::from_public_key_der(public_key).map_err(invalid_public_key)?;
    Ok(key.size() * 8)
}

pub(super) enum SigningKey {
    Ed25519(ed25519::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    RsaPssSha256(RsaPrivateKey),
}

impl SigningKey {
    pub(super) fn generate(algorithm: Algorithm) -> Result<Self, CryptoError> {
        let mut rng = rng();
        Ok(match algorithm {
            Algorithm::Ed25519 => Self::Ed25519(ed25519::SigningKey::generate(&mut rng)),
            Algorithm::EcdsaP256Sha256 => {
                Self::P256(p256::ecdsa::SigningKey::generate_from_rng(&mut rng))
            }
            Algorithm::EcdsaP384Sha384 => {
                Self::P384(p384::ecdsa::SigningKey::generate_from_rng(&mut rng))
            }
            Algorithm::RsaPssSha256 => Self::RsaPssSha256(
                RsaPrivateKey::new(&mut rng, GENERATED_RSA_BITS).map_err(invalid_private_key)?,
            ),
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
            Ok(key) => Ok(Self::RsaPssSha256(key)),
            Err(_) => Err(invalid_private_key("unsupported or malformed PKCS#8 key")),
        }
    }

    pub(super) fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::P256(_) => Algorithm::EcdsaP256Sha256,
            Self::P384(_) => Algorithm::EcdsaP384Sha384,
            Self::RsaPssSha256(_) => Algorithm::RsaPssSha256,
        }
    }

    pub(super) fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        let der = match self {
            Self::Ed25519(key) => return Ok(key.verifying_key().to_bytes().to_vec()),
            Self::P256(key) => key.verifying_key().to_public_key_der(),
            Self::P384(key) => key.verifying_key().to_public_key_der(),
            Self::RsaPssSha256(key) => key.to_public_key().to_public_key_der(),
        };
        Ok(der.map_err(invalid_private_key)?.into_vec())
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
            Self::RsaPssSha256(key) => rsa::pss::SigningKey::<Sha256>::new(key.clone())
                .sign_with_rng(&mut rng(), message)
                .to_vec(),
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
