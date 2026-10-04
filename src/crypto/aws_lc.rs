//! The cryptography backend built on AWS-LC, through `aws-lc-rs`.

use aws_lc_rs::digest;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{self, KeySize};
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair, ParsedPublicKey,
    RsaKeyPair, VerificationAlgorithm,
};

use super::{Algorithm, CryptoError, HashAlgorithm};

const GENERATED_RSA_SIZE: KeySize = KeySize::Rsa3072;

pub(super) struct Hasher(digest::Context);

impl Hasher {
    pub(super) fn new(algorithm: HashAlgorithm) -> Self {
        Hasher(digest::Context::new(match algorithm {
            HashAlgorithm::Sha256 => &digest::SHA256,
            HashAlgorithm::Sha512 => &digest::SHA512,
        }))
    }

    pub(super) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub(super) fn finalize(self) -> Vec<u8> {
        self.0.finish().as_ref().to_vec()
    }
}

pub(super) fn verify(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verification: &'static dyn VerificationAlgorithm = match algorithm {
        Algorithm::Ed25519 => &signature::ED25519,
        Algorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
        Algorithm::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
        // aws-lc-rs only verifies PSS signatures with a digest-length salt.
        Algorithm::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
    };
    ParsedPublicKey::new(verification, public_key)
        .map_err(invalid_public_key)?
        .verify_sig(message, signature)
        .map_err(|_| CryptoError::BadSignature)
}

pub(super) fn rsa_modulus_bits(public_key: &[u8]) -> Result<usize, CryptoError> {
    let key = rsa::PublicKey::from_der(public_key).map_err(invalid_public_key)?;
    Ok(key.modulus_len() * 8)
}

pub(super) enum SigningKey {
    Ed25519(Ed25519KeyPair),
    Ecdsa(Algorithm, EcdsaKeyPair),
    RsaPssSha256(RsaKeyPair),
}

impl SigningKey {
    pub(super) fn generate(algorithm: Algorithm) -> Result<Self, CryptoError> {
        let key = match algorithm {
            Algorithm::Ed25519 => Ed25519KeyPair::generate().map(Self::Ed25519),
            Algorithm::EcdsaP256Sha256 | Algorithm::EcdsaP384Sha384 => {
                EcdsaKeyPair::generate(ecdsa_signing(algorithm))
                    .map(|key| Self::Ecdsa(algorithm, key))
            }
            Algorithm::RsaPssSha256 => {
                RsaKeyPair::generate(GENERATED_RSA_SIZE).map(Self::RsaPssSha256)
            }
        };
        key.map_err(invalid_private_key)
    }

    pub(super) fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        // The PKCS#8 structure names its algorithm, so at most one parser
        // accepts it. OpenSSL writes Ed25519 keys as PKCS#8 v1, which
        // `from_pkcs8` rejects.
        if let Ok(key) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der) {
            return Ok(Self::Ed25519(key));
        }
        for algorithm in [Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384] {
            if let Ok(key) = EcdsaKeyPair::from_pkcs8(ecdsa_signing(algorithm), der) {
                return Ok(Self::Ecdsa(algorithm, key));
            }
        }
        match RsaKeyPair::from_pkcs8(der) {
            Ok(key) => Ok(Self::RsaPssSha256(key)),
            Err(_) => Err(invalid_private_key("unsupported or malformed PKCS#8 key")),
        }
    }

    pub(super) fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Ecdsa(algorithm, _) => *algorithm,
            Self::RsaPssSha256(_) => Algorithm::RsaPssSha256,
        }
    }

    pub(super) fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        let der = match self {
            Self::Ed25519(key) => return Ok(key.public_key().as_ref().to_vec()),
            Self::Ecdsa(_, key) => key.public_key().as_der(),
            Self::RsaPssSha256(key) => key.public_key().as_der(),
        };
        Ok(der.map_err(invalid_private_key)?.as_ref().to_vec())
    }

    pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let rng = SystemRandom::new();
        match self {
            Self::Ed25519(key) => Ok(key.sign(message).as_ref().to_vec()),
            Self::Ecdsa(_, key) => key
                .sign(&rng, message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(signing_error),
            Self::RsaPssSha256(key) => {
                let mut signature = vec![0; key.public_modulus_len()];
                key.sign(&signature::RSA_PSS_SHA256, &rng, message, &mut signature)
                    .map_err(signing_error)?;
                Ok(signature)
            }
        }
    }
}

/// The signing algorithm for an ECDSA [`Algorithm`]; signatures are DER.
fn ecdsa_signing(algorithm: Algorithm) -> &'static EcdsaSigningAlgorithm {
    match algorithm {
        Algorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        Algorithm::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        Algorithm::Ed25519 | Algorithm::RsaPssSha256 => unreachable!("{algorithm:?} is not ECDSA"),
    }
}

fn invalid_public_key(error: impl ToString) -> CryptoError {
    CryptoError::InvalidPublicKey(error.to_string())
}

fn invalid_private_key(error: impl ToString) -> CryptoError {
    CryptoError::InvalidPrivateKey(error.to_string())
}

fn signing_error(error: aws_lc_rs::error::Unspecified) -> CryptoError {
    CryptoError::Signing(Box::new(error))
}
