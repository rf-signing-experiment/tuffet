//! The cryptography backend built on AWS-LC, through `aws-lc-rs`.

use aws_lc_rs::digest;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{self, KeySize};
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair, ParsedPublicKey,
    PqdsaKeyPair, PqdsaSigningAlgorithm, RsaKeyPair, VerificationAlgorithm,
};

use super::{Algorithm, CryptoError, HashAlgorithm, MlDsaParameterSet, RsaPssHash};

const ML_DSA_PARAMETER_SETS: [MlDsaParameterSet; 3] = [
    MlDsaParameterSet::MlDsa44,
    MlDsaParameterSet::MlDsa65,
    MlDsaParameterSet::MlDsa87,
];

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
    parse_public_key(algorithm, public_key)?
        .verify_sig(message, signature)
        .map_err(|_| CryptoError::BadSignature)
}

pub(super) fn check_public_key(algorithm: Algorithm, public_key: &[u8]) -> Result<(), CryptoError> {
    parse_public_key(algorithm, public_key).map(drop)
}

fn parse_public_key(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<ParsedPublicKey, CryptoError> {
    let verification: &'static dyn VerificationAlgorithm = match algorithm {
        Algorithm::Ed25519 => &signature::ED25519,
        Algorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
        Algorithm::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
        // aws-lc-rs only verifies PSS signatures with a digest-length salt.
        Algorithm::RsaPss(RsaPssHash::Sha256) => &signature::RSA_PSS_2048_8192_SHA256,
        Algorithm::RsaPss(RsaPssHash::Sha384) => &signature::RSA_PSS_2048_8192_SHA384,
        Algorithm::RsaPss(RsaPssHash::Sha512) => &signature::RSA_PSS_2048_8192_SHA512,
        // Pure ML-DSA with an empty context.
        Algorithm::MlDsa(MlDsaParameterSet::MlDsa44) => &signature::ML_DSA_44,
        Algorithm::MlDsa(MlDsaParameterSet::MlDsa65) => &signature::ML_DSA_65,
        Algorithm::MlDsa(MlDsaParameterSet::MlDsa87) => &signature::ML_DSA_87,
    };
    ParsedPublicKey::new(verification, public_key).map_err(invalid_public_key)
}

pub(super) fn rsa_modulus_bits(public_key: &[u8]) -> Result<usize, CryptoError> {
    let key = rsa::PublicKey::from_der(public_key).map_err(invalid_public_key)?;
    let modulus = key.modulus();
    let modulus = modulus.big_endian_without_leading_zero();
    let leading_zero_bits = modulus.first().map_or(0, |first| first.leading_zeros());
    Ok(modulus.len() * 8 - leading_zero_bits as usize)
}

pub(super) enum SigningKey {
    Ed25519(Ed25519KeyPair),
    Ecdsa(Algorithm, EcdsaKeyPair),
    RsaPss(RsaPssHash, RsaKeyPair),
    MlDsa(MlDsaParameterSet, PqdsaKeyPair),
}

impl SigningKey {
    pub(super) fn generate(algorithm: Algorithm) -> Result<Self, CryptoError> {
        let key = match algorithm {
            Algorithm::Ed25519 => Ed25519KeyPair::generate().map(Self::Ed25519),
            Algorithm::EcdsaP256Sha256 | Algorithm::EcdsaP384Sha384 => {
                EcdsaKeyPair::generate(ecdsa_signing(algorithm))
                    .map(|key| Self::Ecdsa(algorithm, key))
            }
            Algorithm::RsaPss(hash) => {
                RsaKeyPair::generate(GENERATED_RSA_SIZE).map(|key| Self::RsaPss(hash, key))
            }
            Algorithm::MlDsa(set) => {
                PqdsaKeyPair::generate(ml_dsa_signing(set)).map(|key| Self::MlDsa(set, key))
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
        for set in ML_DSA_PARAMETER_SETS {
            if let Ok(key) = PqdsaKeyPair::from_pkcs8(ml_dsa_signing(set), der) {
                return Ok(Self::MlDsa(set, key));
            }
        }
        match RsaKeyPair::from_pkcs8(der) {
            Ok(key) => Ok(Self::RsaPss(RsaPssHash::Sha256, key)),
            Err(_) => Err(invalid_private_key("unsupported or malformed PKCS#8 key")),
        }
    }

    pub(super) fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Ecdsa(algorithm, _) => *algorithm,
            Self::RsaPss(hash, _) => Algorithm::RsaPss(*hash),
            Self::MlDsa(set, _) => Algorithm::MlDsa(*set),
        }
    }

    pub(super) fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        let der = match self {
            Self::Ed25519(key) => return Ok(key.public_key().as_ref().to_vec()),
            Self::Ecdsa(_, key) => key.public_key().as_der(),
            Self::RsaPss(_, key) => key.public_key().as_der(),
            Self::MlDsa(_, key) => key.public_key().as_der(),
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
            Self::RsaPss(hash, key) => {
                let padding = match hash {
                    RsaPssHash::Sha256 => &signature::RSA_PSS_SHA256,
                    RsaPssHash::Sha384 => &signature::RSA_PSS_SHA384,
                    RsaPssHash::Sha512 => &signature::RSA_PSS_SHA512,
                };
                let mut signature = vec![0; key.public_modulus_len()];
                key.sign(padding, &rng, message, &mut signature)
                    .map_err(signing_error)?;
                Ok(signature)
            }
            Self::MlDsa(set, key) => {
                let mut signature = vec![0; ml_dsa_signing(*set).signature_len()];
                let len = key.sign(message, &mut signature).map_err(signing_error)?;
                signature.truncate(len);
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
        Algorithm::Ed25519 | Algorithm::RsaPss(_) | Algorithm::MlDsa(_) => {
            unreachable!("{algorithm:?} is not ECDSA")
        }
    }
}

fn ml_dsa_signing(set: MlDsaParameterSet) -> &'static PqdsaSigningAlgorithm {
    match set {
        MlDsaParameterSet::MlDsa44 => &signature::ML_DSA_44_SIGNING,
        MlDsaParameterSet::MlDsa65 => &signature::ML_DSA_65_SIGNING,
        MlDsaParameterSet::MlDsa87 => &signature::ML_DSA_87_SIGNING,
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
