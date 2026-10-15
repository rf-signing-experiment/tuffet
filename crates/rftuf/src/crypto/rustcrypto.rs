//! The cryptography backend built on the RustCrypto crates.

use ed25519_dalek as ed25519;
use getrandom::SysRng;
use ml_dsa::pkcs8::PrivateKeyInfoRef;
use ml_dsa::pkcs8::der::asn1::OctetStringRef;
use ml_dsa::pkcs8::der::{self, AnyRef, Reader as _, SliceReader};
use ml_dsa::pkcs8::spki::AssociatedAlgorithmIdentifier;
use ml_dsa::signature::Keypair as _;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams};
use p256::elliptic_curve::Generate;
use rand_core::UnwrapErr;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer as _, Verifier as _};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::{Algorithm, CryptoError, HashAlgorithm, MlDsaParameterSet, RsaPssHash};

const GENERATED_RSA_BITS: usize = 3072;

/// An ML-DSA parameter set, with the identifiers of its keys.
trait MlDsaParameters: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>> {}

impl<P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>> MlDsaParameters
    for P
{
}

#[derive(Debug)]
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
    if VerifyingKey::decode(algorithm, public_key)?.verify(message, signature) {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

pub(super) fn check_public_key(algorithm: Algorithm, public_key: &[u8]) -> Result<(), CryptoError> {
    VerifyingKey::decode(algorithm, public_key).map(drop)
}

pub(super) fn rsa_modulus_bits(public_key: &[u8]) -> Result<usize, CryptoError> {
    let key: RsaPublicKey = from_spki(public_key)?;
    Ok(key.n().bits() as usize)
}

/// A public key, decoded for the algorithm it is used with.
enum VerifyingKey {
    Ed25519(ed25519::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    RsaPss(RsaPssHash, RsaPublicKey),
    MlDsa44(ml_dsa::VerifyingKey<MlDsa44>),
    MlDsa65(ml_dsa::VerifyingKey<MlDsa65>),
    MlDsa87(ml_dsa::VerifyingKey<MlDsa87>),
}

impl VerifyingKey {
    fn decode(algorithm: Algorithm, public_key: &[u8]) -> Result<Self, CryptoError> {
        Ok(match algorithm {
            Algorithm::Ed25519 => {
                let bytes = public_key.try_into().map_err(invalid_public_key)?;
                Self::Ed25519(ed25519::VerifyingKey::from_bytes(bytes).map_err(invalid_public_key)?)
            }
            Algorithm::EcdsaP256Sha256 => Self::P256(from_spki(public_key)?),
            Algorithm::EcdsaP384Sha384 => Self::P384(from_spki(public_key)?),
            Algorithm::RsaPss(hash) => Self::RsaPss(hash, from_spki(public_key)?),
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa44) => Self::MlDsa44(from_spki(public_key)?),
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa65) => Self::MlDsa65(from_spki(public_key)?),
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa87) => Self::MlDsa87(from_spki(public_key)?),
        })
    }

    fn verify(self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Ed25519(key) => ed25519::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify_strict(message, &signature).is_ok()),
            Self::P256(key) => p256::ecdsa::Signature::from_der(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
            Self::P384(key) => p384::ecdsa::Signature::from_der(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
            Self::RsaPss(hash, key) => {
                use rsa::pss::{Signature, VerifyingKey};
                let Ok(signature) = Signature::try_from(signature) else {
                    return false;
                };
                // Signers disagree on the PSS salt length (python-tuf and go-tuf
                // use the digest length, OpenSSL defaults to the maximum), so
                // detect it.
                match hash {
                    RsaPssHash::Sha256 => VerifyingKey::<Sha256>::new_with_auto_salt_len(key)
                        .verify(message, &signature),
                    RsaPssHash::Sha384 => VerifyingKey::<Sha384>::new_with_auto_salt_len(key)
                        .verify(message, &signature),
                    RsaPssHash::Sha512 => VerifyingKey::<Sha512>::new_with_auto_salt_len(key)
                        .verify(message, &signature),
                }
                .is_ok()
            }
            Self::MlDsa44(key) => verify_ml_dsa(&key, message, signature),
            Self::MlDsa65(key) => verify_ml_dsa(&key, message, signature),
            Self::MlDsa87(key) => verify_ml_dsa(&key, message, signature),
        }
    }
}

fn verify_ml_dsa<P: MlDsaParams>(
    key: &ml_dsa::VerifyingKey<P>,
    message: &[u8],
    signature: &[u8],
) -> bool {
    ml_dsa::Signature::<P>::try_from(signature)
        .is_ok_and(|signature| key.verify(message, &signature).is_ok())
}

/// Decodes a DER-encoded `SubjectPublicKeyInfo`.
fn from_spki<K: DecodePublicKey>(der: &[u8]) -> Result<K, CryptoError> {
    K::from_public_key_der(der).map_err(invalid_public_key)
}

pub(super) enum SigningKey {
    Ed25519(ed25519::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    RsaPss(RsaPssHash, RsaPrivateKey),
    MlDsa44(ml_dsa::SigningKey<MlDsa44>),
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    MlDsa87(ml_dsa::SigningKey<MlDsa87>),
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
            Algorithm::RsaPss(hash) => Self::RsaPss(
                hash,
                RsaPrivateKey::new(&mut rng, GENERATED_RSA_BITS).map_err(invalid_private_key)?,
            ),
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa44) => {
                Self::MlDsa44(ml_dsa::SigningKey::generate_from_rng(&mut rng))
            }
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa65) => {
                Self::MlDsa65(ml_dsa::SigningKey::generate_from_rng(&mut rng))
            }
            Algorithm::MlDsa(MlDsaParameterSet::MlDsa87) => {
                Self::MlDsa87(ml_dsa::SigningKey::generate_from_rng(&mut rng))
            }
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
        if let Some(key) = ml_dsa_from_pkcs8_der(der) {
            return Ok(Self::MlDsa44(key));
        }
        if let Some(key) = ml_dsa_from_pkcs8_der(der) {
            return Ok(Self::MlDsa65(key));
        }
        if let Some(key) = ml_dsa_from_pkcs8_der(der) {
            return Ok(Self::MlDsa87(key));
        }
        match RsaPrivateKey::from_pkcs8_der(der) {
            Ok(key) => Ok(Self::RsaPss(RsaPssHash::Sha256, key)),
            Err(_) => Err(invalid_private_key("unsupported or malformed PKCS#8 key")),
        }
    }

    pub(super) fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::P256(_) => Algorithm::EcdsaP256Sha256,
            Self::P384(_) => Algorithm::EcdsaP384Sha384,
            Self::RsaPss(hash, _) => Algorithm::RsaPss(*hash),
            Self::MlDsa44(_) => Algorithm::MlDsa(MlDsaParameterSet::MlDsa44),
            Self::MlDsa65(_) => Algorithm::MlDsa(MlDsaParameterSet::MlDsa65),
            Self::MlDsa87(_) => Algorithm::MlDsa(MlDsaParameterSet::MlDsa87),
        }
    }

    pub(super) fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        let der = match self {
            Self::Ed25519(key) => return Ok(key.verifying_key().to_bytes().to_vec()),
            Self::P256(key) => key.verifying_key().to_public_key_der(),
            Self::P384(key) => key.verifying_key().to_public_key_der(),
            Self::RsaPss(_, key) => key.to_public_key().to_public_key_der(),
            Self::MlDsa44(key) => key.verifying_key().to_public_key_der(),
            Self::MlDsa65(key) => key.verifying_key().to_public_key_der(),
            Self::MlDsa87(key) => key.verifying_key().to_public_key_der(),
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
            Self::RsaPss(hash, key) => {
                use rsa::pss::SigningKey;
                let (key, mut rng) = (key.clone(), rng());
                match hash {
                    RsaPssHash::Sha256 => SigningKey::<Sha256>::new(key)
                        .sign_with_rng(&mut rng, message)
                        .to_vec(),
                    RsaPssHash::Sha384 => SigningKey::<Sha384>::new(key)
                        .sign_with_rng(&mut rng, message)
                        .to_vec(),
                    RsaPssHash::Sha512 => SigningKey::<Sha512>::new(key)
                        .sign_with_rng(&mut rng, message)
                        .to_vec(),
                }
            }
            Self::MlDsa44(key) => sign_ml_dsa(key, message)?,
            Self::MlDsa65(key) => sign_ml_dsa(key, message)?,
            Self::MlDsa87(key) => sign_ml_dsa(key, message)?,
        })
    }
}

/// Loads an ML-DSA private key in one of the PKCS#8 forms that include the
/// seed (RFC 9881): `seed`, or `both`, which OpenSSL writes by default.
fn ml_dsa_from_pkcs8_der<P: MlDsaParameters>(der: &[u8]) -> Option<ml_dsa::SigningKey<P>> {
    if let Ok(key) = ml_dsa::SigningKey::<P>::from_pkcs8_der(der) {
        return Some(key);
    }
    let info = PrivateKeyInfoRef::try_from(der).ok()?;
    info.algorithm
        .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)
        .ok()?;
    let mut reader = SliceReader::new(info.private_key.as_bytes()).ok()?;
    let (seed, expanded) = reader
        .sequence(|both| {
            let seed: &OctetStringRef = both.decode()?;
            let expanded: &OctetStringRef = both.decode()?;
            Ok::<_, der::Error>((seed, expanded))
        })
        .ok()?;
    reader.finish().ok()?;
    let key = ml_dsa::SigningKey::<P>::from_seed(seed.as_bytes().try_into().ok()?);
    // Like OpenSSL, reject a key whose two forms disagree.
    #[allow(deprecated)] // in favor of the seed, which is what the key is built from
    let expanded_from_seed = key.expanded_key().to_expanded();
    (expanded_from_seed.as_slice() == expanded.as_bytes()).then_some(key)
}

/// Signs with the hedged variant of ML-DSA, which FIPS 204 recommends.
fn sign_ml_dsa<P: MlDsaParams>(
    key: &ml_dsa::SigningKey<P>,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let signature = key
        .expanded_key()
        .sign_randomized(message, &[], &mut rng())
        .map_err(|error| CryptoError::Signing(Box::new(error)))?;
    Ok(signature.encode().to_vec())
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
