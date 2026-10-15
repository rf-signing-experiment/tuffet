//! Signing: in-memory `PrivateKey`s, and the `Signer` trait for keys held
//! elsewhere.

use std::assert_matches;

use rftuf::Error;
use rftuf::crypto::{CryptoError, PrivateKey, Signer, public_key_from_pem};
use rftuf::metadata::{Key, Metadata, RoleType, Root, SignatureScheme, Targets};
use rftuf::pouf::{Json, Pouf};

use crate::support::{data, far_future};

#[test]
fn pkcs8_private_keys_load_from_pem_and_der() {
    let from_pem = PrivateKey::from_pkcs8_pem(&data::crypto_text("p256.key.pem")).unwrap();
    let from_der = PrivateKey::from_pkcs8_der(&data::crypto("p256.key.der")).unwrap();
    assert_eq!(from_der.public_key(), from_pem.public_key());
}

#[test]
fn rejects_what_is_not_a_pkcs8_private_key() {
    assert_matches!(
        PrivateKey::from_pkcs8_der(b"not a key"),
        Err(CryptoError::InvalidPrivateKey(_))
    );
    assert_matches!(
        PrivateKey::from_pkcs8_pem("not a key"),
        Err(CryptoError::InvalidPrivateKey(_))
    );
    assert_matches!(
        PrivateKey::from_pkcs8_pem(&data::crypto_text("p256.pub.pem")),
        Err(CryptoError::InvalidPrivateKey(reason)) if reason.contains("PRIVATE KEY")
    );
}

/// A key held elsewhere, here simulated with an in-memory key. Its public key
/// is described with `public_key_from_pem`, as an HSM's would be.
struct ExternalKey {
    public: Key,
    device: PrivateKey,
}

impl Signer for ExternalKey {
    fn public_key(&self) -> &Key {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.device.sign(message)
    }
}

/// Metadata can be signed with any `Signer`, and verifies with the key the
/// signer describes.
#[test]
fn custom_signers_sign_metadata() {
    let device = PrivateKey::from_pkcs8_pem(&data::crypto_text("p384.key.pem")).unwrap();
    let public = public_key_from_pem(
        &SignatureScheme::EcdsaSha2Nistp384,
        &data::crypto_text("p384.pub.pem"),
    )
    .unwrap();
    let external = ExternalKey { public, device };

    let mut root = Root::new(far_future());
    root.add_key(
        RoleType::Targets,
        Json::key_id(external.public_key()).unwrap(),
        external.public_key().clone(),
    );
    let mut targets = Metadata::<Targets>::new(Targets::new(far_future())).unwrap();
    targets.sign(&external).unwrap();
    root.verify_role(&targets).unwrap();
}

/// A signer that fails, for example because its device is unavailable.
struct Unavailable(Key);

impl Signer for Unavailable {
    fn public_key(&self) -> &Key {
        &self.0
    }

    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing("the device is unavailable".into()))
    }
}

#[test]
fn signing_failures_are_reported() {
    let key = PrivateKey::generate(&SignatureScheme::Ed25519).unwrap();
    let unavailable = Unavailable(key.public_key().clone());
    let mut targets = Metadata::<Targets>::new(Targets::new(far_future())).unwrap();
    assert_matches!(
        targets.sign(&unavailable),
        Err(Error::Crypto(CryptoError::Signing(_)))
    );
    assert!(targets.signatures().is_empty());
}

/// A private key's `Debug` output shows its public key, never its secret.
#[test]
fn private_keys_do_not_show_their_secret() {
    let pem = data::crypto_text("ed25519.key.pem");
    let (_, der) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
    // An Ed25519 PKCS#8 key ends with its 32-byte seed.
    let seed = &der[der.len() - 32..];
    let key = PrivateKey::from_pkcs8_der(&der).unwrap();

    let debug = format!("{key:?}");
    assert!(debug.contains(&data::crypto_text("ed25519.pub.hex")));
    assert!(!debug.contains(&hex::encode(seed)));
    assert!(!debug.contains(&format!("{seed:?}")[1..20]));
}
