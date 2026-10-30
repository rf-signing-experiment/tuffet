//! Keys held outside the process, such as in an HSM or a cloud KMS, are
//! described as metadata lists keys with `public_key_from_spki` (DER) or
//! `public_key_from_pem`, which encode them as `PrivateKey` does, so that a
//! key always gets the same KEYVAL, and key ID.

use std::assert_matches;

use tuffet::crypto::{
    CryptoError, PrivateKey, Signer, public_key_from_pem, public_key_from_spki, verify_signature,
};
use tuffet::metadata::SignatureScheme;
use tuffet::pouf::{Json, Pouf};

use crate::support::data;
use crate::{key, message};

/// The DER encoding of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410) up to
/// the key itself.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[test]
fn keys_are_described_as_private_keys_describe_them() {
    let rsa = PrivateKey::from_pkcs8_pem(&data::crypto_text("rsa.key.pem")).unwrap();
    let mut signers = vec![rsa];
    for scheme in [
        SignatureScheme::Ed25519,
        SignatureScheme::EcdsaSha2Nistp256,
        SignatureScheme::EcdsaSha2Nistp384,
        SignatureScheme::MlDsa44V1,
        SignatureScheme::MlDsa65V1,
        SignatureScheme::MlDsa87V1,
    ] {
        signers.push(PrivateKey::generate(&scheme).unwrap());
    }

    for signer in signers {
        let expected = signer.public_key();
        let scheme = &expected.scheme;
        let described = if *scheme == SignatureScheme::Ed25519 {
            let raw = hex::decode(&expected.keyval.public).unwrap();
            public_key_from_spki(scheme, &[&ED25519_SPKI_PREFIX[..], &raw].concat()).unwrap()
        } else {
            public_key_from_pem(scheme, &expected.keyval.public).unwrap()
        };
        assert_eq!(&described, expected, "{scheme}");
        assert_eq!(
            Json::key_id(&described).unwrap(),
            Json::key_id(expected).unwrap()
        );
    }
}

/// PEM keys are encoded again, so line endings and surrounding whitespace do
/// not change the key or its key ID.
#[test]
fn pem_keys_are_encoded_again() {
    for (scheme, pem) in [
        (SignatureScheme::EcdsaSha2Nistp256, "p256.pub.pem"),
        (SignatureScheme::EcdsaSha2Nistp384, "p384.pub.pem"),
        (SignatureScheme::RsassaPssSha256, "rsa.pub.pem"),
        (SignatureScheme::MlDsa87V1, "ml-dsa-87.pub.pem"),
    ] {
        let as_is = public_key_from_pem(&scheme, &data::crypto_text(pem)).unwrap();
        assert_eq!(as_is.keyval.public, format!("{}\n", data::crypto_text(pem)));

        let crlf = format!("\n  {}\r\n", data::crypto_text(pem).replace('\n', "\r\n"));
        let reencoded = public_key_from_pem(&scheme, &crlf).unwrap();
        assert_eq!(reencoded, as_is, "{scheme}");
    }
}

/// The key must be a valid key for the scheme.
#[test]
fn keys_must_be_valid_for_their_scheme() {
    let p256 = data::crypto_text("p256.pub.pem");
    for scheme in [
        SignatureScheme::EcdsaSha2Nistp384,
        SignatureScheme::RsassaPssSha256,
        SignatureScheme::MlDsa44V1,
    ] {
        assert_matches!(
            public_key_from_pem(&scheme, &p256),
            Err(CryptoError::InvalidPublicKey(_)),
            "{scheme}"
        );
    }
    assert_matches!(
        public_key_from_spki(&SignatureScheme::EcdsaSha2Nistp256, b"not a key"),
        Err(CryptoError::InvalidPublicKey(_))
    );
    let short_ed25519 = [&ED25519_SPKI_PREFIX[..], &[0; 31]].concat();
    assert_matches!(
        public_key_from_spki(&SignatureScheme::Ed25519, &short_ed25519),
        Err(CryptoError::InvalidPublicKey(_))
    );
    assert_matches!(
        public_key_from_pem(&SignatureScheme::Other("sphincs+".to_owned()), &p256),
        Err(CryptoError::UnsupportedScheme { .. })
    );
}

/// Only public keys (`BEGIN PUBLIC KEY`) are accepted, not private keys.
#[test]
fn private_keys_are_not_public_keys() {
    assert_matches!(
        public_key_from_pem(
            &SignatureScheme::EcdsaSha2Nistp256,
            &data::crypto_text("p256.key.pem")
        ),
        Err(CryptoError::InvalidPublicKey(reason)) if reason.contains("label")
    );
}

/// The keys described can verify signatures.
#[test]
fn described_keys_verify_signatures() {
    let described = public_key_from_pem(
        &SignatureScheme::EcdsaSha2Nistp256,
        &data::crypto_text("p256.pub.pem"),
    )
    .unwrap();
    assert_eq!(
        described.keyval.public.trim(),
        key(SignatureScheme::EcdsaSha2Nistp256, "p256.pub.pem")
            .keyval
            .public
    );
    verify_signature(&described, &message(), &data::crypto("p256.sig")).unwrap();
}
