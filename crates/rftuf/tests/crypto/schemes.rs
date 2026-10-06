//! What every supported signature scheme does: verify OpenSSL's signatures,
//! sign and verify with generated keys and with OpenSSL's private keys, and
//! reject signatures of other messages or by other keys.
//!
//! The specification defines "rsassa-pss-sha256", "ed25519" and
//! "ecdsa-sha2-nistp256" (4.2.2), and lets implementations define more.
//! rftuf also supports "ecdsa-sha2-nistp384", "rsassa-pss-sha384" and
//! "rsassa-pss-sha512", which other implementations use, and the ML-DSA
//! schemes of TAP 21.

use rftuf::crypto::{CryptoError, PrivateKey, Signer, verify_signature};
use rftuf::metadata::{Key, KeyType, SignatureScheme};

use crate::support::data;
use crate::{key, message};

/// Each supported scheme with a public key and OpenSSL's signature of the
/// message, in `tests/data/crypto`.
fn openssl_signatures() -> [(SignatureScheme, &'static str, &'static str); 9] {
    [
        (SignatureScheme::Ed25519, "ed25519.pub.hex", "ed25519.sig"),
        (
            SignatureScheme::EcdsaSha2Nistp256,
            "p256.pub.pem",
            "p256.sig",
        ),
        (
            SignatureScheme::EcdsaSha2Nistp384,
            "p384.pub.pem",
            "p384.sig",
        ),
        (
            SignatureScheme::RsassaPssSha256,
            "rsa.pub.pem",
            "rsa-pss-saltdigest.sig",
        ),
        (
            SignatureScheme::RsassaPssSha384,
            "rsa.pub.pem",
            "rsa-pss-sha384.sig",
        ),
        (
            SignatureScheme::RsassaPssSha512,
            "rsa.pub.pem",
            "rsa-pss-sha512.sig",
        ),
        (
            SignatureScheme::MlDsa44V1,
            "ml-dsa-44.pub.pem",
            "ml-dsa-44.sig",
        ),
        (
            SignatureScheme::MlDsa65V1,
            "ml-dsa-65.pub.pem",
            "ml-dsa-65.sig",
        ),
        (
            SignatureScheme::MlDsa87V1,
            "ml-dsa-87.pub.pem",
            "ml-dsa-87.sig",
        ),
    ]
}

#[test]
fn verifies_signatures_made_by_openssl() {
    for (scheme, public, signature) in openssl_signatures() {
        let key = key(scheme.clone(), public);
        let signature = data::crypto(signature);
        verify_signature(&key, &message(), &signature).unwrap_or_else(|e| panic!("{scheme}: {e}"));
        assert!(
            matches!(
                verify_signature(&key, b"another message", &signature),
                Err(CryptoError::BadSignature)
            ),
            "{scheme}"
        );
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore)] // test is too slow in debug mode.
fn generated_keys_sign_and_verify() {
    for (scheme, _, _) in openssl_signatures() {
        let signer = PrivateKey::generate(&scheme).unwrap();
        assert_eq!(signer.public_key().scheme, scheme);
        assert_eq!(Some(signer.public_key().keytype.clone()), scheme.key_type());
        let signature = signer.sign(b"payload").unwrap();
        verify_signature(signer.public_key(), b"payload", &signature).unwrap();

        assert!(
            matches!(
                verify_signature(signer.public_key(), b"Payload", &signature),
                Err(CryptoError::BadSignature)
            ),
            "{scheme}"
        );
        let other = PrivateKey::generate(&scheme).unwrap();
        assert!(
            matches!(
                verify_signature(other.public_key(), b"payload", &signature),
                Err(CryptoError::BadSignature)
            ),
            "{scheme}"
        );
    }
}

/// PKCS#8 private keys made by OpenSSL load with the right scheme and public
/// key, and sign verifiably.
#[test]
fn private_keys_made_by_openssl_sign_and_verify() {
    for (private, scheme, public, signature) in [
        (
            "ed25519.key.pem",
            SignatureScheme::Ed25519,
            "ed25519.pub.hex",
            "ed25519.sig",
        ),
        (
            "p256.key.pem",
            SignatureScheme::EcdsaSha2Nistp256,
            "p256.pub.pem",
            "p256.sig",
        ),
        (
            "p384.key.pem",
            SignatureScheme::EcdsaSha2Nistp384,
            "p384.pub.pem",
            "p384.sig",
        ),
        (
            "rsa.key.pem",
            SignatureScheme::RsassaPssSha256,
            "rsa.pub.pem",
            "rsa-pss-saltdigest.sig",
        ),
        (
            "ml-dsa-44.key.pem",
            SignatureScheme::MlDsa44V1,
            "ml-dsa-44.pub.pem",
            "ml-dsa-44.sig",
        ),
        (
            "ml-dsa-65.key.pem",
            SignatureScheme::MlDsa65V1,
            "ml-dsa-65.pub.pem",
            "ml-dsa-65.sig",
        ),
        (
            "ml-dsa-87.key.pem",
            SignatureScheme::MlDsa87V1,
            "ml-dsa-87.pub.pem",
            "ml-dsa-87.sig",
        ),
    ] {
        let signer = PrivateKey::from_pkcs8_pem(&data::crypto_text(private)).unwrap();
        let derived = signer.public_key();
        assert_eq!(derived.scheme, scheme);
        assert_eq!(
            derived.keyval.public.trim(),
            data::crypto_text(public),
            "{scheme}"
        );
        verify_signature(derived, &message(), &data::crypto(signature)).unwrap();

        let signature = signer.sign(b"payload").unwrap();
        verify_signature(&key(scheme, public), b"payload", &signature).unwrap();
    }
}

/// 4.2.2: "SCHEME: A string denoting a corresponding signature scheme": a key
/// is only used if its key type and scheme belong together.
#[test]
fn key_type_and_scheme_must_belong_together() {
    let mut ed25519 = key(SignatureScheme::Ed25519, "ed25519.pub.hex");
    ed25519.keytype = KeyType::Rsa;
    assert!(matches!(
        verify_signature(&ed25519, &message(), &data::crypto("ed25519.sig")),
        Err(CryptoError::UnsupportedScheme { keytype, scheme }) if keytype == "rsa" && scheme == "ed25519"
    ));

    let mut p256 = key(SignatureScheme::EcdsaSha2Nistp256, "p256.pub.pem");
    p256.scheme = SignatureScheme::RsassaPssSha256;
    assert!(matches!(
        verify_signature(&p256, &message(), &data::crypto("p256.sig")),
        Err(CryptoError::UnsupportedScheme { .. })
    ));
}

/// Key types and schemes rftuf does not implement cannot verify anything.
#[test]
fn unknown_schemes_are_unsupported() {
    let unknown = Key::new(
        KeyType::Other("sphincs".to_owned()),
        SignatureScheme::Other("sphincs+".to_owned()),
        "00".repeat(32),
    );
    assert!(matches!(
        verify_signature(&unknown, &message(), &[0; 64]),
        Err(CryptoError::UnsupportedScheme { .. })
    ));
    assert!(matches!(
        PrivateKey::generate(&SignatureScheme::Other("sphincs+".to_owned())),
        Err(CryptoError::UnsupportedScheme { .. })
    ));
}
