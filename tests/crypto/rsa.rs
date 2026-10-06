//! The "rsa" key type (4.2.2), with the "rsassa-pss-sha256" scheme of the
//! specification ("RSA Probabilistic signature scheme with appendix. The
//! underlying hash function is SHA256.") and "rsassa-pss-sha384" and
//! "rsassa-pss-sha512", which other implementations use. PUBLIC is in "PEM
//! format", a `SubjectPublicKeyInfo`, and "All RSA keys MUST be at least
//! 2048 bits". To limit the cost of verification, rftuf also rejects keys of
//! more than 8192 bits.

use rftuf::crypto::{CryptoError, PrivateKey, Signer, public_key_from_pem, verify_signature};
use rftuf::metadata::SignatureScheme;

use crate::support::data;
use crate::{key, message};

/// Each scheme fixes the hash function (of both the message digest and
/// MGF1), so a signature only verifies with the scheme it was made with.
#[test]
fn signatures_only_verify_with_their_hash_function() {
    let signatures = [
        (SignatureScheme::RsassaPssSha256, "rsa-pss-saltdigest.sig"),
        (SignatureScheme::RsassaPssSha384, "rsa-pss-sha384.sig"),
        (SignatureScheme::RsassaPssSha512, "rsa-pss-sha512.sig"),
    ];
    for (signed_with, signature) in &signatures {
        for (scheme, _) in &signatures {
            let result = verify_signature(
                &key(scheme.clone(), "rsa.pub.pem"),
                &message(),
                &data::crypto(signature),
            );
            assert_eq!(
                result.is_ok(),
                scheme == signed_with,
                "{signed_with} checked as {scheme}"
            );
        }
    }
}

/// PSS signatures with a salt as long as the digest, as python-tuf, go-tuf
/// and rftuf make them, verify. Signatures with other salt lengths
/// (OpenSSL's default is the maximum) only verify with the `rustcrypto`
/// backend, because `aws-lc-rs` does not support them.
#[test]
fn salt_lengths() {
    let key = key(SignatureScheme::RsassaPssSha256, "rsa.pub.pem");
    verify_signature(&key, &message(), &data::crypto("rsa-pss-saltdigest.sig")).unwrap();

    let maximum_salt = verify_signature(&key, &message(), &data::crypto("rsa-pss-saltmax.sig"));
    if cfg!(feature = "aws-lc-rs") {
        assert!(matches!(maximum_salt, Err(CryptoError::BadSignature)));
    } else {
        maximum_salt.unwrap();
    }
}

/// "All RSA keys MUST be at least 2048 bits."
#[test]
fn keys_of_fewer_than_2048_bits_are_rejected() {
    let small = key(SignatureScheme::RsassaPssSha256, "rsa1024.pub.pem");
    assert!(matches!(
        verify_signature(&small, &message(), &[0; 128]),
        Err(CryptoError::InvalidPublicKey(reason)) if reason.contains("2048")
    ));
    assert!(matches!(
        public_key_from_pem(
            &SignatureScheme::RsassaPssSha256,
            &data::crypto_text("rsa1024.pub.pem")
        ),
        Err(CryptoError::InvalidPublicKey(reason)) if reason.contains("2048")
    ));
}

/// Known deviation: key sizes are checked in whole bytes, so keys of 2041 to
/// 2047 bits, whose moduli are also 256 bytes long, are taken for 2048-bit
/// keys. (With `aws-lc-rs`, only `public_key_from_pem` accepts them.)
#[test]
#[ignore = "known deviation: RSA keys of 2041 to 2047 bits are accepted"]
fn keys_of_2047_bits_are_rejected() {
    let pem = data::crypto_text("rsa2047.pub.pem");
    assert!(matches!(
        public_key_from_pem(&SignatureScheme::RsassaPssSha256, &pem),
        Err(CryptoError::InvalidPublicKey(_))
    ));
    let key = key(SignatureScheme::RsassaPssSha256, "rsa2047.pub.pem");
    assert!(matches!(
        verify_signature(&key, &message(), &data::crypto("rsa2047-pss.sig")),
        Err(CryptoError::InvalidPublicKey(_))
    ));
    assert!(matches!(
        PrivateKey::from_pkcs8_pem(&data::crypto_text("rsa2047.key.pem")),
        Err(CryptoError::InvalidPrivateKey(_))
    ));
}

#[test]
fn keys_of_2048_to_8192_bits_are_accepted() {
    for pem in ["rsa.pub.pem", "rsa8192.pub.pem"] {
        public_key_from_pem(&SignatureScheme::RsassaPssSha256, &data::crypto_text(pem))
            .unwrap_or_else(|e| panic!("{pem}: {e}"));
    }
    // (The `rustcrypto` backend already refuses to parse this key.)
    let large = key(SignatureScheme::RsassaPssSha256, "rsa8200.pub.pem");
    assert!(matches!(
        verify_signature(&large, &message(), &[0; 1025]),
        Err(CryptoError::InvalidPublicKey(_))
    ));
    assert!(matches!(
        public_key_from_pem(
            &SignatureScheme::RsassaPssSha256,
            &data::crypto_text("rsa8200.pub.pem")
        ),
        Err(CryptoError::InvalidPublicKey(_))
    ));
}

/// PUBLIC is a `SubjectPublicKeyInfo` ("BEGIN PUBLIC KEY"), not a PKCS#1
/// key ("BEGIN RSA PUBLIC KEY").
#[test]
fn public_keys_must_be_subject_public_key_info() {
    let mut pkcs1_label = key(SignatureScheme::RsassaPssSha256, "rsa.pub.pem");
    pkcs1_label.keyval.public = pkcs1_label
        .keyval
        .public
        .replace("PUBLIC KEY", "RSA PUBLIC KEY");
    assert!(matches!(
        verify_signature(&pkcs1_label, &message(), &data::crypto("rsa-pss-saltdigest.sig")),
        Err(CryptoError::InvalidPublicKey(reason)) if reason.contains("label")
    ));
}

/// RSA keys sign with the scheme they are generated for, and PKCS#8 keys
/// (which do not name a scheme) with "rsassa-pss-sha256".
#[test]
fn rsa_keys_sign_with_their_scheme() {
    let loaded = PrivateKey::from_pkcs8_pem(&data::crypto_text("rsa.key.pem")).unwrap();
    assert_eq!(loaded.public_key().scheme, SignatureScheme::RsassaPssSha256);

    let generated = PrivateKey::generate(&SignatureScheme::RsassaPssSha512).unwrap();
    assert_eq!(
        generated.public_key().scheme,
        SignatureScheme::RsassaPssSha512
    );
    let signature = generated.sign(b"payload").unwrap();
    let mut as_sha256 = generated.public_key().clone();
    as_sha256.scheme = SignatureScheme::RsassaPssSha256;
    assert!(verify_signature(&as_sha256, b"payload", &signature).is_err());
}
