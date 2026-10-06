//! The "ecdsa" key type (4.2.2), with the "ecdsa-sha2-nistp256" scheme of the
//! specification ("Elliptic Curve Digital Signature Algorithm with NIST
//! P-256 curve signing and SHA-256 hashing") and "ecdsa-sha2-nistp384",
//! which other implementations use. PUBLIC is in "PEM format": a
//! `SubjectPublicKeyInfo`. Signatures are DER-encoded, as in python-tuf and
//! go-tuf.

use rftuf::crypto::{CryptoError, verify_signature};
use rftuf::metadata::SignatureScheme;

use crate::support::data;
use crate::{key, message};

/// Converts a DER-encoded ECDSA signature (a SEQUENCE of the INTEGERs r and
/// s) to the fixed-size `r || s` encoding.
fn der_to_fixed(der: &[u8], scalar_size: usize) -> Vec<u8> {
    assert_eq!(der[0], 0x30, "a SEQUENCE");
    let mut rest = &der[2..];
    let mut fixed = Vec::new();
    for _ in 0..2 {
        assert_eq!(rest[0], 0x02, "an INTEGER");
        let length = usize::from(rest[1]);
        let integer = &rest[2..2 + length];
        let significant = &integer[integer.iter().take_while(|&&b| b == 0).count()..];
        fixed.resize(fixed.len() + scalar_size - significant.len(), 0);
        fixed.extend_from_slice(significant);
        rest = &rest[2 + length..];
    }
    fixed
}

/// Signatures are DER-encoded: the same signature in the fixed-size `r || s`
/// encoding is rejected.
#[test]
fn signatures_are_der_encoded() {
    for (scheme, public, signature, scalar_size) in [
        (
            SignatureScheme::EcdsaSha2Nistp256,
            "p256.pub.pem",
            "p256.sig",
            32,
        ),
        (
            SignatureScheme::EcdsaSha2Nistp384,
            "p384.pub.pem",
            "p384.sig",
            48,
        ),
    ] {
        let key = key(scheme.clone(), public);
        let der = data::crypto(signature);
        verify_signature(&key, &message(), &der).unwrap();
        let fixed = der_to_fixed(&der, scalar_size);
        assert_eq!(fixed.len(), 2 * scalar_size);
        assert!(
            matches!(
                verify_signature(&key, &message(), &fixed),
                Err(CryptoError::BadSignature)
            ),
            "{scheme}"
        );
    }
}

/// Each scheme fixes the curve: a P-256 key cannot be used with
/// "ecdsa-sha2-nistp384", nor a P-384 key with "ecdsa-sha2-nistp256".
#[test]
fn keys_are_only_used_with_the_curve_of_their_scheme() {
    let p256_as_p384 = key(SignatureScheme::EcdsaSha2Nistp384, "p256.pub.pem");
    assert!(matches!(
        verify_signature(&p256_as_p384, &message(), &data::crypto("p256.sig")),
        Err(CryptoError::InvalidPublicKey(_))
    ));
    let p384_as_p256 = key(SignatureScheme::EcdsaSha2Nistp256, "p384.pub.pem");
    assert!(matches!(
        verify_signature(&p384_as_p256, &message(), &data::crypto("p384.sig")),
        Err(CryptoError::InvalidPublicKey(_))
    ));
}

#[test]
fn public_keys_must_be_pem_encoded() {
    let signature = data::crypto("p256.sig");
    for invalid in [
        "-----BEGIN PUBLIC KEY-----".to_owned(),
        "not a key".to_owned(),
        // The base64 body of the PEM, without its armor.
        data::crypto_text("p256.pub.pem")
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect(),
    ] {
        let mut key = key(SignatureScheme::EcdsaSha2Nistp256, "p256.pub.pem");
        key.keyval.public = invalid.clone();
        assert!(
            matches!(
                verify_signature(&key, &message(), &signature),
                Err(CryptoError::InvalidPublicKey(_))
            ),
            "{invalid}"
        );
    }
}
