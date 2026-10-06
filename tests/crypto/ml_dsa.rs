//! ML-DSA (FIPS 204), as TAP 21 adds it: the "ml-dsa" key type, and the
//! "ml-dsa-44/1", "ml-dsa-65/1" and "ml-dsa-87/1" schemes. PUBLIC is a PEM
//! `SubjectPublicKeyInfo`. Keys do not sign the payload itself but the
//! message `"tuf" || 0x01 || SHA-512(payload)`, with pure ML-DSA and an
//! empty context.

use rftuf::crypto::{
    CryptoError, HashAlgorithm, PrivateKey, Signer, ml_dsa_message, verify_signature,
};
use rftuf::metadata::SignatureScheme;

use crate::support::data;
use crate::{key, message};

#[test]
fn the_message_of_tap21() {
    let mut expected = b"tuf\x01".to_vec();
    expected.extend(HashAlgorithm::Sha512.digest(&message()));
    assert_eq!(ml_dsa_message(&message()), expected);
    assert_eq!(ml_dsa_message(b"").len(), 4 + 64);
}

/// OpenSSL signed the TAP 21 message of `message.txt` with pure ML-DSA (see
/// `tests/data/README.md`), so its signatures verifying shows that
/// verification builds that message from the payload, exactly once.
/// `PrivateKey` signatures, which verify the same way, are signatures of
/// that message too.
#[test]
fn signatures_are_of_the_tap21_message() {
    let key = key(SignatureScheme::MlDsa44V1, "ml-dsa-44.pub.pem");
    let openssl = data::crypto("ml-dsa-44.sig");
    verify_signature(&key, &message(), &openssl).unwrap();
    assert!(matches!(
        verify_signature(&key, &ml_dsa_message(&message()), &openssl),
        Err(CryptoError::BadSignature)
    ));

    let signer = PrivateKey::from_pkcs8_pem(&data::crypto_text("ml-dsa-44.key.pem")).unwrap();
    let ours = signer.sign(&message()).unwrap();
    verify_signature(&key, &message(), &ours).unwrap();
    assert!(matches!(
        verify_signature(&key, &ml_dsa_message(&message()), &ours),
        Err(CryptoError::BadSignature)
    ));
}

/// The scheme names the parameter set: a signature only verifies with its
/// own, and a key of one parameter set is not a valid key of another.
#[test]
fn signatures_only_verify_with_their_parameter_set() {
    let sets = [
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
    ];
    for (scheme, public, _) in &sets {
        for (signed_with, _, signature) in &sets {
            if scheme == signed_with {
                continue;
            }
            let result = verify_signature(
                &key(scheme.clone(), public),
                &message(),
                &data::crypto(signature),
            );
            assert!(
                matches!(result, Err(CryptoError::BadSignature)),
                "{signed_with} checked as {scheme}"
            );
            let result = verify_signature(
                &key(signed_with.clone(), public),
                &message(),
                &data::crypto(signature),
            );
            assert!(
                matches!(result, Err(CryptoError::InvalidPublicKey(_))),
                "{scheme} key used as {signed_with}"
            );
        }
    }
}

/// RFC 9881 private keys hold the seed, the expanded key, or both. Keys
/// with the seed load with both backends: here, ML-DSA-44 and -87 keys in
/// OpenSSL's default form (both) and an ML-DSA-65 key with only the seed.
/// Keys with only the expanded key only load with the `aws-lc-rs` backend.
#[test]
fn private_keys_load_in_the_forms_with_a_seed() {
    for (private, public) in [
        ("ml-dsa-44.key.pem", "ml-dsa-44.pub.pem"),
        ("ml-dsa-65.key.pem", "ml-dsa-65.pub.pem"),
        ("ml-dsa-87.key.pem", "ml-dsa-87.pub.pem"),
    ] {
        let signer = PrivateKey::from_pkcs8_pem(&data::crypto_text(private)).unwrap();
        assert_eq!(
            signer.public_key().keyval.public.trim(),
            data::crypto_text(public)
        );
    }

    let expanded_only =
        PrivateKey::from_pkcs8_pem(&data::crypto_text("ml-dsa-44.expanded.key.pem"));
    if cfg!(feature = "aws-lc-rs") {
        assert_eq!(
            expanded_only.unwrap().public_key().keyval.public.trim(),
            data::crypto_text("ml-dsa-44.pub.pem")
        );
    } else {
        assert!(matches!(
            expanded_only,
            Err(CryptoError::InvalidPrivateKey(_))
        ));
    }
}

/// A private key that holds both forms is rejected if its expanded key is
/// not the one its seed expands to (as OpenSSL does).
#[test]
fn private_keys_whose_forms_disagree_are_rejected() {
    let pem = data::crypto_text("ml-dsa-44.key.pem");
    let (_, mut der) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
    PrivateKey::from_pkcs8_der(&der).unwrap();
    // The expanded key comes last.
    *der.last_mut().unwrap() ^= 1;
    assert!(matches!(
        PrivateKey::from_pkcs8_der(&der),
        Err(CryptoError::InvalidPrivateKey(_))
    ));
}
