//! The "ed25519" key type and scheme (4.2.2): "Elliptic curve digital
//! signature algorithm based on Twisted Edwards curves", whose PUBLIC is a
//! "64-byte hex encoded string": the 32-byte public key in hex.

use std::assert_matches;

use tuffet::crypto::{CryptoError, PrivateKey, Signer, verify_signature};
use tuffet::metadata::{Key, KeyType, SignatureScheme};

use crate::support::data;
use crate::{key, message};

fn ed25519_key(public: &str) -> Key {
    Key::new(
        KeyType::Ed25519,
        SignatureScheme::Ed25519,
        public.to_owned(),
    )
}

/// Test 1 of RFC 8032, section 7.1: the empty message.
#[test]
fn verifies_the_first_test_vector_of_rfc8032() {
    let key = ed25519_key("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065\
         224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .unwrap();
    verify_signature(&key, b"", &signature).unwrap();
}

#[test]
fn public_keys_are_32_bytes_in_hex() {
    let generated = PrivateKey::generate(&SignatureScheme::Ed25519).unwrap();
    let public = &generated.public_key().keyval.public;
    assert_eq!(public.len(), 64);
    assert!(
        public
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );

    let signature = data::crypto("ed25519.sig");
    let valid = data::crypto_text("ed25519.pub.hex");
    verify_signature(&ed25519_key(&valid.to_uppercase()), &message(), &signature).unwrap();
    for invalid in [
        "abcd".to_owned(),
        format!("{valid}00"),
        valid[..62].to_owned(),
        "zz".repeat(32),
        data::crypto_text("p256.pub.pem"),
    ] {
        assert_matches!(
            verify_signature(&ed25519_key(&invalid), &message(), &signature),
            Err(CryptoError::InvalidPublicKey(_)),
            "{invalid}"
        );
    }
}

/// Ed25519 signatures are 64 bytes.
#[test]
fn signatures_of_another_length_are_rejected() {
    let key = key(SignatureScheme::Ed25519, "ed25519.pub.hex");
    let signature = data::crypto("ed25519.sig");
    assert_eq!(signature.len(), 64);
    for invalid in [&signature[..63], &[&signature[..], &[0]].concat(), &[]] {
        assert_matches!(
            verify_signature(&key, &message(), invalid),
            Err(CryptoError::BadSignature)
        );
    }
}
