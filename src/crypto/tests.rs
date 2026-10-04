use super::*;
use crate::metadata::KeyType;

/// Test vectors generated with OpenSSL; see `tests/data/README.md`.
macro_rules! vector {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/crypto/",
            $name
        ))
    };
}

const MESSAGE: &[u8] = vector!("message.txt");

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap().trim().to_owned()
}

fn key(scheme: SignatureScheme, public: &[u8]) -> Key {
    Key::new(scheme.key_type().unwrap(), scheme, text(public))
}

#[test]
fn generated_keys_sign_and_verify() {
    for scheme in [
        SignatureScheme::Ed25519,
        SignatureScheme::EcdsaSha2Nistp256,
        SignatureScheme::EcdsaSha2Nistp384,
    ] {
        let signer = PrivateKey::generate(&scheme).unwrap();
        assert_eq!(signer.public_key().scheme, scheme);
        let signature = signer.sign(b"message").unwrap();
        verify_signature(signer.public_key(), b"message", &signature).unwrap();

        let tampered = verify_signature(signer.public_key(), b"messagE", &signature);
        assert!(
            matches!(tampered, Err(CryptoError::BadSignature)),
            "{scheme}"
        );
        let other = PrivateKey::generate(&scheme).unwrap();
        assert!(verify_signature(other.public_key(), b"message", &signature).is_err());
    }
}

#[test]
fn rsa_keys_sign_and_verify() {
    let signer = PrivateKey::from_pkcs8_pem(&text(vector!("rsa.key.pem"))).unwrap();
    let signature = signer.sign(b"message").unwrap();
    verify_signature(signer.public_key(), b"message", &signature).unwrap();
    assert!(matches!(
        verify_signature(signer.public_key(), b"other", &signature),
        Err(CryptoError::BadSignature)
    ));
}

#[test]
fn verifies_signatures_made_by_openssl() {
    let cases: [(SignatureScheme, &[u8], &[u8]); 5] = [
        (
            SignatureScheme::RsassaPssSha256,
            vector!("rsa.pub.pem"),
            vector!("rsa-pss-saltmax.sig"),
        ),
        (
            SignatureScheme::RsassaPssSha256,
            vector!("rsa.pub.pem"),
            vector!("rsa-pss-saltdigest.sig"),
        ),
        (
            SignatureScheme::EcdsaSha2Nistp256,
            vector!("p256.pub.pem"),
            vector!("p256.sig"),
        ),
        (
            SignatureScheme::EcdsaSha2Nistp384,
            vector!("p384.pub.pem"),
            vector!("p384.sig"),
        ),
        (
            SignatureScheme::Ed25519,
            vector!("ed25519.pub.hex"),
            vector!("ed25519.sig"),
        ),
    ];
    for (scheme, public, signature) in cases {
        let key = key(scheme, public);
        verify_signature(&key, MESSAGE, signature).unwrap();
        assert!(verify_signature(&key, b"something else", signature).is_err());
    }
}

#[test]
fn verifies_rfc8032_ed25519_test_vector() {
    let public = b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let signature = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065\
         224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .unwrap();
    verify_signature(&key(SignatureScheme::Ed25519, public), b"", &signature).unwrap();
}

#[test]
fn loads_pkcs8_keys_made_by_openssl() {
    /// Loads a private key and checks that it matches OpenSSL's public key
    /// and signature.
    fn check(private: &[u8], scheme: SignatureScheme, public: &[u8], signature: &[u8]) {
        let signer = PrivateKey::from_pkcs8_pem(&text(private)).unwrap();
        let derived = signer.public_key();
        assert_eq!(derived.scheme, scheme);
        assert_eq!(derived.keyval.public.trim(), text(public), "{scheme}");
        verify_signature(derived, MESSAGE, signature).unwrap();
    }
    check(
        vector!("rsa.key.pem"),
        SignatureScheme::RsassaPssSha256,
        vector!("rsa.pub.pem"),
        vector!("rsa-pss-saltmax.sig"),
    );
    check(
        vector!("p256.key.pem"),
        SignatureScheme::EcdsaSha2Nistp256,
        vector!("p256.pub.pem"),
        vector!("p256.sig"),
    );
    check(
        vector!("p384.key.pem"),
        SignatureScheme::EcdsaSha2Nistp384,
        vector!("p384.pub.pem"),
        vector!("p384.sig"),
    );
    check(
        vector!("ed25519.key.pem"),
        SignatureScheme::Ed25519,
        vector!("ed25519.pub.hex"),
        vector!("ed25519.sig"),
    );

    let from_der = PrivateKey::from_pkcs8_der(vector!("p256.key.der")).unwrap();
    assert_eq!(
        from_der.public_key().keyval.public.trim(),
        text(vector!("p256.pub.pem"))
    );
    assert!(matches!(
        PrivateKey::from_pkcs8_der(b"not a key"),
        Err(CryptoError::InvalidPrivateKey(_))
    ));
}

#[test]
fn rejects_rsa_keys_below_2048_bits() {
    let key = key(SignatureScheme::RsassaPssSha256, vector!("rsa1024.pub.pem"));
    let result = verify_signature(&key, MESSAGE, &[0; 128]);
    assert!(
        matches!(result, Err(CryptoError::InvalidPublicKey(message)) if message.contains("2048"))
    );
}

#[test]
fn rejects_key_types_that_do_not_match_the_scheme() {
    let mut ed25519 = key(SignatureScheme::Ed25519, vector!("ed25519.pub.hex"));
    ed25519.keytype = KeyType::Rsa;
    let result = verify_signature(&ed25519, MESSAGE, vector!("ed25519.sig"));
    assert!(matches!(result, Err(CryptoError::UnsupportedScheme { .. })));

    let unknown = Key::new(
        KeyType::Other("x".into()),
        SignatureScheme::Other("x".into()),
        String::new(),
    );
    assert!(matches!(
        verify_signature(&unknown, MESSAGE, b""),
        Err(CryptoError::UnsupportedScheme { .. })
    ));
}

#[test]
fn rejects_malformed_keys_and_signatures() {
    let ed25519 = key(SignatureScheme::Ed25519, vector!("ed25519.pub.hex"));
    assert!(matches!(
        verify_signature(&ed25519, MESSAGE, &[0; 63]),
        Err(CryptoError::MalformedSignature)
    ));
    let short_key = key(SignatureScheme::Ed25519, b"abcd");
    assert!(matches!(
        verify_signature(&short_key, MESSAGE, vector!("ed25519.sig")),
        Err(CryptoError::InvalidPublicKey(_))
    ));

    // ECDSA signatures must be DER, not the fixed-size r || s encoding.
    let p256 = key(SignatureScheme::EcdsaSha2Nistp256, vector!("p256.pub.pem"));
    assert!(matches!(
        verify_signature(&p256, MESSAGE, &[1; 64]),
        Err(CryptoError::MalformedSignature)
    ));
    let garbage = key(
        SignatureScheme::EcdsaSha2Nistp256,
        b"-----BEGIN PUBLIC KEY-----",
    );
    assert!(matches!(
        verify_signature(&garbage, MESSAGE, vector!("p256.sig")),
        Err(CryptoError::InvalidPublicKey(_))
    ));
}

#[test]
fn hashes_match_known_digests() {
    assert_eq!(
        hex::encode(HashAlgorithm::Sha256.digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex::encode(HashAlgorithm::Sha512.digest(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    let mut hasher = HashAlgorithm::Sha256.hasher();
    hasher.update(b"a");
    hasher.update(b"bc");
    assert_eq!(hasher.finalize(), HashAlgorithm::Sha256.digest(b"abc"));
    assert_eq!(
        HashAlgorithm::from_name("sha512"),
        Some(HashAlgorithm::Sha512)
    );
    assert_eq!(HashAlgorithm::from_name("md5"), None);
}
