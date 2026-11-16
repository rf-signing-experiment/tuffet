//! With both backends compiled in, checks that they agree with each other.
//! The other tests of this module, which use its public API, are in
//! `tests/crypto`.

use super::{Algorithm, HashAlgorithm, aws_lc, decode_pem, rustcrypto};

/// Keys and signatures generated with OpenSSL; see `tests/data/README.md`.
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

#[test]
fn backends_derive_the_same_keys_and_verify_each_others_signatures() {
    let keys: [&[u8]; 7] = [
        vector!("ed25519.key.pem"),
        vector!("p256.key.pem"),
        vector!("p384.key.pem"),
        vector!("rsa.key.pem"),
        vector!("ml-dsa-44.key.pem"),
        vector!("ml-dsa-65.key.pem"),
        vector!("ml-dsa-87.key.pem"),
    ];
    for private in keys {
        let der = decode_pem(&text(private), "PRIVATE KEY").unwrap();
        let rustcrypto = rustcrypto::SigningKey::from_pkcs8_der(&der).unwrap();
        let aws_lc = aws_lc::SigningKey::from_pkcs8_der(&der).unwrap();
        let algorithm = rustcrypto.algorithm();
        assert_eq!(aws_lc.algorithm(), algorithm);
        let public = rustcrypto.public_key().unwrap();
        assert_eq!(aws_lc.public_key().unwrap(), public, "{algorithm:?}");

        let aws_lc_public = aws_lc::PublicKey::decode(algorithm, &public).unwrap();
        let rustcrypto_public = rustcrypto::PublicKey::decode(algorithm, &public).unwrap();
        let spki = rustcrypto_public.spki().unwrap();
        assert_eq!(aws_lc_public.spki().unwrap(), spki, "{algorithm:?}");
        if algorithm != Algorithm::Ed25519 {
            assert_eq!(spki, public, "{algorithm:?}");
        }

        assert!(aws_lc_public.verify(MESSAGE, &rustcrypto.sign(MESSAGE).unwrap()));
        assert!(rustcrypto_public.verify(MESSAGE, &aws_lc.sign(MESSAGE).unwrap()));
    }
}

#[test]
fn backends_compute_the_same_digests() {
    for algorithm in HashAlgorithm::ALL {
        let mut rustcrypto = rustcrypto::Hasher::new(algorithm);
        let mut aws_lc = aws_lc::Hasher::new(algorithm);
        rustcrypto.update(MESSAGE);
        aws_lc.update(MESSAGE);
        assert_eq!(rustcrypto.finalize(), aws_lc.finalize());
    }
}
