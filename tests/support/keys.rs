//! Deterministic test keys.
//!
//! Keys are Ed25519 keys derived from a name. Ed25519 signatures are
//! deterministic too, so metadata signed with these keys is the same in every
//! run, which the snapshot tests rely on.

use std::sync::Arc;

use rftuf::crypto::{HashAlgorithm, PrivateKey, Signer};
use rftuf::metadata::KeyId;
use rftuf::pouf::{Json, Pouf};

/// The DER encoding of an Ed25519 PKCS#8 (v1) private key, up to its 32-byte
/// seed (RFC 8410).
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The Ed25519 key named `name`: the same name always gives the same key.
pub fn key(name: &str) -> Arc<PrivateKey> {
    let seed = HashAlgorithm::Sha256.digest(name.as_bytes());
    let der = [&ED25519_PKCS8_PREFIX[..], &seed].concat();
    Arc::new(PrivateKey::from_pkcs8_der(&der).expect("a valid Ed25519 PKCS#8 key"))
}

/// The key ID of `key`, as the JSON POUF computes it.
pub fn key_id(key: &PrivateKey) -> KeyId {
    Json::key_id(key.public_key()).unwrap()
}
