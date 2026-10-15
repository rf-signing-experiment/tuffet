//! 4.2.2 Key objects: `{"keytype": KEYTYPE, "scheme": SCHEME, "keyval":
//! {"public": PUBLIC}}`, and the KEYIDs that refer to them.
//!
//! The key types and signature schemes themselves are tested in the
//! `crypto` tests.

use std::assert_matches;

use rftuf::Error;
use rftuf::crypto::{HashAlgorithm, Signer};
use rftuf::metadata::{
    DelegatedRole, Delegations, Key, KeyId, KeyType, Metadata, RoleType, Root, Signature,
    SignatureScheme, Targets,
};
use rftuf::pouf::{Json, Pouf};
use serde_json::json;

use crate::support::far_future;
use crate::support::keys::key;

/// 4.2.2: "TUF is not restricted to any particular signature SCHEMEs,
/// KEYTYPEs", so keys of any type and scheme are decoded, and encoded
/// unchanged. (rftuf ignores the signatures of keys it cannot use; see
/// `signatures`.)
#[test]
fn keys_of_any_type_and_scheme_are_decoded() {
    for (keytype, scheme) in [
        ("ed25519", "ed25519"),
        ("ecdsa", "ecdsa-sha2-nistp256"),
        ("rsa", "rsassa-pss-sha256"),
        ("ml-dsa", "ml-dsa-65/1"),
        ("sphincs", "sphincs+"),
    ] {
        let json = json!({"keytype": keytype, "scheme": scheme, "keyval": {"public": "abcd"}});
        let key: Key = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(key.keytype, KeyType::from(keytype));
        assert_eq!(key.scheme, SignatureScheme::from(scheme));
        assert_eq!(serde_json::to_value(&key).unwrap(), json);
    }
    assert_eq!(
        SignatureScheme::from("sphincs+"),
        SignatureScheme::Other("sphincs+".to_owned())
    );
    assert_eq!(KeyType::from("dsa"), KeyType::Other("dsa".to_owned()));
}

/// 4.2.1: a KEYID is "a hexdigest of the SHA-256 hash of the canonical form
/// of the key". (`Pouf::key_id` computes it for new keys.)
#[test]
fn key_ids_are_the_sha256_of_the_canonical_key() {
    let public = "fcf224e55fa226056adf113ef1eb3d55e308b75b321c8c8316999d8c4fd9e0d9";
    let key = Key::new(
        KeyType::Ed25519,
        SignatureScheme::Ed25519,
        public.to_owned(),
    );
    let canonical =
        format!(r#"{{"keytype":"ed25519","keyval":{{"public":"{public}"}},"scheme":"ed25519"}}"#);
    assert_eq!(
        Json::key_id(&key).unwrap().as_str(),
        hex::encode(HashAlgorithm::Sha256.digest(canonical.as_bytes()))
    );
}

/// 4.3 (KEYID): "Clients MUST calculate each KEYID to verify this is correct
/// for the associated key." rftuf deliberately does not, like python-tuf and
/// go-tuf (see "Key IDs" in the crate documentation): key IDs are labels,
/// and a key listed under any key ID verifies signatures labeled with it.
#[test]
fn key_ids_are_not_recomputed() {
    let signer = key("release key");
    let label = KeyId::new("release-key-2025");
    let mut root = Root::new(far_future());
    root.add_key(
        RoleType::Targets,
        label.clone(),
        signer.public_key().clone(),
    );

    let mut targets = Metadata::<Targets>::new(Targets::new(far_future())).unwrap();
    let sig = signer.sign(targets.canonical_signed()).unwrap();
    targets.add_signature(Signature::new(label, sig));
    root.verify_role(&targets).unwrap();
}

/// 4.3 (KEYID): "Clients MUST ensure that for any KEYID represented in this
/// key list and in other files, only one unique key has that KEYID." With
/// key IDs as labels, one ID can name different keys in root and in a
/// delegation. That cannot be abused: the signatures of a role are only
/// checked with the keys its delegating role lists.
#[test]
fn a_key_id_only_names_a_key_in_the_metadata_that_lists_it() {
    let (in_root, in_delegation) = (key("listed in root"), key("listed in a delegation"));
    let label = KeyId::new("shared-label");
    let mut root = Root::new(far_future());
    root.add_key(
        RoleType::Targets,
        label.clone(),
        in_root.public_key().clone(),
    );
    let mut top_level = Targets::new(far_future());
    let mut delegations = Delegations::new();
    delegations
        .keys
        .insert(label.clone(), in_delegation.public_key().clone());
    delegations
        .roles
        .push(DelegatedRole::new("a", vec![label.clone()], 1));
    top_level.delegations = Some(delegations);

    let signed_by = |signer: &rftuf::crypto::PrivateKey| {
        let mut metadata = Metadata::<Targets>::new(Targets::new(far_future())).unwrap();
        let sig = signer.sign(metadata.canonical_signed()).unwrap();
        metadata.add_signature(Signature::new(label.clone(), sig));
        metadata
    };
    root.verify_role(&signed_by(&in_root)).unwrap();
    assert_matches!(
        root.verify_role(&signed_by(&in_delegation)),
        Err(Error::SignatureThreshold { .. })
    );
    top_level
        .verify_delegate("a", &signed_by(&in_delegation))
        .unwrap();
    assert_matches!(
        top_level.verify_delegate("a", &signed_by(&in_root)),
        Err(Error::SignatureThreshold { .. })
    );
}
