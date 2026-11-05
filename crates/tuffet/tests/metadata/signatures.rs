//! Signature thresholds.
//!
//! Metadata is signed by a role when at least the role's THRESHOLD (4.3,
//! 4.5) of its keys have validly signed it. "When computing the THRESHOLD
//! each KEY MUST only contribute one SIGNATURE" (5.3.4, 5.4.2, 5.5.3 and
//! 5.6.3). The workflow tests check which keys each step uses; these tests
//! check how signatures are counted.

use std::assert_matches;

use serde_json::json;
use tuffet::Error;
use tuffet::crypto::{PrivateKey, Signer};
use tuffet::metadata::{
    DelegatedRole, Delegations, Key, KeyId, KeyType, Metadata, RoleType, Root, Signature,
    SignatureScheme, Targets,
};
use tuffet::pouf::{Json, Pouf};

use crate::support::keys::{key, key_id};
use crate::support::{data, far_future};

/// Root metadata that trusts `signers` for the targets role, with
/// `threshold`.
fn root_trusting(signers: &[&PrivateKey], threshold: u64) -> Root {
    let mut root = Root::new(far_future());
    for signer in signers {
        root.add_key(
            RoleType::Targets,
            key_id(signer),
            signer.public_key().clone(),
        );
    }
    root.roles.targets.threshold = threshold;
    root
}

fn unsigned_targets() -> Metadata<Targets> {
    Metadata::new(Targets::new(far_future())).unwrap()
}

#[test]
fn a_threshold_of_the_roles_keys_must_sign() {
    let (a, b, c) = (key("a"), key("b"), key("c"));
    let root = root_trusting(&[&a, &b, &c], 2);
    let mut targets = unsigned_targets();
    assert_matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold {
            valid: 0,
            threshold: 2,
            ..
        })
    );
    targets.sign(a.as_ref()).unwrap();
    assert_matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold {
            valid: 1,
            threshold: 2,
            ..
        })
    );
    targets.sign(b.as_ref()).unwrap();
    root.verify_role(&targets).unwrap();
    targets.sign(c.as_ref()).unwrap();
    root.verify_role(&targets).unwrap();
}

/// Signatures by keys the role does not list are ignored, even if another
/// role trusts them.
#[test]
fn signatures_by_other_keys_do_not_count() {
    let (trusted, other_role, unknown) = (key("trusted"), key("snapshot"), key("unknown"));
    let mut root = root_trusting(&[&trusted], 1);
    root.add_key(
        RoleType::Snapshot,
        key_id(&other_role),
        other_role.public_key().clone(),
    );
    let mut targets = unsigned_targets();
    targets.sign(other_role.as_ref()).unwrap();
    targets.sign(unknown.as_ref()).unwrap();
    assert_matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold { valid: 0, .. })
    );
}

/// An invalid signature by a key the role lists does not count.
#[test]
fn invalid_signatures_do_not_count() {
    let (a, b) = (key("a"), key("b"));
    let root = root_trusting(&[&a, &b], 2);
    let mut targets = unsigned_targets();
    targets.sign(a.as_ref()).unwrap();
    let signature_of_other_data = b.sign(b"other data").unwrap();
    targets.add_signature(Signature::new(key_id(&b), signature_of_other_data));
    assert_matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold {
            valid: 1,
            threshold: 2,
            ..
        })
    );
}

/// "each KEY MUST only contribute one SIGNATURE": a key that a role lists
/// under two key IDs (here, the key with and without an extra field, as key
/// IDs are not recomputed) counts once.
#[test]
fn a_key_counts_once_even_under_several_key_ids() {
    let signer = key("signer");
    let key = signer.public_key().clone();
    let mut variant = key.clone();
    variant
        .unrecognized_fields
        .insert("comment".to_owned(), json!("the same key"));
    let (id, variant_id) = (Json::key_id(&key).unwrap(), Json::key_id(&variant).unwrap());
    assert_ne!(id, variant_id);

    let mut root = Root::new(far_future());
    root.add_key(RoleType::Targets, id.clone(), key);
    root.add_key(RoleType::Targets, variant_id.clone(), variant);
    root.roles.targets.threshold = 2;
    Metadata::<Root>::new(root.clone()).unwrap();

    let mut targets = unsigned_targets();
    let sig = signer.sign(targets.canonical_signed()).unwrap();
    targets.add_signature(Signature::new(id, sig.clone()));
    targets.add_signature(Signature::new(variant_id, sig));
    assert_matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold {
            valid: 1,
            threshold: 2,
            ..
        })
    );
}

/// Keys are told apart by their material, not by the strings that encode it:
/// a key that a role lists twice, with its KEYVAL encoded in two ways that
/// decode to the same key, counts once.
#[test]
fn a_key_counts_once_however_its_public_key_is_encoded() {
    let private = |name: &str| PrivateKey::from_pkcs8_pem(&data::crypto_text(name)).unwrap();
    let ed25519 = key("signer");
    let (p256, rsa, ml_dsa) = (
        private("p256.key.pem"),
        private("rsa.key.pem"),
        private("ml-dsa-44.key.pem"),
    );
    let public = |signer: &PrivateKey| signer.public_key().keyval.public.clone();
    #[allow(unused_mut)]
    let mut variants = vec![
        (&*ed25519, public(&ed25519).to_uppercase()),
        (&p256, public(&p256).replace('\n', "\r\n")),
        (&p256, data::crypto_text("p256.compressed.pub.pem")),
        (&rsa, format!(" {}\n", public(&rsa))),
        (&ml_dsa, public(&ml_dsa).trim_end().to_owned()),
    ];
    // `aws-lc-rs` also takes the bare point, without its SubjectPublicKeyInfo.
    #[cfg(feature = "aws-lc-rs")]
    {
        let (_, spki) = pem_rfc7468::decode_vec(public(&p256).as_bytes()).unwrap();
        let point = &spki[spki.len() - 65..];
        let bare = pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, point);
        variants.push((&p256, bare.unwrap()));
    }
    for (signer, encoded) in variants {
        let key = signer.public_key().clone();
        assert_ne!(encoded, key.keyval.public);
        let mut variant = key.clone();
        variant.keyval.public = encoded;
        let (id, variant_id) = (KeyId::new("key"), KeyId::new("variant"));

        let mut targets = unsigned_targets();
        let sig = signer.sign(targets.canonical_signed()).unwrap();
        targets.add_signature(Signature::new(id.clone(), sig.clone()));
        targets.add_signature(Signature::new(variant_id.clone(), sig));

        // Each encoding is a valid one for the key.
        for (id, key) in [(&id, &key), (&variant_id, &variant)] {
            let mut root = Root::new(far_future());
            root.add_key(RoleType::Targets, id.clone(), key.clone());
            root.verify_role(&targets).unwrap();
        }

        let mut root = Root::new(far_future());
        root.add_key(RoleType::Targets, id, key);
        root.add_key(RoleType::Targets, variant_id, variant.clone());
        root.roles.targets.threshold = 2;
        assert_matches!(
            root.verify_role(&targets),
            Err(Error::SignatureThreshold {
                valid: 1,
                threshold: 2,
                ..
            }),
            "{:?}",
            variant.keyval.public
        );
    }
}

/// Keys whose type or scheme tuffet does not support (4.2.2: "TUF is not
/// restricted to any particular signature SCHEMEs, KEYTYPEs") are ignored:
/// their signatures do not count, but do not make verification fail either.
#[test]
fn keys_tuffet_cannot_use_are_ignored() {
    let supported = key("supported");
    let unsupported = Key::new(
        KeyType::Other("sphincs".to_owned()),
        SignatureScheme::Other("sphincs+".to_owned()),
        "00".repeat(32),
    );
    let unsupported_id = KeyId::new("unsupported");
    let mut root = root_trusting(&[&supported], 1);
    root.add_key(RoleType::Targets, unsupported_id.clone(), unsupported);

    let mut targets = unsigned_targets();
    targets.add_signature(Signature::new(unsupported_id, vec![0; 64]));
    assert_matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold { valid: 0, .. })
    );
    targets.sign(supported.as_ref()).unwrap();
    root.verify_role(&targets).unwrap();
}

/// A key ID that a role lists but the keys do not define counts nothing.
#[test]
fn key_ids_without_a_key_count_nothing() {
    let signer = key("signer");
    let mut root = Root::new(far_future());
    root.roles.targets.keyids.push(key_id(&signer));
    let mut targets = unsigned_targets();
    targets.sign(signer.as_ref()).unwrap();
    assert_matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold { valid: 0, .. })
    );
}

/// Delegated targets metadata is verified with the keys and threshold that
/// the delegating role lists for it (3.1.2.1), and only a role that is
/// delegated to can be verified.
#[test]
fn delegated_roles_are_verified_with_the_keys_of_their_delegation() {
    let (a1, a2, other) = (key("a1"), key("a2"), key("other"));
    let mut delegating = Targets::new(far_future());
    let mut delegations = Delegations::new();
    for signer in [&a1, &a2, &other] {
        delegations
            .keys
            .insert(key_id(signer), signer.public_key().clone());
    }
    delegations
        .roles
        .push(DelegatedRole::new("a", vec![key_id(&a1), key_id(&a2)], 2));
    delegations
        .roles
        .push(DelegatedRole::new("other", vec![key_id(&other)], 1));
    delegating.delegations = Some(delegations);

    let mut a = unsigned_targets();
    a.sign(a1.as_ref()).unwrap();
    a.sign(other.as_ref()).unwrap();
    assert_matches!(
        delegating.verify_delegate("a", &a),
        Err(Error::SignatureThreshold { role, valid: 1, threshold: 2 }) if role == "a"
    );
    a.sign(a2.as_ref()).unwrap();
    delegating.verify_delegate("a", &a).unwrap();
    assert_matches!(
        delegating.verify_delegate("b", &a),
        Err(Error::UnknownDelegation(role)) if role == "b"
    );
    assert_matches!(
        Targets::new(far_future()).verify_delegate("a", &a),
        Err(Error::UnknownDelegation(role)) if role == "a"
    );
}
