//! 4.2.1 Object format: "All signed metadata objects have the format"
//! `{"signed": ROLE, "signatures": [{"keyid": KEYID, "sig": SIGNATURE}, ...]}`,
//! where ROLE is "A dictionary whose "_type" field describes the role type".

use std::assert_matches;

use serde_json::{Value, json};
use tuffet::Error;
use tuffet::metadata::{MetaFile, Metadata, Root, Targets, Timestamp};

use crate::support::keys::key;
use crate::support::{data, far_future};
use crate::{decode, python_tuf_document};

#[test]
fn metadata_is_a_payload_with_signatures() {
    let timestamp = Metadata::<Timestamp>::from_bytes(&data::python_tuf("timestamp.json")).unwrap();
    assert_eq!(timestamp.signed().version, 1);
    let [signature] = timestamp.signatures() else {
        panic!("one signature expected");
    };
    assert_eq!(
        signature.keyid.as_str(),
        "8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758"
    );
    assert_eq!(signature.sig.len(), 64, "an Ed25519 signature");
}

#[test]
fn rejects_documents_that_are_not_signed_metadata() {
    let timestamp = python_tuf_document("timestamp.json");
    let without = |field: &str| {
        let mut document = timestamp.clone();
        document.as_object_mut().unwrap().remove(field);
        document
    };
    let with = |field: &str, value: Value| {
        let mut document = timestamp.clone();
        document[field] = value;
        document
    };
    let mut no_sig = timestamp.clone();
    no_sig["signatures"][0]
        .as_object_mut()
        .unwrap()
        .remove("sig");

    assert_matches!(
        Metadata::<Timestamp>::from_bytes(b"not json"),
        Err(Error::Decode(_))
    );
    for (case, document) in [
        ("an array", json!([])),
        (
            "an array of the values of signatures and signed",
            json!([timestamp["signatures"], timestamp["signed"]]),
        ),
        ("no signed", without("signed")),
        ("no signatures", without("signatures")),
        ("signed not an object", with("signed", json!("timestamp"))),
        ("signatures not a list", with("signatures", json!({}))),
        ("a signature without sig", no_sig),
    ] {
        let bytes = serde_json::to_vec(&document).unwrap();
        assert_matches!(
            Metadata::<Timestamp>::from_bytes(&bytes),
            Err(Error::Decode(_)),
            "{case}"
        );
    }
}

/// 4.2.1: the "_type" field describes the role type, and metadata is only
/// decoded as the role it names, so metadata of one role can never be taken
/// for another.
#[test]
fn the_type_field_must_name_the_role() {
    let result = Metadata::<Root>::from_bytes(&data::python_tuf("timestamp.json"));
    assert_matches!(result, Err(Error::Decode(e)) if e.to_string().contains("_type"));

    let mut untyped = python_tuf_document("timestamp.json")["signed"].take();
    untyped.as_object_mut().unwrap().remove("_type");
    assert_matches!(decode::<Timestamp>(untyped), Err(Error::Decode(_)));
}

/// 4.2.1: "The keyid MUST be unique in the "signatures" array: multiple
/// signatures with the same keyid are not allowed."
#[test]
fn key_ids_must_be_unique_in_signatures() {
    let mut document = python_tuf_document("timestamp.json");
    let signature = document["signatures"][0].clone();
    document["signatures"]
        .as_array_mut()
        .unwrap()
        .push(signature);
    let result = Metadata::<Timestamp>::from_bytes(&serde_json::to_vec(&document).unwrap());
    // The error names the key.
    assert_matches!(
        result,
        Err(Error::InvalidMetadata(reason)) if reason.contains("multiple signatures by key 8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758")
    );
}

/// 4.2.1: a SIGNATURE is "A hex-encoded signature". Either case is accepted;
/// tuffet writes lowercase.
#[test]
fn signatures_are_hex_encoded() {
    let document = python_tuf_document("timestamp.json");
    let sig = document["signatures"][0]["sig"]
        .as_str()
        .unwrap()
        .to_owned();
    let with_sig = |sig: &str| {
        let mut document = document.clone();
        document["signatures"][0]["sig"] = json!(sig);
        Metadata::<Timestamp>::from_bytes(&serde_json::to_vec(&document).unwrap())
    };

    let uppercase = with_sig(&sig.to_uppercase()).unwrap();
    let bytes = &uppercase.signatures()[0].sig;
    assert_eq!(bytes.as_ref(), hex::decode(&sig).unwrap());
    assert_eq!(bytes.to_string(), sig);
    assert_eq!(bytes.clone().into_vec(), hex::decode(&sig).unwrap());
    let reencoded: Value = serde_json::from_slice(&uppercase.to_bytes().unwrap()).unwrap();
    assert_eq!(reencoded["signatures"][0]["sig"], json!(sig));

    for invalid in ["xyz0", "abc", "0x00"] {
        assert_matches!(with_sig(invalid), Err(Error::Decode(_)), "{invalid}");
    }
}

/// Signatures cover the payload as it was received, so the payload of
/// decoded metadata cannot be changed in place: it is taken out, changed,
/// and wrapped again, without the signatures it invalidated.
#[test]
fn a_changed_payload_is_wrapped_again_without_its_signatures() {
    let timestamp = Metadata::<Timestamp>::from_bytes(&data::python_tuf("timestamp.json")).unwrap();
    assert_eq!(timestamp.signatures().len(), 1);
    let received = timestamp.canonical_signed().to_vec();

    let mut payload = timestamp.into_signed();
    payload.version += 1;
    let changed = Metadata::<Timestamp>::new(payload).unwrap();
    assert!(changed.signatures().is_empty());
    assert_eq!(changed.signed().version, 2);
    assert_ne!(changed.canonical_signed(), received);
}

/// Signing again with a key replaces its earlier signature, so that
/// metadata never holds two signatures with the same key ID (4.2.1).
#[test]
fn signing_again_replaces_the_signature_of_the_key() {
    let signer = key("signer");
    let mut targets = Metadata::<Targets>::new(Targets::new(far_future())).unwrap();
    targets.sign(signer.as_ref()).unwrap();
    targets.sign(signer.as_ref()).unwrap();
    assert_eq!(targets.signatures().len(), 1);
    targets.sign(key("other").as_ref()).unwrap();
    assert_eq!(targets.signatures().len(), 2);
    targets.clear_signatures();
    assert!(targets.signatures().is_empty());
}

/// Payloads are validated both when metadata is decoded and when it is
/// created for signing, so that tuffet neither accepts nor writes invalid
/// metadata.
#[test]
fn payloads_are_validated_before_signing() {
    let mut timestamp = Timestamp::new(far_future());
    assert_matches!(
        Metadata::<Timestamp>::new(timestamp.clone()),
        Err(Error::InvalidMetadata(reason)) if reason.contains("snapshot.json")
    );
    timestamp
        .meta
        .insert("snapshot.json".to_owned(), MetaFile::new(1));
    Metadata::<Timestamp>::new(timestamp).unwrap();
}
