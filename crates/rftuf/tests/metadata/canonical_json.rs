//! 4.1 Metaformat: JSON metadata is signed over its canonical form, "the
//! "canonical JSON" subdialect" (OLPC canonical JSON, as the reference
//! implementation produces it).

use std::assert_matches;

use rftuf::Error;
use rftuf::metadata::{Metadata, Root, Timestamp};
use rftuf::pouf::json::canonical;
use serde_json::{Value, json};
use snapbox::{assert_data_eq, str};

use crate::decode;
use crate::support::TestRepo;

fn canonical(value: Value) -> String {
    String::from_utf8(canonical::to_vec(&value).unwrap()).unwrap()
}

/// Canonical JSON has no whitespace outside strings, and sorts object
/// members by key.
#[test]
fn members_are_sorted_and_whitespace_is_omitted() {
    let value = json!({"b": [1, {"d": null, "c": true}], "a": false, "aa": -3});
    assert_eq!(
        canonical(value),
        r#"{"a":false,"aa":-3,"b":[1,{"c":true,"d":null}]}"#
    );
}

/// Keys are sorted by their UTF-8 bytes, which is the order of their code
/// points.
#[test]
fn keys_are_sorted_by_code_point() {
    let value = json!({"é": 1, "z": 2, "Z": 3, "a": 4, "\u{1F600}": 5, "\u{FFFD}": 6});
    assert_eq!(
        canonical(value),
        "{\"Z\":3,\"a\":4,\"z\":2,\"é\":1,\"\u{FFFD}\":6,\"\u{1F600}\":5}"
    );
}

/// In strings, only `"` and `\` are escaped; every other character,
/// including control characters, is written as is, in UTF-8.
#[test]
fn only_quotes_and_backslashes_are_escaped() {
    let value = json!("quote \" backslash \\ newline \n tab \t nul \u{0} é");
    assert_eq!(
        canonical(value),
        "\"quote \\\" backslash \\\\ newline \n tab \t nul \u{0} é\""
    );
}

/// 4.1: the examples "use a subset of the JSON object format, with
/// floating-point numbers omitted", and canonical JSON has only integers, so
/// metadata with a number that is not an integer, wherever it is, cannot be
/// decoded.
#[test]
fn numbers_must_be_integers() {
    assert!(canonical::to_vec(&json!({"a": 1.5})).is_err());
    assert!(canonical::to_vec(&json!([1.0])).is_err());
    assert_eq!(canonical(json!(u64::MAX)), u64::MAX.to_string());
    assert_eq!(canonical(json!(i64::MIN)), i64::MIN.to_string());

    let repo = TestRepo::new();
    let mut payload = serde_json::to_value(&repo.timestamp).unwrap();
    payload["x-extension"] = json!({"ratio": 0.5});
    assert_matches!(decode::<Timestamp>(payload), Err(Error::Decode(_)));
}

/// Signatures cover the canonical form of the payload exactly as received,
/// which is what `Metadata::canonical_signed` holds.
#[test]
fn signatures_cover_the_canonical_form_of_the_payload() {
    let repo = TestRepo::new();
    let timestamp = Metadata::<Timestamp>::from_bytes(&repo.file("timestamp.json")).unwrap();
    let document: Value = serde_json::from_slice(&repo.file("timestamp.json")).unwrap();
    assert_eq!(
        timestamp.canonical_signed(),
        canonical::to_vec(&document["signed"]).unwrap()
    );
    assert_data_eq!(
        String::from_utf8(timestamp.canonical_signed().to_vec()).unwrap(),
        str![[
            r#"{"_type":"timestamp","expires":"2125-05-08T12:00:00Z","meta":{"snapshot.json":{"version":1}},"spec_version":"1.0.36","version":1}"#
        ]]
    );
}

/// Because signatures cover the canonical form, the layout of a metadata
/// file (whitespace, member order) can change without invalidating them.
#[test]
fn formatting_does_not_affect_signatures() {
    let repo = TestRepo::new();
    let root = Metadata::<Root>::from_bytes(&repo.initial_root()).unwrap();
    let timestamp: Value = serde_json::from_slice(&repo.file("timestamp.json")).unwrap();
    let compact = serde_json::to_vec(&json!({
        "signed": timestamp["signed"],
        "signatures": timestamp["signatures"],
    }))
    .unwrap();
    assert_ne!(compact, repo.file("timestamp.json"));

    let reformatted = Metadata::<Timestamp>::from_bytes(&compact).unwrap();
    root.signed().verify_role(&reformatted).unwrap();
}

/// A JSON object with duplicate keys is read the same way for the payload
/// and for the bytes signatures cover (the last value wins), so a parser
/// difference cannot make the client check one value and use another.
#[test]
fn duplicate_keys_mean_the_same_to_payload_and_signatures() {
    let repo = TestRepo::new();
    let root = Metadata::<Root>::from_bytes(&repo.initial_root()).unwrap();
    let original = String::from_utf8(repo.file("timestamp.json")).unwrap();
    assert!(original.contains("\"version\": 1,"));
    let timestamp = |text: String| Metadata::<Timestamp>::from_bytes(text.as_bytes()).unwrap();

    // A duplicate before the signed value: the signed value counts.
    let before = timestamp(original.replace("\"version\": 1,", "\"version\": 2, \"version\": 1,"));
    assert_eq!(before.signed().version, 1);
    root.signed().verify_role(&before).unwrap();

    // A duplicate after it: the new value counts, and the signature is invalid.
    let after = timestamp(original.replace("\"version\": 1,", "\"version\": 1, \"version\": 2,"));
    assert_eq!(after.signed().version, 2);
    assert_matches!(
        root.signed().verify_role(&after),
        Err(Error::SignatureThreshold { .. })
    );
}
