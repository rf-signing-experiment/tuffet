//! 4.4 File formats: snapshot.json, and the METAFILES object it shares with
//! timestamp.json (4.6). Snapshot metadata "MUST list the version numbers
//! of the top-level targets metadata and all delegated targets metadata. It
//! MAY also list their lengths and file hashes."

use serde_json::json;
use tuffet::metadata::{HexBytes, Snapshot};

use crate::{decode, invalid_reason, python_tuf_payload};

/// METAFILES: each entry has a VERSION, and optionally a LENGTH and HASHES
/// (here, the example of 4.4).
#[test]
fn meta_lists_versions_with_optional_lengths_and_hashes() {
    let mut payload = python_tuf_payload("snapshot.json");
    payload["meta"] = json!({
        "targets.json": {"version": 1},
        "project1.json": {
            "version": 1,
            "hashes": {"sha256": "f592d072e1193688a686267e8e10d7257b4ebfcf28133350dae88362d82a0c8a"}
        },
        "project2.json": {
            "version": 1,
            "length": 604,
            "hashes": {"sha256": "1f812e378264c3085bb69ec5f6663ed21e5882bbece3c3f8a0e8479f205ffb91"}
        },
    });
    let snapshot = decode::<Snapshot>(payload).unwrap();
    let meta = &snapshot.signed().meta;

    assert_eq!(meta["targets.json"].version, 1);
    assert_eq!(meta["targets.json"].length, None);
    assert_eq!(meta["targets.json"].hashes, None);
    assert_eq!(meta["project1.json"].length, None);
    let project2 = &meta["project2.json"];
    assert_eq!(project2.length, Some(604));
    assert_eq!(
        project2.hashes.as_ref().unwrap().get("sha256"),
        Some(&HexBytes::new(
            hex::decode("1f812e378264c3085bb69ec5f6663ed21e5882bbece3c3f8a0e8479f205ffb91")
                .unwrap()
        ))
    );
}

/// METAFILES VERSION is a version number of metadata, which "is greater
/// than 0" (4.3).
#[test]
fn meta_versions_must_be_greater_than_zero() {
    let mut payload = python_tuf_payload("snapshot.json");
    payload["meta"]["role1.json"]["version"] = json!(0);
    assert!(invalid_reason::<Snapshot>(payload).contains("version of role1.json"));
}

/// METAFILES HASHES: "A dictionary that specifies one or more hashes".
#[test]
fn meta_hashes_must_not_be_empty() {
    let mut payload = python_tuf_payload("snapshot.json");
    payload["meta"]["role1.json"]["hashes"] = json!({});
    assert!(invalid_reason::<Snapshot>(payload).contains("must not be empty"));
}
