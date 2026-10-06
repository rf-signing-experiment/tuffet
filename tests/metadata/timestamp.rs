//! 4.6 File formats: timestamp.json, which "indicates the latest version of
//! the snapshot metadata".

use rftuf::Error;
use rftuf::metadata::{MetaFile, Metadata, Timestamp};
use serde_json::json;

use crate::support::far_future;
use crate::{decode, invalid_reason, python_tuf_payload};

#[test]
fn decodes_timestamp_metadata() {
    let timestamp = decode::<Timestamp>(python_tuf_payload("timestamp.json")).unwrap();
    let snapshot = &timestamp.signed().meta["snapshot.json"];
    assert_eq!(snapshot.version, 1);
    assert_eq!(snapshot.length, Some(515));
    assert!(snapshot.hashes.as_ref().unwrap().get("sha256").is_some());
}

/// METAFILES: "In the case of the timestamp.json file, this MUST only include
/// a description of the snapshot.json file."
#[test]
fn meta_must_describe_snapshot_json_only() {
    let mut other_file = python_tuf_payload("timestamp.json");
    other_file["meta"] = json!({"targets.json": {"version": 1}});
    assert!(invalid_reason::<Timestamp>(other_file).contains("snapshot.json"));

    let mut another_file = python_tuf_payload("timestamp.json");
    another_file["meta"]["targets.json"] = json!({"version": 1});
    assert!(invalid_reason::<Timestamp>(another_file).contains("snapshot.json"));

    let mut no_file = python_tuf_payload("timestamp.json");
    no_file["meta"] = json!({});
    assert!(invalid_reason::<Timestamp>(no_file).contains("snapshot.json"));
}

/// METAFILES HASHES: "A dictionary that specifies one or more hashes".
#[test]
fn meta_hashes_must_not_be_empty() {
    let mut payload = python_tuf_payload("timestamp.json");
    payload["meta"]["snapshot.json"]["hashes"] = json!({});
    assert!(invalid_reason::<Timestamp>(payload).contains("must not be empty"));
}

/// The same rules apply to timestamp metadata created for signing.
#[test]
fn a_new_timestamp_must_describe_snapshot_json() {
    let mut timestamp = Timestamp::new(far_future());
    assert!(matches!(
        Metadata::<Timestamp>::new(timestamp.clone()),
        Err(Error::InvalidMetadata(_))
    ));
    timestamp
        .meta
        .insert("snapshot.json".to_owned(), MetaFile::new(1));
    Metadata::<Timestamp>::new(timestamp).unwrap();
}
