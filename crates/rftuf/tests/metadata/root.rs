//! 4.3 File formats: root.json, which "indicates which keys are authorized
//! for all top-level roles, including the root role itself".

use std::assert_matches;

use rftuf::Error;
use rftuf::crypto::Signer;
use rftuf::metadata::{KeyId, Metadata, RoleType, Root};
use serde_json::{Value, json};

use crate::support::far_future;
use crate::support::keys::{key, key_id};
use crate::{decode, invalid_reason, python_tuf_payload};

#[test]
fn decodes_root_metadata() {
    let root = decode::<Root>(python_tuf_payload("root.json")).unwrap();
    let root = root.signed();
    assert_eq!(root.version, 1);
    assert_eq!(root.spec_version, "1.0.0");
    assert_eq!(root.keys.len(), 4);
    assert_eq!(
        root.roles.timestamp.keyids,
        [KeyId::new(
            "8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758"
        )]
    );
    assert_eq!(root.roles.timestamp.threshold, 1);
}

/// CONSISTENT_SNAPSHOT: "An OPTIONAL boolean indicating whether the
/// repository supports consistent snapshots"; when it is absent, the
/// repository does not (6.2.1: the attribute "MAY either be left unspecified
/// or be set to the false value").
#[test]
fn consistent_snapshot_is_optional() {
    for (value, uses_consistent_snapshots) in
        [(Some(true), true), (Some(false), false), (None, false)]
    {
        let mut payload = python_tuf_payload("root.json");
        match value {
            Some(value) => payload["consistent_snapshot"] = json!(value),
            None => {
                payload
                    .as_object_mut()
                    .unwrap()
                    .remove("consistent_snapshot");
            }
        }
        let root = decode::<Root>(payload).unwrap();
        assert_eq!(root.signed().consistent_snapshot, value);
        assert_eq!(
            root.signed().uses_consistent_snapshots(),
            uses_consistent_snapshots
        );
    }
}

/// ROLE: "A role for each of "root", "snapshot", "timestamp", and "targets"
/// MUST be specified in the roles object."
#[test]
fn every_top_level_role_must_be_listed() {
    for role in ["root", "snapshot", "targets", "timestamp"] {
        let mut payload = python_tuf_payload("root.json");
        payload["roles"].as_object_mut().unwrap().remove(role);
        assert_matches!(decode::<Root>(payload), Err(Error::Decode(_)), "{role}");
    }
}

/// THRESHOLD: "A positive integer number of keys (>=1)".
#[test]
fn thresholds_must_be_at_least_one() {
    for role in ["root", "snapshot", "targets", "timestamp"] {
        let mut payload = python_tuf_payload("root.json");
        payload["roles"][role]["threshold"] = json!(0);
        assert!(invalid_reason::<Root>(payload).contains("must be at least 1"));
    }
    let mut payload = python_tuf_payload("root.json");
    payload["roles"]["root"]["threshold"] = json!(-1);
    assert_matches!(decode::<Root>(payload), Err(Error::Decode(_)));
}

/// A role lists each of its keys once, so that no key can count twice
/// towards its threshold (5.3.4: "each KEY MUST only contribute one
/// SIGNATURE").
#[test]
fn a_role_must_not_list_a_key_twice() {
    let mut payload = python_tuf_payload("root.json");
    let keyid = payload["roles"]["root"]["keyids"][0].clone();
    payload["roles"]["root"]["keyids"]
        .as_array_mut()
        .unwrap()
        .push(keyid);
    assert!(invalid_reason::<Root>(payload).contains("more than once"));
}

/// ROLE: "The role of "mirror" is OPTIONAL." rftuf does not support the
/// mirrors role, but keeps it in root metadata, as it keeps every field it
/// does not know (see `unrecognized_fields`).
#[test]
fn the_mirrors_role_is_kept_but_not_used() {
    let mut payload = python_tuf_payload("root.json");
    payload["roles"]["mirrors"] = json!({"keyids": [], "threshold": 1});
    let root = decode::<Root>(payload).unwrap();
    assert_eq!(
        root.signed().roles.unrecognized_fields["mirrors"],
        json!({"keyids": [], "threshold": 1})
    );
    let encoded: Value = serde_json::from_slice(&root.to_bytes().unwrap()).unwrap();
    assert_eq!(encoded["signed"]["roles"]["mirrors"]["threshold"], 1);
}

/// Root metadata is created with `Root::new` and `Root::add_key`, which lists
/// a key once for each role it is added to.
#[test]
fn keys_are_listed_once_for_each_role_they_are_added_to() {
    let signer = key("root and targets");
    let id = key_id(&signer);
    let mut root = Root::new(far_future());
    for role in [RoleType::Root, RoleType::Root, RoleType::Targets] {
        root.add_key(role, id.clone(), signer.public_key().clone());
    }
    assert_eq!(root.roles.root.keyids, [id]);
    assert_eq!(root.roles.targets.keyids, root.roles.root.keyids);
    assert!(root.roles.timestamp.keyids.is_empty());
    assert_eq!(root.keys.len(), 1);
    Metadata::<Root>::new(root).unwrap();
}
