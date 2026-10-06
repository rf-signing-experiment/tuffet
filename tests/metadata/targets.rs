//! 4.5 File formats: targets.json and delegated target roles. Targets
//! metadata lists target files (TARGETS) and may delegate trust for some of
//! them to other roles (DELEGATIONS); delegated roles use the same format.

use rftuf::Error;
use rftuf::metadata::{HexBytes, Targets};
use serde_json::{Value, json};

use crate::{decode, invalid_reason, python_tuf_payload};

/// The targets payload of python-tuf's repository, with its first delegated
/// role changed by `change`.
fn with_delegated_role(change: impl FnOnce(&mut Value)) -> Value {
    let mut payload = python_tuf_payload("targets.json");
    change(&mut payload["delegations"]["roles"][0]);
    payload
}

/// TARGETS: each TARGETPATH has a LENGTH, HASHES and optionally CUSTOM data.
#[test]
fn decodes_targets_metadata() {
    let targets = decode::<Targets>(python_tuf_payload("targets.json")).unwrap();
    let targets = targets.signed();
    let file1 = &targets.targets["file1.txt"];
    assert_eq!(file1.length, 31);
    assert_eq!(
        file1.hashes.get("sha256"),
        Some(&HexBytes::new(
            hex::decode("65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da")
                .unwrap()
        ))
    );
    assert!(file1.hashes.get("sha512").is_some());
    assert_eq!(file1.custom, Some(json!({"file_permissions": "0644"})));
    assert_eq!(targets.targets["file2.txt"].custom, None);

    let delegations = targets.delegations.as_ref().unwrap();
    assert_eq!(delegations.keys.len(), 1);
    let role1 = targets.delegated_role("role1").unwrap();
    assert_eq!(role1.paths, Some(vec!["file3.txt".to_owned()]));
    assert_eq!((role1.threshold, role1.terminating), (1, false));
}

/// TARGETPATH: "It is allowed to have a TARGETS object with no TARGETPATH
/// elements."
#[test]
fn targets_may_be_empty() {
    let targets = decode::<Targets>(python_tuf_payload("role2.json")).unwrap();
    assert!(targets.signed().targets.is_empty());
}

/// HASHES: "A dictionary that specifies one or more hashes of the target
/// file".
#[test]
fn target_hashes_must_not_be_empty() {
    let mut payload = python_tuf_payload("targets.json");
    payload["targets"]["file1.txt"]["hashes"] = json!({});
    assert!(invalid_reason::<Targets>(payload).contains("must not be empty"));
}

/// "DELEGATIONS is an OPTIONAL object".
#[test]
fn delegations_are_optional() {
    let mut payload = python_tuf_payload("targets.json");
    payload.as_object_mut().unwrap().remove("delegations");
    let targets = decode::<Targets>(payload).unwrap();
    assert_eq!(targets.signed().delegations, None);
    assert_eq!(targets.signed().delegated_role("role1"), None);
}

/// ROLENAME: "The rolename MUST be unique in the delegations object:
/// multiple roles with the same rolename are not allowed within a
/// DELEGATIONS."
#[test]
fn delegated_role_names_must_be_unique() {
    let mut payload = python_tuf_payload("targets.json");
    let role = payload["delegations"]["roles"][0].clone();
    payload["delegations"]["roles"]
        .as_array_mut()
        .unwrap()
        .push(role);
    assert!(invalid_reason::<Targets>(payload).contains("delegated more than once"));
}

/// Delegated role names must name a role that has its own metadata file
/// (3.1.2.1), so rftuf, like the reference implementation, rejects empty
/// names and the names of the top-level roles.
#[test]
fn delegated_role_names_must_not_be_empty_or_top_level_role_names() {
    for name in ["", "root", "timestamp", "snapshot", "targets"] {
        let payload = with_delegated_role(|role| role["name"] = json!(name));
        assert!(
            invalid_reason::<Targets>(payload).contains("invalid delegated role name"),
            "{name:?}"
        );
    }
}

/// "The "path_hash_prefixes" and "paths" attributes are OPTIONAL, if used,
/// exactly one of them should be set." (A role with neither is trusted for
/// no paths; see `path_patterns`.)
#[test]
fn delegations_set_paths_or_path_hash_prefixes() {
    let both = with_delegated_role(|role| role["path_hash_prefixes"] = json!(["ab"]));
    assert!(invalid_reason::<Targets>(both).contains("both paths and path_hash_prefixes"));

    let neither = with_delegated_role(|role| {
        role.as_object_mut().unwrap().remove("paths");
    });
    decode::<Targets>(neither).unwrap();
}

/// THRESHOLD "is the same as is described for the root.json file": at
/// least 1.
#[test]
fn delegated_thresholds_must_be_at_least_one() {
    let payload = with_delegated_role(|role| role["threshold"] = json!(0));
    assert!(invalid_reason::<Targets>(payload).contains("must be at least 1"));
}

/// As in root metadata, a delegated role lists each of its keys once.
#[test]
fn a_delegated_role_must_not_list_a_key_twice() {
    let payload = with_delegated_role(|role| {
        let keyid = role["keyids"][0].clone();
        role["keyids"].as_array_mut().unwrap().push(keyid);
    });
    assert!(invalid_reason::<Targets>(payload).contains("more than once"));
}

/// The format of a delegated role has "terminating" without parentheses: it
/// is required.
#[test]
fn delegations_must_say_whether_they_are_terminating() {
    let payload = with_delegated_role(|role| {
        role.as_object_mut().unwrap().remove("terminating");
    });
    assert!(matches!(decode::<Targets>(payload), Err(Error::Decode(_))));
}

/// 4.5 (prioritized delegations): "the "roles" key in the DELEGATIONS object
/// above points to an array of delegated roles, rather than to a hash
/// table", whose order is kept.
#[test]
fn delegated_roles_keep_their_order_of_priority() {
    let mut payload = python_tuf_payload("targets.json");
    let role1 = payload["delegations"]["roles"][0].clone();
    let mut roles = Vec::new();
    for name in ["c", "a", "b"] {
        let mut role = role1.clone();
        role["name"] = json!(name);
        role["paths"] = json!(["*"]);
        roles.push(role);
    }
    payload["delegations"]["roles"] = json!(roles);
    let targets = decode::<Targets>(payload).unwrap();
    let delegations = targets.signed().delegations.as_ref().unwrap();
    let names: Vec<&str> = delegations
        .roles_for_target("file")
        .map(|role| role.name.as_str())
        .collect();
    assert_eq!(names, ["c", "a", "b"]);
}
