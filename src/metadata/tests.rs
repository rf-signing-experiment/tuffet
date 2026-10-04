use chrono::{TimeZone, Utc};
use serde_json::json;

use super::*;
use crate::crypto::{PrivateKey, Signer};
use crate::pouf::Json;

/// Metadata from the reference implementation's test repository; see
/// `tests/data/README.md`.
macro_rules! python_tuf {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/python-tuf/metadata/",
            $name
        ))
    };
}

fn expires() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()
}

fn ed25519() -> PrivateKey {
    PrivateKey::generate(&SignatureScheme::Ed25519).unwrap()
}

fn key_id(signer: &PrivateKey) -> KeyId {
    Json::key_id(signer.public_key()).unwrap()
}

/// Decodes `value` as signed metadata with no signatures.
fn decode<T: Role>(signed: serde_json::Value) -> Result<Metadata<T>> {
    let envelope = json!({"signatures": [], "signed": signed});
    Metadata::from_bytes(&serde_json::to_vec(&envelope).unwrap())
}

fn invalid_reason<T: Role>(signed: serde_json::Value) -> String {
    match decode::<T>(signed) {
        Err(Error::InvalidMetadata(reason)) => reason,
        other => panic!("expected invalid metadata, got {other:?}"),
    }
}

fn timestamp_json() -> serde_json::Value {
    json!({
        "_type": "timestamp",
        "spec_version": "1.0.31",
        "version": 1,
        "expires": "2030-01-01T00:00:00Z",
        "meta": {"snapshot.json": {"version": 1}},
    })
}

#[test]
fn verifies_metadata_from_the_reference_implementation() {
    let root = Metadata::<Root>::from_bytes(python_tuf!("root.json")).unwrap();
    // Root is signed with RSA-PSS; its keys carry extra fields
    // (`keyid_hash_algorithms`) that are part of their key IDs.
    root.signed().verify_role(&root).unwrap();
    assert!(!root.signed().uses_consistent_snapshots());

    let timestamp = Metadata::<Timestamp>::from_bytes(python_tuf!("timestamp.json")).unwrap();
    let snapshot = Metadata::<Snapshot>::from_bytes(python_tuf!("snapshot.json")).unwrap();
    let targets = Metadata::<Targets>::from_bytes(python_tuf!("targets.json")).unwrap();
    root.signed().verify_role(&timestamp).unwrap();
    root.signed().verify_role(&snapshot).unwrap();
    root.signed().verify_role(&targets).unwrap();

    let role1 = Metadata::<Targets>::from_bytes(python_tuf!("role1.json")).unwrap();
    let role2 = Metadata::<Targets>::from_bytes(python_tuf!("role2.json")).unwrap();
    targets.signed().verify_delegate("role1", &role1).unwrap();
    role1.signed().verify_delegate("role2", &role2).unwrap();

    // The top-level targets key is not one of role1's keys.
    assert!(matches!(
        targets.signed().verify_delegate("role1", &targets),
        Err(Error::SignatureThreshold {
            valid: 0,
            threshold: 1,
            ..
        })
    ));
    assert!(matches!(
        targets.signed().verify_delegate("role2", &role2),
        Err(Error::UnknownDelegation(role)) if role == "role2"
    ));
}

#[test]
fn reencoded_metadata_keeps_valid_signatures() {
    let root = Metadata::<Root>::from_bytes(python_tuf!("root.json")).unwrap();
    for original in [&python_tuf!("targets.json")[..], python_tuf!("role1.json")] {
        let targets = Metadata::<Targets>::from_bytes(original).unwrap();
        let reencoded = Metadata::<Targets>::from_bytes(&targets.to_bytes().unwrap()).unwrap();
        assert_eq!(reencoded.canonical_signed(), targets.canonical_signed());
        assert_eq!(reencoded.signed(), targets.signed());
    }
    let targets = Metadata::<Targets>::from_bytes(python_tuf!("targets.json")).unwrap();
    let reencoded = Metadata::<Targets>::from_bytes(&targets.to_bytes().unwrap()).unwrap();
    root.signed().verify_role(&reencoded).unwrap();
}

#[test]
fn rejects_metadata_of_another_role() {
    let result = Metadata::<Root>::from_bytes(python_tuf!("timestamp.json"));
    assert!(matches!(result, Err(Error::Decode(e)) if e.to_string().contains("_type")));
    assert!(decode::<Snapshot>(json!({"version": 1})).is_err());
}

#[test]
fn rejects_malformed_documents() {
    for document in [
        &b"not json"[..],
        b"[]",
        b"{\"signed\": {}}",
        b"{\"signatures\": []}",
    ] {
        assert!(matches!(
            Metadata::<Root>::from_bytes(document),
            Err(Error::Decode(_))
        ));
    }
    let mut float_version = timestamp_json();
    float_version["version"] = json!(1.0);
    assert!(matches!(
        decode::<Timestamp>(float_version),
        Err(Error::Decode(_))
    ));
    let mut bad_expiry = timestamp_json();
    bad_expiry["expires"] = json!("2030-01-01");
    assert!(matches!(
        decode::<Timestamp>(bad_expiry),
        Err(Error::Decode(_))
    ));
}

#[test]
fn rejects_duplicate_signatures_by_one_key() {
    let mut envelope: serde_json::Value =
        serde_json::from_slice(python_tuf!("timestamp.json")).unwrap();
    let signature = envelope["signatures"][0].clone();
    envelope["signatures"]
        .as_array_mut()
        .unwrap()
        .push(signature);
    let result = Metadata::<Timestamp>::from_bytes(&serde_json::to_vec(&envelope).unwrap());
    assert!(
        matches!(result, Err(Error::InvalidMetadata(reason)) if reason.contains("multiple signatures"))
    );
}

#[test]
fn validates_common_fields() {
    decode::<Timestamp>(timestamp_json()).unwrap();
    for (field, value, reason) in [
        ("version", json!(0), "version must be greater than 0"),
        ("spec_version", json!("2.0.0"), "unsupported spec_version"),
        ("spec_version", json!("1"), "malformed spec_version"),
        ("spec_version", json!("1.0.x"), "malformed spec_version"),
    ] {
        let mut signed = timestamp_json();
        signed[field] = value;
        assert!(
            invalid_reason::<Timestamp>(signed).contains(reason),
            "{field}"
        );
    }
    let mut legacy = timestamp_json();
    legacy["spec_version"] = json!("1.0");
    decode::<Timestamp>(legacy).unwrap();
}

#[test]
fn timestamp_must_describe_only_snapshot() {
    let mut signed = timestamp_json();
    signed["meta"] = json!({"targets.json": {"version": 1}});
    assert!(invalid_reason::<Timestamp>(signed).contains("snapshot.json"));
    let mut signed = timestamp_json();
    signed["meta"]["targets.json"] = json!({"version": 1});
    assert!(invalid_reason::<Timestamp>(signed).contains("snapshot.json"));
    let mut signed = timestamp_json();
    signed["meta"]["snapshot.json"]["hashes"] = json!({});
    assert!(invalid_reason::<Timestamp>(signed).contains("must not be empty"));
}

#[test]
fn key_ids_are_opaque_labels() {
    let signer = ed25519();
    let id = KeyId::new("release-key-2025");
    let mut root = Root::new(expires());
    root.add_key(RoleType::Targets, id.clone(), signer.public_key().clone());
    let mut root = Metadata::<Root>::new(root.clone()).unwrap();
    root.sign(&signer).unwrap();
    let root = Metadata::<Root>::from_bytes(&root.to_bytes().unwrap()).unwrap();

    let mut targets = Metadata::<Targets>::new(Targets::new(expires())).unwrap();
    let sig = signer.sign(targets.canonical_signed()).unwrap();
    targets.add_signature(Signature::new(id, sig));
    root.signed().verify_role(&targets).unwrap();
}

#[test]
fn root_roles_must_have_valid_thresholds_and_unique_keys() {
    let root: serde_json::Value = serde_json::from_slice(python_tuf!("root.json")).unwrap();
    let mut zero = root["signed"].clone();
    zero["roles"]["snapshot"]["threshold"] = json!(0);
    assert!(invalid_reason::<Root>(zero).contains("threshold"));
    let mut duplicate = root["signed"].clone();
    let keyid = duplicate["roles"]["root"]["keyids"][0].clone();
    duplicate["roles"]["root"]["keyids"]
        .as_array_mut()
        .unwrap()
        .push(keyid);
    assert!(invalid_reason::<Root>(duplicate).contains("more than once"));
    let mut missing = root["signed"].clone();
    missing["roles"]
        .as_object_mut()
        .unwrap()
        .remove("timestamp");
    assert!(matches!(decode::<Root>(missing), Err(Error::Decode(_))));
}

#[test]
fn delegations_are_validated() {
    let targets: serde_json::Value = serde_json::from_slice(python_tuf!("targets.json")).unwrap();
    let signed = targets["signed"].clone();
    let role = signed["delegations"]["roles"][0].clone();

    for (name, change, reason) in [
        (
            "top-level name",
            json!({"name": "root"}),
            "invalid delegated role name",
        ),
        (
            "empty name",
            json!({"name": ""}),
            "invalid delegated role name",
        ),
        (
            "both path kinds",
            json!({"path_hash_prefixes": ["ab"]}),
            "both paths and path_hash_prefixes",
        ),
        ("zero threshold", json!({"threshold": 0}), "threshold"),
    ] {
        let mut changed_role = role.clone();
        for (field, value) in change.as_object().unwrap() {
            changed_role[field] = value.clone();
        }
        let mut changed = signed.clone();
        changed["delegations"]["roles"] = json!([changed_role]);
        assert!(
            invalid_reason::<Targets>(changed).contains(reason),
            "{name}"
        );
    }

    let mut duplicated = signed.clone();
    duplicated["delegations"]["roles"] = json!([role.clone(), role]);
    assert!(invalid_reason::<Targets>(duplicated).contains("delegated more than once"));

    let mut no_hashes = signed;
    no_hashes["targets"]["file1.txt"]["hashes"] = json!({});
    assert!(invalid_reason::<Targets>(no_hashes).contains("must not be empty"));
}

#[test]
fn threshold_counts_distinct_valid_signatures_from_authorized_keys() {
    let signers = [ed25519(), ed25519(), ed25519()];
    let outsider = ed25519();
    let mut root = Root::new(expires());
    for signer in &signers {
        root.add_key(
            RoleType::Targets,
            key_id(signer),
            signer.public_key().clone(),
        );
    }
    root.roles.targets.threshold = 2;
    root.add_key(
        RoleType::Snapshot,
        key_id(&outsider),
        outsider.public_key().clone(),
    );

    let mut targets = Metadata::<Targets>::new(Targets::new(expires())).unwrap();
    targets.sign(&outsider).unwrap();
    targets.sign(&signers[0]).unwrap();
    assert!(matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold {
            valid: 1,
            threshold: 2,
            ..
        })
    ));

    // An invalid signature by an authorized key does not count.
    targets.add_signature(Signature::new(key_id(&signers[1]), vec![0; 64]));
    assert!(matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold { valid: 1, .. })
    ));

    targets.sign(&signers[1]).unwrap();
    root.verify_role(&targets).unwrap();
    assert_eq!(targets.signatures().len(), 3);
}

#[test]
fn a_key_listed_under_two_key_ids_counts_once() {
    let signer = ed25519();
    let key = signer.public_key().clone();
    let mut variant = key.clone();
    variant
        .unrecognized_fields
        .insert("comment".into(), json!("same key"));
    let (id, variant_id) = (Json::key_id(&key).unwrap(), Json::key_id(&variant).unwrap());
    assert_ne!(id, variant_id);

    let mut root = Root::new(expires());
    root.add_key(RoleType::Targets, id.clone(), key);
    root.add_key(RoleType::Targets, variant_id.clone(), variant);
    root.roles.targets.threshold = 2;
    Metadata::<Root>::new(root.clone()).unwrap();

    let mut targets = Metadata::<Targets>::new(Targets::new(expires())).unwrap();
    let sig = signer.sign(targets.canonical_signed()).unwrap();
    targets.add_signature(Signature::new(id, sig.clone()));
    targets.add_signature(Signature::new(variant_id, sig));
    assert!(matches!(
        root.verify_role(&targets),
        Err(Error::SignatureThreshold { valid: 1, .. })
    ));
}

#[test]
fn signatures_cover_unrecognized_fields() {
    let signer = ed25519();
    let mut root = Root::new(expires());
    root.add_key(
        RoleType::Targets,
        key_id(&signer),
        signer.public_key().clone(),
    );

    let mut payload = Targets::new(expires());
    payload
        .unrecognized_fields
        .insert("x-extension".into(), json!({"level": 1}));
    let mut targets = Metadata::<Targets>::new(payload).unwrap();
    targets.sign(&signer).unwrap();
    let encoded = String::from_utf8(targets.to_bytes().unwrap()).unwrap();

    let decoded = Metadata::<Targets>::from_bytes(encoded.as_bytes()).unwrap();
    assert_eq!(
        decoded.signed().unrecognized_fields["x-extension"],
        json!({"level": 1})
    );
    root.verify_role(&decoded).unwrap();

    let tampered = encoded.replace("\"level\": 1", "\"level\": 2");
    assert_ne!(tampered, encoded);
    let tampered = Metadata::<Targets>::from_bytes(tampered.as_bytes()).unwrap();
    assert!(matches!(
        root.verify_role(&tampered),
        Err(Error::SignatureThreshold { .. })
    ));
}

#[test]
fn signing_again_replaces_the_signature() {
    let signer = ed25519();
    let mut targets = Metadata::<Targets>::new(Targets::new(expires())).unwrap();
    targets.sign(&signer).unwrap();
    targets.sign(&signer).unwrap();
    assert_eq!(targets.signatures().len(), 1);
    targets.clear_signatures();
    assert!(targets.signatures().is_empty());
}

#[test]
fn new_metadata_is_validated() {
    let mut timestamp = Timestamp::new(expires());
    assert!(matches!(
        Metadata::<Timestamp>::new(timestamp.clone()),
        Err(Error::InvalidMetadata(_))
    ));
    timestamp
        .meta
        .insert("snapshot.json".into(), MetaFile::new(1));
    Metadata::<Timestamp>::new(timestamp).unwrap();
}

#[test]
fn delegated_paths_and_hash_prefixes() {
    let mut role = DelegatedRole::new("r", Vec::new(), 1);
    assert!(!role.is_delegated_path("anything"));
    role.paths = Some(vec!["dir/*.txt".into(), "exact".into()]);
    assert!(role.is_delegated_path("dir/a.txt"));
    assert!(role.is_delegated_path("exact"));
    assert!(!role.is_delegated_path("dir/sub/a.txt"));

    let digest = ::hex::encode(crate::crypto::HashAlgorithm::Sha256.digest(b"file1.txt"));
    role.paths = None;
    role.path_hash_prefixes = Some(vec![digest[..4].to_owned()]);
    assert!(role.is_delegated_path("file1.txt"));
    role.path_hash_prefixes = Some(vec!["ffff".into(), digest[..2].to_owned()]);
    assert!(role.is_delegated_path("file1.txt"));
    role.path_hash_prefixes = Some(vec![format!("{}x", &digest[..3])]);
    assert!(!role.is_delegated_path("file1.txt"));
}

#[test]
fn unsupported_roles_in_root_are_preserved() {
    let mut root: serde_json::Value = serde_json::from_slice(python_tuf!("root.json")).unwrap();
    root["signed"]["roles"]["mirrors"] = json!({"keyids": [], "threshold": 1});
    let decoded = decode::<Root>(root["signed"].take()).unwrap();
    assert!(
        decoded
            .signed()
            .roles
            .unrecognized_fields
            .contains_key("mirrors")
    );
    let reencoded: serde_json::Value =
        serde_json::from_slice(&decoded.to_bytes().unwrap()).unwrap();
    assert_eq!(reencoded["signed"]["roles"]["mirrors"]["threshold"], 1);
}
