//! The JSON encoding of metadata, compared with the files in `snapshots/`.
//!
//! The snapshots show the format of each role's metadata as rftuf writes it
//! (4.2 to 4.6): field names and nesting, optional fields left out when
//! unset, date-times (4.2.3), hex-encoded hashes and signatures (4.2.1), and
//! the encoding of each key type (4.2.2). Keys are derived from fixed names,
//! and Ed25519 signatures are deterministic, so the output is the same in
//! every run.
//!
//! After an intentional change to the encoding, update the snapshots with
//! `SNAPSHOTS=overwrite cargo test --test metadata`, and review the diff.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rftuf::crypto::{HashAlgorithm, PrivateKey, Signer, public_key_from_pem};
use rftuf::metadata::{
    DelegatedRole, Delegations, Key, MetaFile, Metadata, Role, RoleType, Root, SignatureScheme,
    Snapshot, TargetFile, Targets, Timestamp,
};
use serde_json::json;
use snapbox::{assert_data_eq, file};

use crate::support::data;
use crate::support::keys::{key, key_id};

fn expires() -> jiff::Timestamp {
    "2030-01-01T00:00:00Z".parse().unwrap()
}

/// Signs `payload` with `signers` and encodes it, as the text of a snapshot
/// file (which ends with a newline).
fn encode<T: Role>(payload: T, signers: &[&PrivateKey]) -> String {
    let mut metadata = Metadata::<T>::new(payload).unwrap();
    for signer in signers {
        metadata.sign(*signer).unwrap();
    }
    String::from_utf8(metadata.to_bytes().unwrap()).unwrap() + "\n"
}

/// The path of a snapshot file.
fn snapshot_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/metadata/snapshots")
        .join(name)
}

/// 4.3: root metadata lists the keys of every top-level role.
#[test]
fn root_json() {
    let mut root = Root::new(expires());
    for role in [
        RoleType::Root,
        RoleType::Timestamp,
        RoleType::Snapshot,
        RoleType::Targets,
    ] {
        let key = key(role.as_str());
        root.add_key(role, key_id(&key), key.public_key().clone());
    }
    let second_root_key = key("root 2");
    root.add_key(
        RoleType::Root,
        key_id(&second_root_key),
        second_root_key.public_key().clone(),
    );
    root.roles.root.threshold = 2;

    assert_data_eq!(
        encode(root, &[&key("root"), &second_root_key]),
        file!["snapshots/root.json"].raw()
    );
}

/// 4.6: timestamp metadata describes snapshot metadata, here by version,
/// length and hashes.
#[test]
fn timestamp_json() {
    let mut timestamp = Timestamp::new(expires());
    timestamp.version = 42;
    timestamp.meta.insert(
        "snapshot.json".to_owned(),
        MetaFile::from_bytes(7, b"snapshot metadata", &[HashAlgorithm::Sha256]),
    );
    assert_data_eq!(
        encode(timestamp, &[&key("timestamp")]),
        file!["snapshots/timestamp.json"].raw()
    );
}

/// 4.4: snapshot metadata describes targets metadata by version, and
/// optionally length and hashes.
#[test]
fn snapshot_json() {
    let mut snapshot = Snapshot::new(expires());
    snapshot.version = 7;
    snapshot
        .meta
        .insert("targets.json".to_owned(), MetaFile::new(3));
    snapshot.meta.insert(
        "project.json".to_owned(),
        MetaFile::from_bytes(1, b"project metadata", &HashAlgorithm::ALL),
    );
    assert_data_eq!(
        encode(snapshot, &[&key("snapshot")]),
        file!["snapshots/snapshot.json"].raw()
    );
}

/// 4.5: targets metadata lists targets, with custom data, and delegates by
/// paths and by path hash prefixes.
#[test]
fn targets_json() {
    let mut targets = Targets::new(expires());
    targets.version = 3;
    targets.targets.insert(
        "file.txt".to_owned(),
        TargetFile::from_bytes(b"file", &HashAlgorithm::ALL),
    );
    let mut with_custom = TargetFile::from_bytes(b"package", &[HashAlgorithm::Sha256]);
    with_custom.custom = Some(json!({"version": "1.2.3", "requires": ["libc"]}));
    targets
        .targets
        .insert("dir/package.tgz".to_owned(), with_custom);

    let (project, bins) = (key("project"), [key("bins 1"), key("bins 2")]);
    let mut delegations = Delegations::new();
    for signer in [&project, &bins[0], &bins[1]] {
        delegations
            .keys
            .insert(key_id(signer), signer.public_key().clone());
    }
    let mut by_paths = DelegatedRole::new("project", vec![key_id(&project)], 1);
    by_paths.paths = Some(vec!["project/*".to_owned(), "*.tgz".to_owned()]);
    by_paths.terminating = true;
    let mut by_prefixes = DelegatedRole::new("bins", vec![key_id(&bins[0]), key_id(&bins[1])], 2);
    by_prefixes.path_hash_prefixes = Some(vec!["0".to_owned(), "1".to_owned()]);
    delegations.roles = vec![by_paths, by_prefixes];
    targets.delegations = Some(delegations);

    assert_data_eq!(
        encode(targets, &[&key("targets")]),
        file!["snapshots/targets.json"].raw()
    );
}

/// 4.2.2: how each key type encodes its public key: hex for Ed25519, PEM
/// `SubjectPublicKeyInfo` for the others (the ML-DSA key types and schemes
/// are those of TAP 21).
#[test]
fn key_objects() {
    let mut keys: BTreeMap<String, Key> = BTreeMap::new();
    keys.insert("ed25519".to_owned(), key("ed25519").public_key().clone());
    for (scheme, pem) in [
        (SignatureScheme::EcdsaSha2Nistp256, "p256.pub.pem"),
        (SignatureScheme::EcdsaSha2Nistp384, "p384.pub.pem"),
        (SignatureScheme::RsassaPssSha256, "rsa.pub.pem"),
        (SignatureScheme::MlDsa44V1, "ml-dsa-44.pub.pem"),
    ] {
        let key = public_key_from_pem(&scheme, &data::crypto_text(pem)).unwrap();
        keys.insert(scheme.to_string(), key);
    }
    assert_data_eq!(
        serde_json::to_string_pretty(&keys).unwrap() + "\n",
        file!["snapshots/keys.json"].raw()
    );
}

/// What rftuf encodes, it decodes again, with valid signatures, and encodes
/// to the same bytes.
#[test]
fn encoded_metadata_decodes_and_reencodes_identically() {
    fn round_trip<T: Role>(name: &str) -> Metadata<T> {
        let file = std::fs::read(snapshot_path(name)).unwrap();
        let encoded = file.strip_suffix(b"\n").unwrap();
        let metadata = Metadata::<T>::from_bytes(encoded).unwrap();
        assert_eq!(metadata.to_bytes().unwrap(), encoded, "{name}");
        metadata
    }
    let root = round_trip::<Root>("root.json");
    root.signed().verify_role(&root).unwrap();

    // Timestamp, snapshot and targets metadata, signed by the root above.
    let timestamp = round_trip::<Timestamp>("timestamp.json");
    root.signed().verify_role(&timestamp).unwrap();
    let snapshot = round_trip::<Snapshot>("snapshot.json");
    root.signed().verify_role(&snapshot).unwrap();
    let targets = round_trip::<Targets>("targets.json");
    root.signed().verify_role(&targets).unwrap();
}
