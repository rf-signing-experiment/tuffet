//! Interoperability with the reference implementation, python-tuf, through
//! its test repository (`tests/data/python-tuf`; see `tests/data/README.md`):
//! rftuf verifies its metadata, computes its key IDs, re-encodes it without
//! invalidating signatures, and updates from it.

mod support;

use chrono::{TimeZone, Utc};
use futures_executor::block_on;
use rftuf::metadata::{Metadata, Root, Snapshot, Targets, Timestamp};
use rftuf::pouf::{Json, Pouf};
use rftuf::store::FilesystemStore;
use rftuf::transport::FilesystemTransport;
use rftuf::{Error, Updater};

use support::data::{self, python_tuf};

#[test]
fn verifies_the_metadata_of_the_reference_implementation() {
    let root = Metadata::<Root>::from_bytes(&python_tuf("root.json")).unwrap();
    // Root is signed with an RSA-PSS key, the other top-level roles with
    // Ed25519 keys.
    root.signed().verify_role(&root).unwrap();
    let timestamp = Metadata::<Timestamp>::from_bytes(&python_tuf("timestamp.json")).unwrap();
    root.signed().verify_role(&timestamp).unwrap();
    let snapshot = Metadata::<Snapshot>::from_bytes(&python_tuf("snapshot.json")).unwrap();
    root.signed().verify_role(&snapshot).unwrap();
    let targets = Metadata::<Targets>::from_bytes(&python_tuf("targets.json")).unwrap();
    root.signed().verify_role(&targets).unwrap();

    // "targets" delegates to "role1", which delegates to "role2".
    let role1 = Metadata::<Targets>::from_bytes(&python_tuf("role1.json")).unwrap();
    targets.signed().verify_delegate("role1", &role1).unwrap();
    let role2 = Metadata::<Targets>::from_bytes(&python_tuf("role2.json")).unwrap();
    role1.signed().verify_delegate("role2", &role2).unwrap();

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

/// The key IDs rftuf computes for new keys are those of the reference
/// implementation, including for keys with fields rftuf does not know (here
/// `keyid_hash_algorithms`).
#[test]
fn computes_the_key_ids_of_the_reference_implementation() {
    let root = Metadata::<Root>::from_bytes(&python_tuf("root.json")).unwrap();
    let targets = Metadata::<Targets>::from_bytes(&python_tuf("targets.json")).unwrap();
    let delegated_keys = &targets.signed().delegations.as_ref().unwrap().keys;
    for (keyid, key) in root.signed().keys.iter().chain(delegated_keys) {
        assert!(
            key.unrecognized_fields
                .contains_key("keyid_hash_algorithms")
        );
        assert_eq!(&Json::key_id(key).unwrap(), keyid);
    }
}

/// Re-encoded metadata keeps all its fields (see
/// `metadata::unrecognized_fields`), so its signatures stay valid.
#[test]
fn reencoded_metadata_keeps_valid_signatures() {
    let root = Metadata::<Root>::from_bytes(&python_tuf("root.json")).unwrap();
    for name in ["targets.json", "role1.json"] {
        let original = Metadata::<Targets>::from_bytes(&python_tuf(name)).unwrap();
        let reencoded = Metadata::<Targets>::from_bytes(&original.to_bytes().unwrap()).unwrap();
        assert_eq!(
            reencoded.canonical_signed(),
            original.canonical_signed(),
            "{name}"
        );
        assert_eq!(reencoded.signed(), original.signed(), "{name}");
    }
    let targets = Metadata::<Targets>::from_bytes(&python_tuf("targets.json")).unwrap();
    let reencoded = Metadata::<Targets>::from_bytes(&targets.to_bytes().unwrap()).unwrap();
    root.signed().verify_role(&reencoded).unwrap();
}

/// The whole workflow against the reference implementation's repository, on
/// disk: refresh, find a target listed by a delegated role, download it.
#[test]
fn updates_from_the_repository_of_the_reference_implementation() {
    let repository = data::path("python-tuf");
    let transport =
        FilesystemTransport::new(repository.join("metadata"), repository.join("targets"));
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::new(dir.path().join("metadata")).unwrap();
    let mut updater = Updater::builder(transport, store)
        .initial_root(python_tuf("root.json"))
        .build()
        .unwrap();

    block_on(updater.refresh_at(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap())).unwrap();
    let file1 = block_on(updater.get_target_info("file1.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(
        file1.file.custom,
        Some(serde_json::json!({"file_permissions": "0644"}))
    );

    // file3.txt is listed by the delegated role "role1".
    let file3 = block_on(updater.get_target_info("file3.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(file3.role, "role1");
    let destination = dir.path().join("file3.txt");
    block_on(updater.download_target_to(&file3, &destination)).unwrap();
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        std::fs::read(repository.join("targets/file3.txt")).unwrap()
    );
    for name in [
        "root.json",
        "timestamp.json",
        "snapshot.json",
        "targets.json",
        "role1.json",
    ] {
        assert!(
            dir.path().join("metadata").join(name).exists(),
            "{name} is persisted"
        );
    }

    // The repository's metadata expires in 2030.
    let late = Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0).unwrap();
    assert!(matches!(
        block_on(updater.refresh_at(late)),
        Err(Error::Expired { .. })
    ));
}
