//! Tests of the verification rules in `TrustedMetadata`, without I/O.

mod common;

use std::collections::BTreeMap;

use chrono::Duration;
use common::{TestRepo, expired, now};
use rftuf::metadata::{MetaFile, RoleType};
use rftuf::trusted::TimestampUpdate;
use rftuf::{Error, TrustedMetadata};

fn trusted(repo: &TestRepo) -> TrustedMetadata {
    TrustedMetadata::new(&repo.initial_root(), now()).unwrap()
}

/// Loads timestamp, snapshot and targets metadata from the repository.
fn load_all(repo: &TestRepo) -> TrustedMetadata {
    let mut trusted = trusted(repo);
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    trusted.update_targets(&repo.file("targets.json")).unwrap();
    trusted
}

#[test]
fn loads_a_complete_set_of_metadata() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file.txt", b"content");
    repo.commit();
    let trusted = load_all(&repo);
    assert_eq!(trusted.timestamp().unwrap().signed().version, 2);
    assert_eq!(trusted.snapshot_meta().unwrap().version, 2);
    assert_eq!(trusted.targets_meta("targets").unwrap().version, 2);
    assert!(
        trusted
            .targets()
            .unwrap()
            .signed()
            .targets
            .contains_key("file.txt")
    );
}

#[test]
fn rejects_calls_out_of_order() {
    let repo = TestRepo::new();
    let mut trusted = trusted(&repo);
    let invalid_state = |result: rftuf::Result<()>| matches!(result, Err(Error::InvalidState(_)));

    assert!(invalid_state(
        trusted.update_snapshot(&repo.file("snapshot.json"))
    ));
    assert!(invalid_state(
        trusted.update_targets(&repo.file("targets.json")).map(drop)
    ));
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert!(invalid_state(
        trusted.update_root(&repo.file("1.root.json")).map(drop)
    ));
    assert!(invalid_state(
        trusted.load_cached_timestamp(&repo.file("timestamp.json"))
    ));
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    assert!(invalid_state(
        trusted
            .update_timestamp(&repo.file("timestamp.json"))
            .map(drop)
    ));
    trusted.update_targets(&repo.file("targets.json")).unwrap();
    assert!(invalid_state(
        trusted.update_snapshot(&repo.file("snapshot.json"))
    ));
}

#[test]
fn new_root_must_be_signed_by_old_and_new_root_keys() {
    let mut repo = TestRepo::new();
    let old_key = repo.signers["root"][0].clone();
    repo.rotate_key(RoleType::Root);
    let new_key = repo.signers["root"][0].clone();
    let mut next = repo.root.clone();
    next.version = 2;

    let mut trusted = trusted(&repo);
    let only_new = TestRepo::sign_with(&next, &[&new_key]);
    assert!(matches!(
        trusted.update_root(&only_new),
        Err(Error::SignatureThreshold { role, valid: 0, .. }) if role == "root"
    ));
    let only_old = TestRepo::sign_with(&next, &[&old_key]);
    assert!(matches!(
        trusted.update_root(&only_old),
        Err(Error::SignatureThreshold { .. })
    ));
    assert_eq!(trusted.root().signed().version, 1);

    trusted
        .update_root(&TestRepo::sign_with(&next, &[&old_key, &new_key]))
        .unwrap();
    assert_eq!(trusted.root().signed().version, 2);
}

#[test]
fn root_versions_must_increase_by_one() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    repo.publish_root();
    let mut trusted = trusted(&repo);
    for (file, actual) in [("3.root.json", 3), ("1.root.json", 1)] {
        let result = trusted.update_root(&repo.file(file));
        assert!(
            matches!(result, Err(Error::VersionMismatch { expected: 2, actual: a, .. }) if a == actual),
            "{file}"
        );
    }
    trusted.update_root(&repo.file("2.root.json")).unwrap();
    trusted.update_root(&repo.file("3.root.json")).unwrap();
}

#[test]
fn final_root_must_not_be_expired() {
    let mut repo = TestRepo::new();
    repo.root.expires = expired();
    repo.publish_root();
    let mut trusted = trusted(&repo);
    // Intermediate roots may be expired; the final one may not.
    trusted.update_root(&repo.file("2.root.json")).unwrap();
    assert!(matches!(
        trusted.update_timestamp(&repo.file("timestamp.json")),
        Err(Error::Expired { role, .. }) if role == "root"
    ));
}

#[test]
fn timestamp_must_not_be_expired() {
    let mut repo = TestRepo::new();
    repo.timestamp.expires = expired();
    repo.publish_timestamp();
    let mut trusted = trusted(&repo);
    assert!(matches!(
        trusted.update_timestamp(&repo.file("timestamp.json")),
        Err(Error::Expired { role, .. }) if role == "timestamp"
    ));
    assert!(trusted.timestamp().is_none());
}

#[test]
fn expired_cached_timestamp_still_prevents_rollback() {
    let mut repo = TestRepo::new();
    let old = repo.file("timestamp.json");
    repo.timestamp.expires = expired();
    repo.publish_timestamp();

    let mut trusted = trusted(&repo);
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert!(matches!(
        trusted.update_timestamp(&old),
        Err(Error::Rollback { role, trusted: 2, new: 1 }) if role == "timestamp"
    ));
}

#[test]
fn timestamp_with_the_trusted_version_is_unchanged() {
    let mut repo = TestRepo::new();
    let mut trusted = trusted(&repo);
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert_eq!(
        trusted
            .update_timestamp(&repo.file("timestamp.json"))
            .unwrap(),
        TimestampUpdate::Unchanged
    );

    // ...but an unchanged timestamp that has expired is not acceptable.
    repo.timestamp.expires = expired();
    repo.publish_timestamp();
    let mut trusted = self::trusted(&repo);
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert!(matches!(
        trusted.update_timestamp(&repo.file("timestamp.json")),
        Err(Error::Expired { role, .. }) if role == "timestamp"
    ));
}

#[test]
fn timestamp_must_not_roll_back_snapshot() {
    let mut repo = TestRepo::new();
    repo.publish_snapshot();
    let mut rolled_back = repo.timestamp.clone();
    rolled_back.version += 1;
    rolled_back.meta = BTreeMap::from([("snapshot.json".to_owned(), MetaFile::new(1))]);

    let mut trusted = trusted(&repo);
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert!(matches!(
        trusted.update_timestamp(&repo.sign("timestamp", &rolled_back)),
        Err(Error::Rollback { role, trusted: 2, new: 1 }) if role == "snapshot"
    ));
}

#[test]
fn timestamp_must_be_signed_by_current_keys() {
    let mut repo = TestRepo::new();
    let cached = repo.file("timestamp.json");
    repo.rotate_key(RoleType::Timestamp);
    repo.publish_root();
    repo.publish_timestamp();

    let mut trusted = trusted(&repo);
    trusted.update_root(&repo.file("2.root.json")).unwrap();
    assert!(matches!(
        trusted.load_cached_timestamp(&cached),
        Err(Error::SignatureThreshold { .. })
    ));
    assert!(matches!(
        trusted.update_timestamp(&cached),
        Err(Error::SignatureThreshold { .. })
    ));
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
}

#[test]
fn snapshot_must_match_timestamp() {
    let mut repo = TestRepo::new();
    repo.meta_hashes = true;
    repo.publish_snapshot();
    let mut trusted = trusted(&repo);
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();

    // Same version, different content: caught by the hashes in timestamp.
    let mut forged = repo.snapshot.clone();
    forged.expires += Duration::days(1);
    let result = trusted.update_snapshot(&repo.sign("snapshot", &forged));
    assert!(matches!(
        result,
        Err(Error::HashMismatch { .. } | Error::LengthMismatch { .. })
    ));

    // Without hashes in timestamp, the version must still match.
    let repo = TestRepo::new();
    let mut trusted = self::trusted(&repo);
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    let mut newer = repo.snapshot.clone();
    newer.version += 1;
    assert!(matches!(
        trusted.update_snapshot(&repo.sign("snapshot", &newer)),
        Err(Error::VersionMismatch {
            expected: 1,
            actual: 2,
            ..
        })
    ));
    // ...and it must be signed by the snapshot keys.
    assert!(matches!(
        trusted.update_snapshot(&repo.sign("timestamp", &repo.snapshot)),
        Err(Error::SignatureThreshold { .. })
    ));
}

#[test]
fn snapshot_must_not_remove_or_roll_back_targets() {
    let mut repo = TestRepo::new();
    repo.add_delegation("targets", "a", &["*"], false);
    repo.commit();
    let cached = repo.file("snapshot.json");

    // Timestamp for a snapshot v3 that the tests forge.
    let mut timestamp = repo.timestamp.clone();
    timestamp.version += 1;
    timestamp.meta = BTreeMap::from([("snapshot.json".to_owned(), MetaFile::new(3))]);
    let mut trusted = trusted(&repo);
    trusted
        .update_timestamp(&repo.sign("timestamp", &timestamp))
        .unwrap();
    assert!(
        !trusted.load_cached_snapshot(&cached).unwrap(),
        "cached snapshot is outdated"
    );

    let mut removed = repo.snapshot.clone();
    removed.version = 3;
    removed.meta.remove("a.json");
    assert!(matches!(
        trusted.update_snapshot(&repo.sign("snapshot", &removed)),
        Err(Error::RemovedFromSnapshot(name)) if name == "a.json"
    ));

    let mut rolled_back = repo.snapshot.clone();
    rolled_back.version = 3;
    rolled_back
        .meta
        .insert("targets.json".to_owned(), MetaFile::new(1));
    assert!(matches!(
        trusted.update_snapshot(&repo.sign("snapshot", &rolled_back)),
        Err(Error::Rollback { role, trusted: 2, new: 1 }) if role == "targets.json"
    ));
}

#[test]
fn outdated_cached_snapshot_cannot_be_used_for_targets() {
    let mut repo = TestRepo::new();
    let cached = repo.file("snapshot.json");
    repo.commit();

    let mut trusted = trusted(&repo);
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert!(!trusted.load_cached_snapshot(&cached).unwrap());
    assert!(matches!(
        trusted.update_targets(&repo.file("targets.json")),
        Err(Error::VersionMismatch { role, expected: 2, actual: 1 }) if role == "snapshot"
    ));
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    trusted.update_targets(&repo.file("targets.json")).unwrap();
}

#[test]
fn current_cached_snapshot_is_used_as_is() {
    let repo = TestRepo::new();
    let mut trusted = trusted(&repo);
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert!(
        trusted
            .load_cached_snapshot(&repo.file("snapshot.json"))
            .unwrap()
    );
    trusted.update_targets(&repo.file("targets.json")).unwrap();
}

#[test]
fn targets_must_match_snapshot() {
    let mut repo = TestRepo::new();
    repo.meta_hashes = true;
    repo.add_target("targets", "file.txt", b"content");
    repo.commit();
    let mut trusted = trusted(&repo);
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();

    let mut forged = repo.targets["targets"].clone();
    forged.targets.clear();
    assert!(matches!(
        trusted.update_targets(&repo.sign("targets", &forged)),
        Err(Error::HashMismatch { .. } | Error::LengthMismatch { .. })
    ));
    assert!(matches!(
        trusted.update_delegated_targets(&repo.file("targets.json"), "missing", "targets"),
        Err(Error::NotInSnapshot(name)) if name == "missing.json"
    ));
    trusted.update_targets(&repo.file("targets.json")).unwrap();
}

#[test]
fn targets_version_must_match_snapshot() {
    let repo = TestRepo::new();
    let mut trusted = trusted(&repo);
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    let mut newer = repo.targets["targets"].clone();
    newer.version = 5;
    assert!(matches!(
        trusted.update_targets(&repo.sign("targets", &newer)),
        Err(Error::VersionMismatch { role, expected: 1, actual: 5 }) if role == "targets"
    ));
}

#[test]
fn targets_must_not_be_expired() {
    let mut repo = TestRepo::new();
    repo.targets_mut("targets").expires = expired();
    repo.commit();
    let mut trusted = trusted(&repo);
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    assert!(matches!(
        trusted.update_targets(&repo.file("targets.json")),
        Err(Error::Expired { role, .. }) if role == "targets"
    ));
}

#[test]
fn delegated_targets_must_be_signed_by_delegated_keys() {
    let mut repo = TestRepo::new();
    repo.add_delegation("targets", "a", &["*"], false);
    repo.add_delegation("a", "b", &["*"], false);
    repo.commit();
    let mut trusted = load_all(&repo);
    let a = repo.file("a.json");

    assert!(matches!(
        trusted.update_delegated_targets(&repo.file("b.json"), "b", "a"),
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        trusted.update_delegated_targets(&a, "a", "root"),
        Err(Error::UnknownDelegation(role)) if role == "a"
    ));
    let signed_by_targets_key = repo.sign("targets", &repo.targets["a"]);
    assert!(matches!(
        trusted.update_delegated_targets(&signed_by_targets_key, "a", "targets"),
        Err(Error::SignatureThreshold { role, .. }) if role == "a"
    ));

    trusted
        .update_delegated_targets(&a, "a", "targets")
        .unwrap();
    trusted
        .update_delegated_targets(&repo.file("b.json"), "b", "a")
        .unwrap();
    assert!(trusted.targets_role("b").is_some());
}
