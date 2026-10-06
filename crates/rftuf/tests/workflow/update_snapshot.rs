//! 5.5 Update the snapshot role.
//!
//! Snapshot metadata is downloaded when the trusted timestamp lists a version
//! the client does not have. It must be the snapshot the timestamp
//! describes, be signed by the root's snapshot keys, not roll back any
//! targets metadata the trusted snapshot lists, and not have expired.

use jiff::SignedDuration;
use rftuf::metadata::{MetaFile, RoleType};
use rftuf::pouf::Json;
use rftuf::{Error, TrustedMetadata, UpdaterConfig};

use crate::support::{Delegation, TestRepo, assert_err, expired, now};

/// Verification state that trusts the repository's current snapshot, loaded
/// from the cache, and a timestamp that lists the next snapshot version,
/// which the tests then forge.
fn expecting_next_snapshot(repo: &TestRepo) -> TrustedMetadata {
    let mut timestamp = repo.timestamp.clone();
    timestamp.version += 1;
    let next_version = repo.snapshot.version + 1;
    timestamp
        .meta
        .insert("snapshot.json".to_owned(), MetaFile::new(next_version));
    let mut trusted = repo.trusted();
    trusted
        .update_timestamp(&repo.sign("timestamp", &timestamp))
        .unwrap();
    let current = trusted
        .load_cached_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    assert!(!current, "the trusted snapshot is outdated");
    trusted
}

/// 5.5.1: snapshot metadata is downloaded "up to ... the number of bytes
/// specified in the timestamp metadata file", which then takes precedence
/// over the configured maximum.
#[test]
fn snapshot_downloads_are_limited_to_the_length_listed_in_timestamp() {
    let mut repo = TestRepo::builder().meta_lengths().build();
    let length = repo.timestamp.meta["snapshot.json"].length.unwrap();
    // Trailing whitespace changes neither the payload nor its signature.
    let mut padded = repo.file("snapshot.json");
    padded.extend_from_slice(&[b' '; 100]);
    repo.write("snapshot.json", padded);

    let mut config = UpdaterConfig::default();
    config.snapshot_max_length = length + 10;
    assert_err!(
        repo.client_with(config).refresh(),
        Error::TooLarge { name, max } if name == "snapshot.json" && max == length
    );
}

/// 5.5.1: when timestamp metadata lists no length, snapshot metadata is
/// downloaded up to "some Y number of bytes":
/// `UpdaterConfig::snapshot_max_length`.
#[test]
fn snapshot_downloads_are_limited_to_snapshot_max_length() {
    let repo = TestRepo::new();
    let length = repo.file("snapshot.json").len() as u64;

    let mut config = UpdaterConfig::default();
    config.snapshot_max_length = length - 1;
    assert_err!(
        repo.client_with(config.clone()).refresh(),
        Error::TooLarge { name, max } if name == "snapshot.json" && max == length - 1
    );
    config.snapshot_max_length = length;
    repo.client_with(config).refresh().unwrap();
}

/// 5.5.2: "The hashes of the new snapshot metadata file MUST match the
/// hashes, if any, listed in the trusted timestamp metadata. This is done,
/// in part, to prevent a mix-and-match attack": a snapshot that is validly
/// signed and has the listed version, but is not the one the timestamp
/// describes, is rejected.
#[test]
fn snapshot_must_match_the_hashes_listed_in_timestamp() {
    let repo = TestRepo::builder().meta_hashes().build();
    let mut trusted = repo.trusted_with_timestamp();
    let mut other = repo.snapshot.clone();
    other.expires += SignedDuration::from_hours(24);

    assert_err!(
        trusted.update_snapshot(&repo.sign("snapshot", &other)),
        Error::HashMismatch { name, algorithm } if name == "snapshot.json" && algorithm == "sha256"
    );
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
}

/// 5.5.3: "The new snapshot metadata file MUST have been signed by a
/// THRESHOLD of keys specified in the trusted root metadata file."
#[test]
fn snapshot_must_be_signed_by_a_threshold_of_snapshot_keys() {
    let repo = TestRepo::builder().keys(RoleType::Snapshot, 2, 2).build();
    let keys = &repo.signers["snapshot"];
    let mut trusted = repo.trusted_with_timestamp();

    let by_timestamp_key = repo.sign("timestamp", &repo.snapshot);
    assert_err!(
        trusted.update_snapshot(&by_timestamp_key),
        Error::SignatureThreshold { role, valid: 0, threshold: 2 } if role == "snapshot"
    );
    let by_one_key = TestRepo::sign_with(&repo.snapshot, &[&keys[0]]);
    assert_err!(
        trusted.update_snapshot(&by_one_key),
        Error::SignatureThreshold { role, valid: 1, threshold: 2 } if role == "snapshot"
    );
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
}

/// 5.5.4: "The version number of the new snapshot metadata file MUST match
/// the version number listed in the trusted timestamp metadata."
#[test]
fn snapshot_version_must_match_timestamp() {
    let mut repo = TestRepo::new();
    let version_1 = repo.file("snapshot.json");
    let mut version_2 = repo.snapshot.clone();
    version_2.version = 2;
    let version_2 = repo.sign("snapshot", &version_2);
    let mut trusted = repo.trusted_with_timestamp();
    assert_err!(
        trusted.update_snapshot(&version_2),
        Error::VersionMismatch { role, expected: 1, actual: 2 } if role == "snapshot"
    );

    repo.publish_snapshot();
    repo.write("snapshot.json", version_1);
    assert_err!(
        repo.client().refresh(),
        Error::VersionMismatch { role, expected: 2, actual: 1 } if role == "snapshot"
    );
}

/// 5.5.5: "The version number of the targets metadata file, and all
/// delegated targets metadata files, if any, in the trusted snapshot
/// metadata file, if any, MUST be less than or equal to its version number
/// in the new snapshot metadata file."
#[test]
fn snapshot_must_not_roll_back_targets_metadata() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["*"]));
    repo.commit();
    repo.add_target("a", "file", b"data");
    repo.commit();
    assert_eq!(repo.snapshot.meta["targets.json"].version, 2);
    assert_eq!(repo.snapshot.meta["a.json"].version, 2);

    for file in ["targets.json", "a.json"] {
        let mut trusted = expecting_next_snapshot(&repo);
        let mut next = repo.snapshot.clone();
        next.version += 1;
        next.meta.insert(file.to_owned(), MetaFile::new(1));
        assert_err!(
            trusted.update_snapshot(&repo.sign("snapshot", &next)),
            Error::Rollback { role, trusted: 2, new: 1 } if role == file
        );
    }
}

/// 5.5.5: "Furthermore, any targets metadata filename that was listed in the
/// trusted snapshot metadata file, if any, MUST continue to be listed in
/// the new snapshot metadata file."
#[test]
fn snapshot_must_keep_listing_targets_metadata() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["*"]));
    repo.commit();

    for file in ["targets.json", "a.json"] {
        let mut trusted = expecting_next_snapshot(&repo);
        let mut next = repo.snapshot.clone();
        next.version += 1;
        next.meta.remove(file);
        assert_err!(
            trusted.update_snapshot(&repo.sign("snapshot", &next)),
            Error::RemovedFromSnapshot(name) if name == file
        );
    }
}

/// 5.5.5: within those rules, versions may stay the same or increase, and
/// new targets metadata may be listed.
#[test]
fn snapshot_may_keep_or_increase_versions_and_list_new_files() {
    let repo = TestRepo::new();
    let mut trusted = expecting_next_snapshot(&repo);
    let mut next = repo.snapshot.clone();
    next.version += 1;
    next.meta
        .insert("new-role.json".to_owned(), MetaFile::new(1));
    trusted
        .update_snapshot(&repo.sign("snapshot", &next))
        .unwrap();
}

/// 5.5.6: "If the new snapshot metadata file is expired, discard it, abort
/// the update cycle, and report the potential freeze attack."
#[test]
fn rejects_an_expired_snapshot() {
    let mut repo = TestRepo::new();
    repo.snapshot.expires = expired();
    repo.publish_snapshot();

    let mut trusted = repo.trusted_with_timestamp();
    assert_err!(
        trusted.update_snapshot(&repo.file("snapshot.json")),
        Error::Expired { role, .. } if role == "snapshot"
    );
    assert!(trusted.snapshot().is_none());

    assert_err!(repo.client().refresh(), Error::Expired { role, .. } if role == "snapshot");
}

/// 5.5.7: "The client MUST write the file to non-volatile storage as
/// FILENAME.EXT (e.g. snapshot.json)."
#[test]
fn a_new_snapshot_is_persisted() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(
        client.stored("snapshot.json"),
        Some(repo.file("snapshot.json"))
    );

    repo.publish_snapshot();
    client.refresh().unwrap();
    assert_eq!(
        client.stored("snapshot.json"),
        Some(repo.file("snapshot.json"))
    );
}

/// The snapshot persisted by an earlier update is trusted without being
/// downloaded again as long as the timestamp lists its version (and it has
/// not expired).
#[test]
fn a_current_trusted_snapshot_is_not_downloaded_again() {
    let repo = TestRepo::new();
    let mut trusted = repo.trusted_with_timestamp();
    let current = trusted
        .load_cached_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    assert!(current);
    trusted.update_targets(&repo.file("targets.json")).unwrap();

    let mut client = repo.client();
    client.refresh().unwrap();
    repo.requests();
    client.refresh().unwrap();
    assert_eq!(repo.requests(), ["2.root.json", "timestamp.json"]);
}

/// 5.5.6: a trusted snapshot that has expired is not used, even while the
/// timestamp still lists its version: the update fails as it would with a
/// downloaded one (a freeze attack).
#[test]
fn an_expired_trusted_snapshot_is_not_used() {
    let mut repo = TestRepo::new();
    repo.snapshot.expires = now() + SignedDuration::from_hours(1);
    repo.publish_snapshot();
    let mut client = repo.client();
    client.refresh().unwrap();

    // The timestamp is renewed, but still lists the same snapshot.
    repo.publish_timestamp();
    let later = now() + SignedDuration::from_hours(2);
    let mut trusted = TrustedMetadata::<Json>::new(&repo.file("root.json"), later).unwrap();
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    let current = trusted
        .load_cached_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    assert!(!current, "an expired snapshot is not current");
    assert_err!(
        trusted.update_targets(&repo.file("targets.json")),
        Error::Expired { role, .. } if role == "snapshot"
    );

    client.time = later;
    assert_err!(client.refresh(), Error::Expired { role, .. } if role == "snapshot");
}

/// 5.5.3: signatures are checked with the keys of the newest root, so a
/// trusted snapshot signed with a key that has since been rotated out is
/// not used.
#[test]
fn a_trusted_snapshot_signed_with_a_rotated_out_key_is_not_used() {
    let mut repo = TestRepo::new();
    let signed_with_old_key = repo.file("snapshot.json");
    repo.rotate_key(RoleType::Snapshot);
    repo.publish_root();
    repo.publish_snapshot();

    let mut trusted = repo.trusted_with_timestamp();
    assert_err!(
        trusted.load_cached_snapshot(&signed_with_old_key),
        Error::SignatureThreshold { role, .. } if role == "snapshot"
    );
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
}

/// An outdated trusted snapshot is the baseline of the rollback checks of
/// 5.5.5, but targets metadata cannot be checked against it.
#[test]
fn an_outdated_trusted_snapshot_is_only_a_rollback_baseline() {
    let mut repo = TestRepo::new();
    let version_1 = repo.file("snapshot.json");
    repo.publish_snapshot();

    let mut trusted = repo.trusted_with_timestamp();
    assert!(!trusted.load_cached_snapshot(&version_1).unwrap());
    assert_err!(
        trusted.update_targets(&repo.file("targets.json")),
        Error::VersionMismatch { role, expected: 2, actual: 1 } if role == "snapshot"
    );
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    trusted.update_targets(&repo.file("targets.json")).unwrap();
}
