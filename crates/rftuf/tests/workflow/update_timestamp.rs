//! 5.4 Update the timestamp role.
//!
//! Timestamp metadata is downloaded in every update; it tells the client
//! whether anything changed. It must be signed by the root's timestamp keys,
//! must not roll back the trusted timestamp, and must not have expired.

use std::assert_matches;

use jiff::SignedDuration;
use rftuf::metadata::{MetaFile, RoleType};
use rftuf::trusted::TimestampUpdate;
use rftuf::{Error, UpdaterConfig};

use crate::support::{TestRepo, expired, far_future};

/// 5.4.1: the timestamp is downloaded in every update, by the fixed name
/// `timestamp.json`, also with consistent snapshots (6.2.1: it "is the only
/// metadata file that may be requested without known version numbers").
#[test]
fn timestamp_is_always_downloaded_as_timestamp_json() {
    let repo = TestRepo::builder().consistent_snapshots().build();
    let mut client = repo.client();
    client.refresh().unwrap();
    repo.requests();

    client.refresh().unwrap();
    assert_eq!(repo.requests(), ["2.root.json", "timestamp.json"]);
}

/// 5.4.1: timestamp metadata is downloaded "up to X number of bytes (because
/// the size is unknown)": `UpdaterConfig::timestamp_max_length`.
#[test]
fn timestamp_downloads_are_limited_to_timestamp_max_length() {
    let repo = TestRepo::new();
    let length = repo.file("timestamp.json").len() as u64;

    let mut config = UpdaterConfig::default();
    config.timestamp_max_length = length - 1;
    assert_matches!(
        repo.client_with(config.clone()).refresh(),
        Err(Error::TooLarge { name, max }) if name == "timestamp.json" && max == length - 1
    );
    config.timestamp_max_length = length;
    repo.client_with(config).refresh().unwrap();
}

/// 5.4.2: "The new timestamp metadata file MUST have been signed by a
/// THRESHOLD of keys specified in the trusted root metadata file."
#[test]
fn timestamp_must_be_signed_by_a_threshold_of_timestamp_keys() {
    let repo = TestRepo::builder().keys(RoleType::Timestamp, 2, 2).build();
    let keys = &repo.signers["timestamp"];
    let mut trusted = repo.trusted();

    let by_snapshot_key = repo.sign("snapshot", &repo.timestamp);
    assert_matches!(
        trusted.update_timestamp(&by_snapshot_key),
        Err(Error::SignatureThreshold { role, valid: 0, threshold: 2 }) if role == "timestamp"
    );
    let by_one_key = TestRepo::sign_with(&repo.timestamp, &[&keys[0]]);
    assert_matches!(
        trusted.update_timestamp(&by_one_key),
        Err(Error::SignatureThreshold { role, valid: 1, threshold: 2 }) if role == "timestamp"
    );
    let by_both_keys = TestRepo::sign_with(&repo.timestamp, &[&keys[0], &keys[1]]);
    trusted.update_timestamp(&by_both_keys).unwrap();
}

/// 5.4.2: signatures are checked with the keys of the newest root, so
/// timestamp metadata signed with a key that has been rotated out is
/// rejected, whether it is downloaded or cached.
#[test]
fn timestamp_signed_with_a_rotated_out_key_is_rejected() {
    let mut repo = TestRepo::new();
    let signed_with_old_key = repo.file("timestamp.json");
    repo.rotate_key(RoleType::Timestamp);
    repo.publish_root();
    repo.publish_timestamp();

    let mut trusted = repo.trusted();
    trusted.update_root(&repo.file("2.root.json")).unwrap();
    assert_matches!(
        trusted.load_cached_timestamp(&signed_with_old_key),
        Err(Error::SignatureThreshold { role, .. }) if role == "timestamp"
    );
    assert_matches!(
        trusted.update_timestamp(&signed_with_old_key),
        Err(Error::SignatureThreshold { role, .. }) if role == "timestamp"
    );
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
}

/// 5.4.3.1: "If the new timestamp metadata version is less than the trusted
/// timestamp metadata version, discard it, abort the update cycle, and
/// report the potential rollback attack."
#[test]
fn rejects_a_timestamp_rollback() {
    let mut repo = TestRepo::new();
    let version_1 = repo.file("timestamp.json");
    repo.publish_timestamp();
    let version_2 = repo.file("timestamp.json");

    let mut trusted = repo.trusted();
    trusted.load_cached_timestamp(&version_2).unwrap();
    assert_matches!(
        trusted.update_timestamp(&version_1),
        Err(Error::Rollback { role, trusted: 2, new: 1 }) if role == "timestamp"
    );

    let mut client = repo.client();
    client.refresh().unwrap();
    repo.write("timestamp.json", version_1);
    assert_matches!(
        client.refresh(),
        Err(Error::Rollback { role, trusted: 2, new: 1 }) if role == "timestamp"
    );
    assert_eq!(client.stored("timestamp.json"), Some(version_2));
}

/// 5.4.3.1: the trusted timestamp is the baseline for rollback checks even
/// once it has expired.
#[test]
fn an_expired_trusted_timestamp_still_prevents_rollbacks() {
    let mut repo = TestRepo::new();
    let version_1 = repo.file("timestamp.json");
    repo.timestamp.expires = expired();
    repo.publish_timestamp();

    let mut trusted = repo.trusted();
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert_matches!(
        trusted.update_timestamp(&version_1),
        Err(Error::Rollback { role, trusted: 2, new: 1 }) if role == "timestamp"
    );
}

/// 5.4.3.1: if the versions are equal, "discard the new timestamp metadata
/// ... This is normal and it shouldn't raise any error." The trusted
/// timestamp stays trusted. Like the reference implementation, rftuf then
/// finishes the update with the trusted snapshot and targets metadata,
/// which cannot have changed either.
#[test]
fn a_timestamp_with_the_trusted_version_is_discarded_without_error() {
    let mut repo = TestRepo::new();
    let mut trusted = repo.trusted();
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    repo.timestamp.expires += SignedDuration::from_hours(24);
    let same_version = repo.sign("timestamp", &repo.timestamp);
    assert_eq!(
        trusted.update_timestamp(&same_version).unwrap(),
        TimestampUpdate::Unchanged
    );
    assert_eq!(trusted.timestamp().unwrap().signed().expires, far_future());

    let mut client = repo.client();
    client.refresh().unwrap();
    let persisted = client.stored("timestamp.json");
    repo.write("timestamp.json", same_version);
    client.refresh().unwrap();
    assert_eq!(client.stored("timestamp.json"), persisted);
}

/// 5.4.3.1, 5.4.4: a timestamp with the trusted version only leaves the
/// trusted timestamp in place if that has not expired.
#[test]
fn an_unchanged_timestamp_must_not_have_expired() {
    let mut repo = TestRepo::new();
    repo.timestamp.expires = expired();
    repo.publish_timestamp();

    let mut trusted = repo.trusted();
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert_matches!(
        trusted.update_timestamp(&repo.file("timestamp.json")),
        Err(Error::Expired { role, .. }) if role == "timestamp"
    );
}

/// 5.4.3.2: "The version number of the snapshot metadata file in the trusted
/// timestamp metadata file, if any, MUST be less than or equal to its
/// version number in the new timestamp metadata file."
#[test]
fn timestamp_must_not_roll_back_the_snapshot_version() {
    let mut repo = TestRepo::new();
    repo.publish_snapshot();
    let mut trusted = repo.trusted();
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();

    let mut next = repo.timestamp.clone();
    next.version += 1;
    next.meta
        .insert("snapshot.json".to_owned(), MetaFile::new(1));
    assert_matches!(
        trusted.update_timestamp(&repo.sign("timestamp", &next)),
        Err(Error::Rollback { role, trusted: 2, new: 1 }) if role == "snapshot"
    );

    next.meta
        .insert("snapshot.json".to_owned(), MetaFile::new(2));
    trusted
        .update_timestamp(&repo.sign("timestamp", &next))
        .unwrap();
}

/// 5.4.4: "If the new timestamp metadata file has expired, discard it, abort
/// the update cycle, and report the potential freeze attack."
#[test]
fn rejects_an_expired_timestamp() {
    let mut repo = TestRepo::new();
    repo.timestamp.expires = expired();
    repo.publish_timestamp();

    let mut trusted = repo.trusted();
    assert_matches!(
        trusted.update_timestamp(&repo.file("timestamp.json")),
        Err(Error::Expired { role, .. }) if role == "timestamp"
    );
    assert!(trusted.timestamp().is_none());

    let mut client = repo.client();
    assert_matches!(client.refresh(), Err(Error::Expired { role, .. }) if role == "timestamp");
    assert_eq!(client.stored("timestamp.json"), None);
}

/// 5.4.5: "The client MUST write the file to non-volatile storage as
/// FILENAME.EXT (e.g. timestamp.json)."
#[test]
fn a_new_timestamp_is_persisted() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(
        client.stored("timestamp.json"),
        Some(repo.file("timestamp.json"))
    );

    repo.publish_timestamp();
    client.refresh().unwrap();
    assert_eq!(
        client.stored("timestamp.json"),
        Some(repo.file("timestamp.json"))
    );
}
