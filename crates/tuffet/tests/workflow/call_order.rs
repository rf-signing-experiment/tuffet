//! The order of the client workflow, as `TrustedMetadata` enforces it.
//!
//! `TrustedMetadata` must be given metadata in the order of the workflow
//! (5.3 to 5.6): root versions, then timestamp, snapshot and targets
//! metadata. Calls made out of order fail with `Error::InvalidState`.

use std::assert_matches;

use tuffet::Error;
use tuffet::trusted::TimestampUpdate;

use crate::support::{Delegation, TestRepo, expired};

/// The workflow in order: each step trusts what the step before it trusted,
/// and tells what to download next.
#[test]
fn metadata_is_trusted_in_workflow_order() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["*"]));
    repo.add_target("a", "file", b"data");
    repo.commit();
    repo.publish_root();

    let mut trusted = repo.trusted();
    trusted.update_root(&repo.file("2.root.json")).unwrap();
    assert_eq!(
        trusted
            .update_timestamp(&repo.file("timestamp.json"))
            .unwrap(),
        TimestampUpdate::Updated
    );
    assert_eq!(trusted.snapshot_meta().unwrap().version, 2);
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    assert_eq!(trusted.targets_meta("targets").unwrap().version, 2);
    assert_eq!(trusted.targets_meta("a").unwrap().version, 1);
    trusted.update_targets(&repo.file("targets.json")).unwrap();
    trusted
        .update_delegated_targets(&repo.file("a.json"), "a", "targets")
        .unwrap();

    assert_eq!(trusted.root().signed().version, 2);
    assert_eq!(trusted.timestamp().unwrap().signed().version, 2);
    assert_eq!(trusted.snapshot().unwrap().signed().version, 2);
    assert_eq!(trusted.targets().unwrap().signed().version, 2);
    let a = trusted.targets_role("a").unwrap();
    assert!(a.signed().targets.contains_key("file"));
}

/// 5.3 comes before 5.4: once timestamp metadata has been checked against
/// the final root (5.3.10), root can no longer change.
#[test]
fn root_cannot_be_updated_once_timestamp_is_loaded() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    let mut trusted = repo.trusted();
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert_matches!(
        trusted.update_root(&repo.file("2.root.json")),
        Err(Error::InvalidState(_))
    );
    assert_eq!(trusted.root().signed().version, 1);
}

/// 5.4 comes before 5.5: snapshot metadata is checked against the trusted
/// timestamp.
#[test]
fn snapshot_needs_timestamp() {
    let repo = TestRepo::new();
    let mut trusted = repo.trusted();
    assert_matches!(
        trusted.update_snapshot(&repo.file("snapshot.json")),
        Err(Error::InvalidState(_))
    );
    assert_matches!(
        trusted.load_cached_snapshot(&repo.file("snapshot.json")),
        Err(Error::InvalidState(_))
    );
}

/// 5.5 comes before 5.6: targets metadata is checked against the trusted
/// snapshot.
#[test]
fn targets_need_snapshot() {
    let repo = TestRepo::new();
    let mut trusted = repo.trusted();
    assert_matches!(
        trusted.update_targets(&repo.file("targets.json")),
        Err(Error::InvalidState(_))
    );
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert_matches!(
        trusted.update_targets(&repo.file("targets.json")),
        Err(Error::InvalidState(_))
    );
}

/// Once snapshot metadata is checked against the timestamp, the timestamp
/// can no longer change; nor can snapshot once targets metadata is checked
/// against it.
#[test]
fn trusted_metadata_cannot_change_once_later_steps_rely_on_it() {
    let repo = TestRepo::new();
    let mut trusted = repo.trusted_with_snapshot();
    assert_matches!(
        trusted.update_timestamp(&repo.file("timestamp.json")),
        Err(Error::InvalidState(_))
    );
    trusted.update_targets(&repo.file("targets.json")).unwrap();
    assert_matches!(
        trusted.update_snapshot(&repo.file("snapshot.json")),
        Err(Error::InvalidState(_))
    );
}

/// Cached metadata is the baseline for newly downloaded metadata, so it
/// must be loaded first.
#[test]
fn cached_metadata_is_loaded_before_new_metadata() {
    let repo = TestRepo::new();
    let mut trusted = repo.trusted_with_timestamp();
    assert_matches!(
        trusted.load_cached_timestamp(&repo.file("timestamp.json")),
        Err(Error::InvalidState(_))
    );
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();
    assert_matches!(
        trusted.load_cached_snapshot(&repo.file("snapshot.json")),
        Err(Error::InvalidState(_))
    );
}

/// Cached metadata is a baseline for new metadata. A caller that does not
/// download a new timestamp can still use a cached one, but only while it
/// has not expired.
#[test]
fn a_cached_timestamp_is_only_used_while_it_has_not_expired() {
    let mut repo = TestRepo::new();
    let mut trusted = repo.trusted();
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    trusted
        .update_snapshot(&repo.file("snapshot.json"))
        .unwrap();

    repo.timestamp.expires = expired();
    repo.publish_timestamp();
    let mut trusted = repo.trusted();
    trusted
        .load_cached_timestamp(&repo.file("timestamp.json"))
        .unwrap();
    assert_matches!(
        trusted.load_cached_snapshot(&repo.file("snapshot.json")),
        Err(Error::Expired { role, .. }) if role == "timestamp"
    );
    assert_matches!(
        trusted.update_snapshot(&repo.file("snapshot.json")),
        Err(Error::Expired { role, .. }) if role == "timestamp"
    );
}

/// A delegated role's metadata is checked against the keys of its
/// delegating role, which must be trusted first.
#[test]
fn delegated_targets_need_their_delegating_role() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["*"]));
    repo.delegate("a", Delegation::to("b").paths(&["*"]));
    repo.commit();
    let mut trusted = repo.trusted_with_targets();

    assert_matches!(
        trusted.update_delegated_targets(&repo.file("b.json"), "b", "a"),
        Err(Error::InvalidState(_))
    );
    trusted
        .update_delegated_targets(&repo.file("a.json"), "a", "targets")
        .unwrap();
    trusted
        .update_delegated_targets(&repo.file("b.json"), "b", "a")
        .unwrap();
}
