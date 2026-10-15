//! 5.3 Update the root role.
//!
//! The client downloads every root version after the one it trusts, as
//! `VERSION.root.json`, until there is none. Each must be signed by a
//! threshold of the root keys of the version before it and of its own root
//! keys (see also 6.1), and is persisted as soon as it is verified.

use std::assert_matches;

use rftuf::crypto::Signer;
use rftuf::metadata::{MetaFile, RoleKeys, RoleType};
use rftuf::store::MetadataStore;
use rftuf::{Error, UpdaterConfig};

use crate::support::keys::{key, key_id};
use crate::support::{TestRepo, expired, far_future};

/// 5.3.1, 5.3.3: the client downloads version N+1 of root metadata, as
/// `N+1.root.json`, until it is not found, so it follows every key rotation
/// since the root it trusts.
#[test]
fn downloads_every_newer_root_version() {
    let mut repo = TestRepo::new();
    for _ in 0..3 {
        repo.rotate_key(RoleType::Root);
        repo.publish_root();
    }
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.root_version(), 4);
    assert_eq!(
        repo.requests()[..4],
        ["2.root.json", "3.root.json", "4.root.json", "5.root.json"]
    );
}

/// 5.3.3: root metadata is downloaded "up to some W number of bytes (because
/// the size is unknown)": `UpdaterConfig::root_max_length`.
#[test]
fn root_downloads_are_limited_to_root_max_length() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    let length = repo.file("2.root.json").len() as u64;

    let mut config = UpdaterConfig::default();
    config.root_max_length = length - 1;
    assert_matches!(
        repo.client_with(config.clone()).refresh(),
        Err(Error::TooLarge { name, max }) if name == "2.root.json" && max == length - 1
    );
    config.root_max_length = length;
    repo.client_with(config).refresh().unwrap();
}

/// 5.3.3: the client stops "if ... we have downloaded more than Y number of
/// root metadata files" (`UpdaterConfig::max_root_rotations`) and goes on
/// with the root it has reached. The next update continues from there.
#[test]
fn downloads_at_most_max_root_rotations_root_versions_per_update() {
    let mut repo = TestRepo::new();
    for _ in 0..3 {
        repo.publish_root();
    }
    let mut config = UpdaterConfig::default();
    config.max_root_rotations = 2;
    let mut client = repo.client_with(config);
    assert_eq!(client.updater.config().max_root_rotations, 2);

    client.refresh().unwrap();
    assert_eq!(client.root_version(), 3);
    client.refresh().unwrap();
    assert_eq!(client.root_version(), 4);
}

/// 5.3.3: the chain of root versions ends where `N+1.root.json` "is not
/// available". rftuf only takes a "not found" response to mean that: any
/// other download failure aborts the update, so that a network error
/// cannot make the client skip a root update.
#[test]
fn a_failed_root_download_aborts_the_update() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    repo.transport.fail("2.root.json");
    let mut client = repo.client();
    assert_matches!(
        client.refresh(),
        Err(Error::Transport { name, source })
            if name == "2.root.json" && source.to_string() == "simulated network failure"
    );
    assert_eq!(client.root_version(), 1);
}

/// The chain of root versions also ends at the largest version number, as
/// there can be no version after it.
#[test]
fn the_chain_of_root_versions_ends_at_the_largest_version_number() {
    let mut repo = TestRepo::new();
    repo.root.version = u64::MAX - 1;
    repo.publish_root();
    let client = repo.client();
    client
        .store
        .store("root.json", &repo.file("root.json"))
        .unwrap();
    let mut client = client.restart();
    assert_eq!(client.root_version(), u64::MAX);

    repo.requests();
    client.refresh().unwrap();
    assert_eq!(repo.requests()[0], "timestamp.json");
}

/// 5.3.4: version N+1 "MUST have been signed by: (1) a THRESHOLD of keys
/// specified in the trusted root metadata file (version N), and (2) a
/// THRESHOLD of keys specified in the new root metadata file being
/// validated (version N+1)".
#[test]
fn new_root_must_be_signed_by_the_trusted_and_its_own_root_keys() {
    let mut repo = TestRepo::new();
    let old_key = repo.signers["root"][0].clone();
    let new_key = repo.rotate_key(RoleType::Root);
    let mut next = repo.root.clone();
    next.version = 2;
    let mut trusted = repo.trusted();

    let only_new = TestRepo::sign_with(&next, &[&new_key]);
    assert_matches!(
        trusted.update_root(&only_new),
        Err(Error::SignatureThreshold { role, valid: 0, threshold: 1 }) if role == "root"
    );
    let only_old = TestRepo::sign_with(&next, &[&old_key]);
    assert_matches!(
        trusted.update_root(&only_old),
        Err(Error::SignatureThreshold { role, valid: 0, threshold: 1 }) if role == "root"
    );
    assert_eq!(trusted.root().signed().version, 1);

    let both = TestRepo::sign_with(&next, &[&old_key, &new_key]);
    trusted.update_root(&both).unwrap();
    assert_eq!(trusted.root().signed().version, 2);
}

/// 6.1's example of 5.3.4: "if there is a 1.root.json that has threshold 2
/// and a 2.root.json that has threshold 3, 2.root.json MUST be signed by at
/// least 2 keys defined in 1.root.json and at least 3 keys defined in
/// 2.root.json."
#[test]
fn root_rotation_example_of_the_specification() {
    let repo = TestRepo::builder().keys(RoleType::Root, 2, 2).build();
    let old = repo.signers["root"].clone();
    let new = [key("new root 1"), key("new root 2"), key("new root 3")];
    let mut next = repo.root.clone();
    next.version = 2;
    for key in &old {
        next.keys.remove(&key_id(key));
    }
    next.roles.root = RoleKeys::new(Vec::new(), 3);
    for key in &new {
        next.add_key(RoleType::Root, key_id(key), key.public_key().clone());
    }
    let mut trusted = repo.trusted();

    let one_old_three_new = TestRepo::sign_with(&next, &[&old[0], &new[0], &new[1], &new[2]]);
    assert_matches!(
        trusted.update_root(&one_old_three_new),
        Err(Error::SignatureThreshold {
            valid: 1,
            threshold: 2,
            ..
        })
    );
    let two_old_two_new = TestRepo::sign_with(&next, &[&old[0], &old[1], &new[0], &new[1]]);
    assert_matches!(
        trusted.update_root(&two_old_two_new),
        Err(Error::SignatureThreshold {
            valid: 2,
            threshold: 3,
            ..
        })
    );
    let two_old_three_new =
        TestRepo::sign_with(&next, &[&old[0], &old[1], &new[0], &new[1], &new[2]]);
    trusted.update_root(&two_old_three_new).unwrap();
}

/// 5.3.4: "Even if a KEYID is listed more than once in the "signatures" list
/// a client MUST NOT count more than one verified SIGNATURE from that KEYID
/// towards the THRESHOLD." rftuf rejects such metadata outright (4.2.1:
/// "multiple signatures with the same keyid are not allowed"); see also
/// `metadata::signatures` for keys listed under several key IDs.
#[test]
fn a_root_key_cannot_sign_twice() {
    let repo = TestRepo::builder().keys(RoleType::Root, 2, 2).build();
    let mut next = repo.root.clone();
    next.version = 2;
    let signed_once = TestRepo::sign_with(&next, &[&repo.signers["root"][0]]);
    let mut document: serde_json::Value = serde_json::from_slice(&signed_once).unwrap();
    let signature = document["signatures"][0].clone();
    document["signatures"]
        .as_array_mut()
        .unwrap()
        .push(signature);

    let mut trusted = repo.trusted();
    let signed_twice = serde_json::to_vec(&document).unwrap();
    assert_matches!(
        trusted.update_root(&signed_twice),
        Err(Error::InvalidMetadata(reason)) if reason.contains("multiple signatures")
    );
}

/// 5.3.4: "If version N+1 is not signed as required, discard it, abort the
/// update cycle, and report the signature failure. On the next update
/// cycle, begin at step 5.3 and version N of the root metadata file."
#[test]
fn a_root_that_is_not_signed_as_required_is_discarded() {
    let mut repo = TestRepo::new();
    let new_key = repo.rotate_key(RoleType::Root);
    let mut next = repo.root.clone();
    next.version = 2;
    let only_new = TestRepo::sign_with(&next, &[&new_key]);
    repo.write("2.root.json", only_new);

    let mut client = repo.client();
    assert_matches!(
        client.refresh(),
        Err(Error::SignatureThreshold { role, .. }) if role == "root"
    );
    assert_eq!(client.root_version(), 1);
    assert_eq!(client.stored("root.json"), Some(repo.initial_root()));
    assert!(client.updater.trusted().is_none());

    repo.requests();
    assert_matches!(client.refresh(), Err(Error::SignatureThreshold { .. }));
    assert_eq!(repo.requests(), ["2.root.json"]);
}

/// 5.3.5: "The version number of the new root metadata (version N+1) MUST be
/// exactly the version in the trusted root metadata (version N) incremented
/// by one ... If the version of the new root metadata file is not N+1,
/// discard it, abort the update cycle, and report the rollback attack."
#[test]
fn new_root_version_must_be_exactly_one_more() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    repo.publish_root();
    let mut trusted = repo.trusted();
    assert_matches!(
        trusted.update_root(&repo.file("3.root.json")),
        Err(Error::VersionMismatch { role, expected: 2, actual: 3 }) if role == "root"
    );
    assert_matches!(
        trusted.update_root(&repo.file("1.root.json")),
        Err(Error::VersionMismatch { role, expected: 2, actual: 1 }) if role == "root"
    );
    trusted.update_root(&repo.file("2.root.json")).unwrap();
    trusted.update_root(&repo.file("3.root.json")).unwrap();

    // What counts is the version in the file, not its name.
    let mut repo = TestRepo::new();
    let mut version_3 = repo.root.clone();
    version_3.version = 3;
    let version_3 = repo.sign("root", &version_3);
    repo.write("2.root.json", version_3);
    assert_matches!(
        repo.client().refresh(),
        Err(Error::VersionMismatch { role, expected: 2, actual: 3 }) if role == "root"
    );
}

/// 5.3.6: "Note that the expiration of the new (intermediate) root metadata
/// file does not matter yet": only the final root must be unexpired
/// (5.3.10).
#[test]
fn intermediate_roots_may_have_expired() {
    let mut repo = TestRepo::new();
    repo.root.expires = expired();
    repo.publish_root();
    repo.root.expires = far_future();
    repo.publish_root();

    let mut trusted = repo.trusted();
    trusted.update_root(&repo.file("2.root.json")).unwrap();
    trusted.update_root(&repo.file("3.root.json")).unwrap();
    trusted
        .update_timestamp(&repo.file("timestamp.json"))
        .unwrap();

    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.root_version(), 3);
}

/// 5.3.7, 5.3.8: each new root becomes the trusted root, and is persisted as
/// `root.json`, as soon as it is verified, so a later failure does not undo
/// it.
#[test]
fn each_verified_root_is_trusted_and_persisted() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    let mut version_3 = repo.root.clone();
    version_3.version = 3;
    let not_signed_by_root = TestRepo::sign_with(&version_3, &[&repo.signers["timestamp"][0]]);
    repo.write("3.root.json", not_signed_by_root);

    let mut client = repo.client();
    assert_matches!(
        client.refresh(),
        Err(Error::SignatureThreshold { role, .. }) if role == "root"
    );
    assert_eq!(client.root_version(), 2);
    assert_eq!(client.stored("root.json"), Some(repo.file("2.root.json")));
}

/// 5.3.10: "The expiration timestamp in the trusted root metadata file MUST
/// be higher than the fixed update start time. If the trusted root metadata
/// file has expired, abort the update cycle, report the potential freeze
/// attack."
#[test]
fn rejects_an_expired_final_root() {
    let mut repo = TestRepo::new();
    repo.root.expires = expired();
    repo.publish_root();

    let mut trusted = repo.trusted();
    trusted.update_root(&repo.file("2.root.json")).unwrap();
    assert_matches!(
        trusted.update_timestamp(&repo.file("timestamp.json")),
        Err(Error::Expired { role, .. }) if role == "root"
    );
    assert!(trusted.timestamp().is_none());

    assert_matches!(repo.client().refresh(), Err(Error::Expired { role, .. }) if role == "root");
}

/// 5.3.11: "If the timestamp and / or snapshot keys have been rotated, then
/// delete the trusted timestamp and snapshot metadata files."
#[test]
fn rotating_timestamp_or_snapshot_keys_deletes_their_trusted_metadata() {
    for role in [RoleType::Timestamp, RoleType::Snapshot] {
        let mut repo = TestRepo::new();
        let mut client = repo.client();
        client.refresh().unwrap();

        repo.rotate_key(role);
        repo.publish_root();
        // End the update right after it has updated root.
        repo.remove("timestamp.json");
        assert_matches!(
            client.refresh(),
            Err(Error::MetadataNotFound(name)) if name == "timestamp.json"
        );

        assert_eq!(client.stored("root.json"), Some(repo.file("2.root.json")));
        assert_eq!(client.stored("timestamp.json"), None, "{role}");
        assert_eq!(client.stored("snapshot.json"), None, "{role}");
        assert!(client.stored("targets.json").is_some(), "{role}");
    }
}

/// 5.3.11 also holds when the update fails after a rotation: the next update
/// starts from the rotated root, and would not see the rotation again.
#[test]
fn rotating_timestamp_keys_deletes_their_trusted_metadata_even_if_the_update_fails() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();

    repo.rotate_key(RoleType::Timestamp);
    repo.publish_root();
    repo.write("3.root.json", b"not root metadata".to_vec());
    assert_matches!(client.refresh(), Err(Error::Decode(_)));

    assert_eq!(client.stored("root.json"), Some(repo.file("2.root.json")));
    assert_eq!(client.stored("timestamp.json"), None);
    assert_eq!(client.stored("snapshot.json"), None);
}

/// 5.3.11 applies to the root versions an update downloads, not to those a
/// restarted client checks again from local storage: the timestamp metadata
/// trusted since the rotation remains the baseline for rollback checks.
#[test]
fn persisted_root_versions_do_not_delete_the_trusted_timestamp_again() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    repo.rotate_key(RoleType::Timestamp);
    repo.publish_root();
    repo.timestamp.version = 9;
    repo.publish_timestamp();
    client.refresh().unwrap();
    assert_eq!(client.trusted().timestamp().unwrap().signed().version, 10);

    repo.timestamp.version = 1;
    repo.publish_timestamp();
    let mut restarted = client.restart_with(repo.initial_root());
    assert_matches!(
        restarted.refresh(),
        Err(Error::Rollback { role, trusted: 10, new: 2 }) if role == "timestamp"
    );
}

/// 5.3.11: when other keys are rotated, the trusted timestamp and snapshot
/// metadata are kept, and what has not changed is not downloaded again.
#[test]
fn rotating_other_keys_keeps_the_trusted_timestamp_and_snapshot() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();

    repo.rotate_key(RoleType::Root);
    repo.publish_root();
    repo.requests();
    client.refresh().unwrap();
    assert_eq!(
        repo.requests(),
        ["2.root.json", "3.root.json", "timestamp.json"]
    );
}

/// 5.3.11 is "done in order to recover from fast-forward attacks". An
/// attacker with the (online) timestamp key publishes a timestamp with a
/// huge version. Clients trust it, and take the repository's next timestamp
/// for a rollback attack until the timestamp key is rotated.
#[test]
fn recovers_from_a_fast_forward_attack_on_timestamp() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();

    repo.timestamp.version = 999;
    repo.publish_timestamp();
    client.refresh().unwrap();

    repo.timestamp.version = 1;
    repo.publish_timestamp();
    assert_matches!(
        client.refresh(),
        Err(Error::Rollback { role, trusted: 1000, new: 2 }) if role == "timestamp"
    );

    repo.rotate_key(RoleType::Timestamp);
    repo.publish_root();
    repo.publish_timestamp();
    client.refresh().unwrap();
    assert_eq!(client.trusted().timestamp().unwrap().signed().version, 3);
    assert_eq!(
        client.stored("timestamp.json"),
        Some(repo.file("timestamp.json"))
    );
}

/// 5.3.11: recovery from a fast-forward attack on snapshot metadata, by an
/// attacker with the timestamp and snapshot keys.
#[test]
fn recovers_from_a_fast_forward_attack_on_snapshot() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();

    repo.snapshot.version = 999;
    repo.publish_snapshot();
    client.refresh().unwrap();

    repo.snapshot.version = 1;
    repo.publish_snapshot();
    assert_matches!(
        client.refresh(),
        Err(Error::Rollback { role, trusted: 1000, new: 2 }) if role == "snapshot"
    );

    repo.rotate_key(RoleType::Snapshot);
    repo.publish_root();
    repo.publish_snapshot();
    client.refresh().unwrap();
    assert_eq!(client.trusted().snapshot().unwrap().signed().version, 3);
}

/// 5.3.11: recovery from a fast-forward attack on targets metadata, by an
/// attacker with the snapshot key who lists a huge targets version in
/// snapshot metadata.
#[test]
fn recovers_from_a_fast_forward_attack_on_targets() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();

    repo.snapshot
        .meta
        .insert("targets.json".to_owned(), MetaFile::new(999));
    repo.publish_snapshot();
    assert_matches!(
        client.refresh(),
        Err(Error::VersionMismatch { role, expected: 999, actual: 1 }) if role == "targets"
    );

    repo.add_target("targets", "file", b"data");
    repo.commit();
    assert_matches!(
        client.refresh(),
        Err(Error::Rollback { role, trusted: 999, new: 2 }) if role == "targets.json"
    );

    repo.rotate_key(RoleType::Snapshot);
    repo.publish_root();
    repo.publish_snapshot();
    client.refresh().unwrap();
    assert_eq!(client.find("file").as_deref(), Some("targets"));
}

/// 5.3.12: "Set whether consistent snapshots are used as per the trusted root
/// metadata file", which is the newest root: a repository can switch to
/// consistent snapshots in a new root version, and clients follow in the
/// same update.
#[test]
fn consistent_snapshots_are_used_as_the_newest_root_says() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();

    repo.root.consistent_snapshot = Some(true);
    repo.publish_root();
    repo.add_target("targets", "file", b"data");
    repo.commit();
    repo.requests();
    client.refresh().unwrap();
    assert_eq!(
        repo.requests(),
        [
            "2.root.json",
            "3.root.json",
            "timestamp.json",
            "2.snapshot.json",
            "2.targets.json"
        ]
    );
}
