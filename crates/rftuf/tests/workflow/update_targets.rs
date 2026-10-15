//! 5.6.1 to 5.6.6 Update the targets role.
//!
//! Targets metadata must be the version the trusted snapshot lists (and match
//! its hashes, if listed), be signed by the keys trusted for the role, and
//! not have expired. The same checks apply to the metadata of delegated
//! roles, which the target search (5.6.7) loads, except that their keys are
//! those their delegating role lists (3.1.2.1: "Delegated target roles are
//! authorized by the keys listed in the directly delegating target role").

use std::assert_matches;

use jiff::SignedDuration;
use rftuf::metadata::RoleType;
use rftuf::{Error, UpdaterConfig};

use crate::support::{Delegation, TestRepo, expired};

/// A repository where the top-level targets role delegates to "a".
fn delegating_to_a(repo: TestRepo) -> TestRepo {
    let mut repo = repo;
    repo.delegate("targets", Delegation::to("a").paths(&["*"]).keys(2, 2));
    repo.commit();
    repo
}

/// 5.6.1: targets metadata is downloaded "up to either the number of bytes
/// specified in the snapshot metadata file, or some Z number of bytes": the
/// listed length takes precedence over the configured maximum.
#[test]
fn targets_downloads_are_limited_to_the_length_listed_in_snapshot() {
    let mut repo = TestRepo::builder().meta_lengths().build();
    let length = repo.snapshot.meta["targets.json"].length.unwrap();
    // Trailing whitespace changes neither the payload nor its signature.
    let mut padded = repo.file("targets.json");
    padded.extend_from_slice(&[b' '; 100]);
    repo.write("targets.json", padded);

    let mut config = UpdaterConfig::default();
    config.targets_max_length = length + 10;
    assert_matches!(
        repo.client_with(config).refresh(),
        Err(Error::TooLarge { name, max }) if name == "targets.json" && max == length
    );
}

/// 5.6.1: when snapshot metadata lists no length, targets metadata is
/// downloaded up to `UpdaterConfig::targets_max_length` bytes.
#[test]
fn targets_downloads_are_limited_to_targets_max_length() {
    let repo = TestRepo::new();
    let length = repo.file("targets.json").len() as u64;

    let mut config = UpdaterConfig::default();
    config.targets_max_length = length - 1;
    assert_matches!(
        repo.client_with(config.clone()).refresh(),
        Err(Error::TooLarge { name, max }) if name == "targets.json" && max == length - 1
    );
    config.targets_max_length = length;
    repo.client_with(config).refresh().unwrap();
}

/// 5.6.2: "The hashes of the new targets metadata file MUST match the hashes,
/// if any, listed in the trusted snapshot metadata. This is done, in part,
/// to prevent a mix-and-match attack".
#[test]
fn targets_must_match_the_hashes_listed_in_snapshot() {
    let mut repo = TestRepo::builder().meta_hashes().build();
    repo.add_target("targets", "file", b"data");
    repo.commit();
    let mut trusted = repo.trusted_with_snapshot();

    let mut other = repo.targets["targets"].clone();
    other.targets.clear();
    assert_matches!(
        trusted.update_targets(&repo.sign("targets", &other)),
        Err(Error::HashMismatch { name, .. }) if name == "targets.json"
    );
    trusted.update_targets(&repo.file("targets.json")).unwrap();
}

/// 5.6.3: "The new targets metadata file MUST have been signed by a
/// THRESHOLD of keys specified in the trusted root metadata file."
#[test]
fn targets_must_be_signed_by_a_threshold_of_targets_keys() {
    let repo = TestRepo::builder().keys(RoleType::Targets, 2, 2).build();
    let keys = &repo.signers["targets"];
    let mut trusted = repo.trusted_with_snapshot();
    let payload = &repo.targets["targets"];

    let by_snapshot_key = repo.sign("snapshot", payload);
    assert_matches!(
        trusted.update_targets(&by_snapshot_key),
        Err(Error::SignatureThreshold { role, valid: 0, threshold: 2 }) if role == "targets"
    );
    let by_one_key = TestRepo::sign_with(payload, &[&keys[0]]);
    assert_matches!(
        trusted.update_targets(&by_one_key),
        Err(Error::SignatureThreshold { role, valid: 1, threshold: 2 }) if role == "targets"
    );
    trusted.update_targets(&repo.file("targets.json")).unwrap();
}

/// 5.6.4: "The version number of the new targets metadata file MUST match the
/// version number listed in the trusted snapshot metadata."
#[test]
fn targets_version_must_match_snapshot() {
    let repo = TestRepo::new();
    let mut trusted = repo.trusted_with_snapshot();
    let mut newer = repo.targets["targets"].clone();
    newer.version = 5;
    assert_matches!(
        trusted.update_targets(&repo.sign("targets", &newer)),
        Err(Error::VersionMismatch { role, expected: 1, actual: 5 }) if role == "targets"
    );
}

/// 5.6.5: "If the new targets metadata file is expired, discard it, abort the
/// update cycle, and report the potential freeze attack."
#[test]
fn rejects_expired_targets() {
    let mut repo = TestRepo::new();
    repo.targets_mut("targets").expires = expired();
    repo.commit();

    let mut trusted = repo.trusted_with_snapshot();
    assert_matches!(
        trusted.update_targets(&repo.file("targets.json")),
        Err(Error::Expired { role, .. }) if role == "targets"
    );
    assert!(trusted.targets().is_none());

    assert_matches!(repo.client().refresh(), Err(Error::Expired { role, .. }) if role == "targets");
}

/// 5.6.6: "The client MUST write the file to non-volatile storage as
/// FILENAME.EXT (e.g. targets.json)."
#[test]
fn new_targets_metadata_is_persisted() {
    let mut repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(
        client.stored("targets.json"),
        Some(repo.file("targets.json"))
    );

    repo.add_target("targets", "file", b"data");
    repo.commit();
    client.refresh().unwrap();
    assert_eq!(
        client.stored("targets.json"),
        Some(repo.file("targets.json"))
    );
}

/// 4.4: snapshot metadata "MUST list the version numbers of the top-level
/// targets metadata and all delegated targets metadata", and targets
/// metadata is checked against that entry (5.6.2, 5.6.4), so metadata that
/// snapshot does not list cannot be trusted.
#[test]
fn targets_metadata_must_be_listed_in_snapshot() {
    let mut repo = TestRepo::new();
    repo.snapshot.meta.remove("targets.json");
    repo.publish_snapshot();

    let mut trusted = repo.trusted_with_snapshot();
    assert_matches!(
        trusted.update_targets(&repo.file("targets.json")),
        Err(Error::NotInSnapshot(name)) if name == "targets.json"
    );
    assert_matches!(
        repo.client().refresh(),
        Err(Error::NotInSnapshot(name)) if name == "targets.json"
    );
}

/// 5.6.3 for delegated roles: delegated targets metadata must be signed by a
/// threshold of the keys the delegating role lists for it.
#[test]
fn delegated_targets_must_be_signed_by_a_threshold_of_the_delegated_keys() {
    let repo = delegating_to_a(TestRepo::new());
    let keys = &repo.signers["a"];
    let payload = &repo.targets["a"];
    let mut trusted = repo.trusted_with_targets();

    let by_targets_key = repo.sign("targets", payload);
    assert_matches!(
        trusted.update_delegated_targets(&by_targets_key, "a", "targets"),
        Err(Error::SignatureThreshold { role, valid: 0, threshold: 2 }) if role == "a"
    );
    let by_one_key = TestRepo::sign_with(payload, &[&keys[0]]);
    assert_matches!(
        trusted.update_delegated_targets(&by_one_key, "a", "targets"),
        Err(Error::SignatureThreshold { role, valid: 1, threshold: 2 }) if role == "a"
    );
    trusted
        .update_delegated_targets(&repo.file("a.json"), "a", "targets")
        .unwrap();
    assert!(trusted.targets_role("a").is_some());
}

/// 3.1.2.1: a role's metadata can only be trusted through a delegation to
/// it: root delegates to the top-level targets role only, and a targets
/// role only to the roles it lists.
#[test]
fn delegated_targets_can_only_be_trusted_through_a_delegation() {
    let repo = delegating_to_a(TestRepo::new());
    let mut trusted = repo.trusted_with_targets();
    let a = repo.file("a.json");

    assert_matches!(
        trusted.update_delegated_targets(&a, "a", "root"),
        Err(Error::UnknownDelegation(role)) if role == "a"
    );
    trusted
        .update_delegated_targets(&a, "a", "targets")
        .unwrap();
    // "a" delegates neither to itself nor to the top-level targets role.
    assert_matches!(
        trusted.update_delegated_targets(&a, "a", "a"),
        Err(Error::UnknownDelegation(role)) if role == "a"
    );
    assert_matches!(
        trusted.delegated_targets("a", "a"),
        Err(Error::UnknownDelegation(role)) if role == "a"
    );
    assert_matches!(
        trusted.update_delegated_targets(&repo.file("targets.json"), "targets", "a"),
        Err(Error::UnknownDelegation(role)) if role == "targets"
    );
}

/// 3.1.2.1 for a role that several roles delegate to, with different keys:
/// its metadata must satisfy each delegation it is used through, not only
/// the one it was loaded through, or one delegation would lend its trust to
/// another.
#[test]
fn a_role_must_satisfy_each_delegation_it_is_used_through() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["a/*"]));
    repo.delegate("targets", Delegation::to("b").paths(&["b/*"]));
    repo.delegate("a", Delegation::to("shared").paths(&["a/*"]));
    // "b" delegates to "shared" too, but to a key that does not sign it.
    repo.delegate("b", Delegation::to("shared").paths(&["b/*"]));
    repo.commit();
    let mut trusted = repo.trusted_with_targets();
    trusted
        .update_delegated_targets(&repo.file("a.json"), "a", "targets")
        .unwrap();
    trusted
        .update_delegated_targets(&repo.file("b.json"), "b", "targets")
        .unwrap();

    assert!(trusted.delegated_targets("shared", "a").unwrap().is_none());
    trusted
        .update_delegated_targets(&repo.file("shared.json"), "shared", "a")
        .unwrap();
    assert!(trusted.delegated_targets("shared", "a").unwrap().is_some());
    assert_matches!(
        trusted.delegated_targets("shared", "b"),
        Err(Error::SignatureThreshold { role, valid: 0, threshold: 1 }) if role == "shared"
    );
    assert_matches!(
        trusted.update_delegated_targets(&repo.file("shared.json"), "shared", "b"),
        Err(Error::SignatureThreshold { role, valid: 0, threshold: 1 }) if role == "shared"
    );
}

/// 5.6.2 for delegated roles: delegated targets metadata must match the
/// hashes the trusted snapshot lists for it.
#[test]
fn delegated_targets_must_match_the_hashes_listed_in_snapshot() {
    let repo = delegating_to_a(TestRepo::builder().meta_hashes().build());
    let mut trusted = repo.trusted_with_targets();
    let mut other = repo.targets["a"].clone();
    other.expires += SignedDuration::from_hours(24);

    assert_matches!(
        trusted.update_delegated_targets(&repo.sign("a", &other), "a", "targets"),
        Err(Error::HashMismatch { name, .. }) if name == "a.json"
    );
}

/// 5.6.4 for delegated roles: delegated targets metadata must have the
/// version the trusted snapshot lists for it.
#[test]
fn delegated_targets_version_must_match_snapshot() {
    let repo = delegating_to_a(TestRepo::new());
    let mut trusted = repo.trusted_with_targets();
    let mut newer = repo.targets["a"].clone();
    newer.version += 1;

    assert_matches!(
        trusted.update_delegated_targets(&repo.sign("a", &newer), "a", "targets"),
        Err(Error::VersionMismatch { role, expected: 1, actual: 2 }) if role == "a"
    );
}

/// 5.6.5 for delegated roles: delegated targets metadata must not have
/// expired.
#[test]
fn rejects_expired_delegated_targets() {
    let mut repo = delegating_to_a(TestRepo::new());
    repo.targets_mut("a").expires = expired();
    repo.commit();
    let mut trusted = repo.trusted_with_targets();

    assert_matches!(
        trusted.update_delegated_targets(&repo.file("a.json"), "a", "targets"),
        Err(Error::Expired { role, .. }) if role == "a"
    );
}

/// 4.4 for delegated roles: snapshot metadata must list delegated targets
/// metadata too.
#[test]
fn delegated_targets_must_be_listed_in_snapshot() {
    let mut repo = delegating_to_a(TestRepo::new());
    repo.snapshot.meta.remove("a.json");
    repo.publish_snapshot();
    let mut trusted = repo.trusted_with_targets();

    assert_matches!(
        trusted.update_delegated_targets(&repo.file("a.json"), "a", "targets"),
        Err(Error::NotInSnapshot(name)) if name == "a.json"
    );
}

/// 3.1.2.1, 5.6.6: delegated targets metadata is persisted, under its role
/// name. Role names are percent-encoded in file names (as in the reference
/// implementation), so that a name such as `team/web` stays one file name.
#[test]
fn delegated_targets_metadata_is_persisted_under_its_encoded_role_name() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("team/web").paths(&["*"]));
    repo.add_target("team/web", "page", b"html");
    repo.commit();

    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.find("page").as_deref(), Some("team/web"));
    assert!(repo.requests().contains(&"team%2Fweb.json".to_owned()));
    assert_eq!(
        client.stored("team%2Fweb.json"),
        Some(repo.file("team%2Fweb.json"))
    );
}
