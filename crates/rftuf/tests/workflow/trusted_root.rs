//! 5.2 Load trusted root metadata.
//!
//! The client starts from root metadata it already trusts: the root shipped
//! with the application (`UpdaterBuilder::initial_root`), followed by the
//! newer root versions that earlier updates persisted (5.3.8), each signed
//! by the root keys of the one before it. Without a shipped root, it starts
//! from the root persisted last.

use std::assert_matches;
use std::sync::Arc;

use rftuf::crypto::Signer;
use rftuf::metadata::RoleType;
use rftuf::pouf::Json;
use rftuf::store::{MemoryStore, MetadataStore};
use rftuf::{Error, TrustedMetadata, Updater};

use crate::support::keys::{key, key_id};
use crate::support::{TestRepo, expired, far_future, now};

/// Builds an updater for `repo` from `initial_root` (if any) and `store`.
fn build(
    repo: &TestRepo,
    store: &Arc<MemoryStore>,
    initial_root: Option<Vec<u8>>,
) -> rftuf::Result<Updater<Arc<crate::support::RecordingTransport>, Arc<MemoryStore>>> {
    let builder = Updater::builder(repo.transport.clone(), store.clone());
    match initial_root {
        Some(root) => builder.initial_root(root).build(),
        None => builder.build(),
    }
}

/// 5.2: root metadata is trusted because it is shipped or persisted, but it
/// must still be signed by a threshold of the root keys it lists itself.
#[test]
fn trusted_root_must_be_signed_by_its_own_root_keys() {
    let repo = TestRepo::new();
    let signed_by_timestamp_key = TestRepo::sign_with(&repo.root, &[&repo.signers["timestamp"][0]]);

    assert_matches!(
        TrustedMetadata::<Json>::new(&signed_by_timestamp_key, now()),
        Err(Error::SignatureThreshold { role, valid: 0, threshold: 1 }) if role == "root"
    );
    let store = Arc::new(MemoryStore::new());
    assert_matches!(
        build(&repo, &store, Some(signed_by_timestamp_key)),
        Err(Error::SignatureThreshold { .. })
    );
}

/// 5.2: "Note that the expiration of the trusted root metadata file does not
/// matter, because we will attempt to update it in the next step."
#[test]
fn trusted_root_may_have_expired() {
    let mut repo = TestRepo::builder()
        .expires(RoleType::Root, expired())
        .build();
    TrustedMetadata::<Json>::new(&repo.initial_root(), now()).unwrap();

    repo.root.expires = far_future();
    repo.publish_root();
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.root_version(), 2);
}

/// 5.2: without a shipped root, the client needs a persisted one.
#[test]
fn an_updater_needs_a_shipped_or_persisted_root() {
    let repo = TestRepo::new();
    let empty = Arc::new(MemoryStore::new());
    assert_matches!(build(&repo, &empty, None), Err(Error::NoTrustedRoot));

    let store = Arc::new(MemoryStore::new());
    store.store("root.json", &repo.initial_root()).unwrap();
    let updater = build(&repo, &store, None).unwrap();
    assert_eq!(updater.root().signed().version, 1);
}

/// 5.2, 5.3.8: a client that has updated its root persisted the newer
/// versions, and starts from them rather than from the root it was shipped
/// with, without downloading them again.
#[test]
fn root_versions_persisted_by_earlier_updates_are_trusted() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    repo.publish_root();
    let mut client = repo.client();
    client.refresh().unwrap();

    let mut restarted = client.restart_with(repo.initial_root());
    assert_eq!(restarted.root_version(), 3);
    repo.requests();
    restarted.refresh().unwrap();
    assert_eq!(repo.requests(), ["4.root.json", "timestamp.json"]);
}

/// 5.2: the shipped root is the trust anchor. Root metadata in local storage
/// that does not descend from it, here that of another repository, is not
/// trusted, and is replaced.
#[test]
fn persisted_roots_that_do_not_descend_from_the_shipped_root_are_not_trusted() {
    let repo = TestRepo::new();
    let mut other = TestRepo::builder().name("other").build();
    other.publish_root();
    other.publish_root();
    let store = Arc::new(MemoryStore::new());
    for name in ["2.root.json", "3.root.json", "root.json"] {
        store.store(name, &other.file(name)).unwrap();
    }

    let updater = build(&repo, &store, Some(repo.initial_root())).unwrap();
    assert_eq!(updater.root().signed(), &repo.root);
    assert_eq!(store.load("root.json").unwrap(), Some(repo.initial_root()));
}

/// Recovery from the compromise of a threshold of root keys, by updating
/// the root out of band (2.1.1). An attacker with the root key of version 1
/// gets a client to accept a forged version 2. The repository publishes its
/// own version 2, with a new root key, and ships it with the application:
/// the restarted client trusts it rather than the forged root it persisted,
/// although both have the same version.
#[test]
fn a_shipped_root_replaces_a_persisted_root_forged_with_compromised_keys() {
    let mut repo = TestRepo::new();
    let attacker = key("attacker");
    let mut forged = repo.root.clone();
    forged.version = 2;
    forged.roles.root.keyids.clear();
    forged.add_key(
        RoleType::Root,
        key_id(&attacker),
        attacker.public_key().clone(),
    );
    let forged = TestRepo::sign_with(&forged, &[&repo.signers["root"][0], &attacker]);
    repo.write("2.root.json", forged.clone());
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.stored("root.json"), Some(forged));

    repo.rotate_key(RoleType::Root);
    repo.publish_root();
    let mut recovered = client.restart_with(repo.file("2.root.json"));
    assert_eq!(recovered.updater.root().signed(), &repo.root);
    assert_eq!(
        recovered.stored("root.json"),
        Some(repo.file("2.root.json"))
    );
    recovered.refresh().unwrap();
}

/// 5.2: an application shipped with a root newer than the persisted one (for
/// example after an upgrade) starts from the shipped root, and persists it.
#[test]
fn a_shipped_root_newer_than_the_persisted_one_is_trusted_and_persisted() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    repo.publish_root();
    let store = Arc::new(MemoryStore::new());
    store.store("root.json", &repo.initial_root()).unwrap();

    let updater = build(&repo, &store, Some(repo.file("3.root.json"))).unwrap();
    assert_eq!(updater.root().signed().version, 3);
    assert_eq!(
        store.load("root.json").unwrap(),
        Some(repo.file("3.root.json"))
    );
}

/// 5.2: a persisted root that cannot be loaded (corrupt, or not signed by
/// its own keys) is replaced by the shipped root. Without a shipped root,
/// the error is reported.
#[test]
fn an_invalid_persisted_root_is_replaced_by_the_shipped_one() {
    let repo = TestRepo::new();
    let not_self_signed = TestRepo::sign_with(&repo.root, &[&repo.signers["targets"][0]]);
    for invalid in [b"garbage".to_vec(), not_self_signed] {
        let store = Arc::new(MemoryStore::new());
        store.store("root.json", &invalid).unwrap();
        assert!(build(&repo, &store, None).is_err());

        let updater = build(&repo, &store, Some(repo.initial_root())).unwrap();
        assert_eq!(updater.root().signed().version, 1);
        assert_eq!(store.load("root.json").unwrap(), Some(repo.initial_root()));
    }
}
