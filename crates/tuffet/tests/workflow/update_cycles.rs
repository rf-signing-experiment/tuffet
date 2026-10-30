//! Updating again.
//!
//! The introduction of section 5: if a step fails, "the client should still
//! be able to update again in the future. Errors raised during the update
//! process should not leave clients in an unrecoverable state." Between
//! updates, the client relies on the metadata it persisted (5.3.8, 5.4.5,
//! 5.5.7, 5.6.6).

use std::assert_matches;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_executor::block_on;
use tuffet::metadata::RoleType;
use tuffet::store::{MemoryStore, MetadataStore};
use tuffet::{Error, Updater};

use crate::support::{Delegation, TestRepo, expired, far_future, now};

/// After a failed update the client trusts no metadata but root, and once
/// the repository is repaired, the next update succeeds.
#[test]
fn an_update_can_be_repeated_after_a_failure() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file", b"data");
    repo.timestamp.expires = expired();
    repo.commit();
    let mut client = repo.client();
    assert_matches!(client.refresh(), Err(Error::Expired { role, .. }) if role == "timestamp");
    assert!(client.updater.trusted().is_none());

    repo.timestamp.expires = far_future();
    repo.publish_timestamp();
    client.refresh().unwrap();
    assert_eq!(client.find("file").as_deref(), Some("targets"));
}

/// A failed update also ends the trust in what earlier updates trusted, so
/// that no target is looked up in metadata the repository no longer vouches
/// for (here, because the timestamp has expired since).
#[test]
fn a_failed_update_ends_the_trust_in_earlier_metadata() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file", b"data");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.find("file").as_deref(), Some("targets"));

    repo.timestamp.expires = expired();
    repo.publish_timestamp();
    assert_matches!(client.refresh(), Err(Error::Expired { role, .. }) if role == "timestamp");
    assert!(client.updater.trusted().is_none());
    assert_matches!(
        client.get_target_info("file"),
        Err(Error::Expired { role, .. }) if role == "timestamp"
    );
}

/// 5.3.7, 5.3.8: root versions verified before a later step fails stay
/// trusted and persisted.
#[test]
fn new_root_versions_stay_trusted_when_a_later_step_fails() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    repo.timestamp.expires = expired();
    repo.publish_timestamp();

    let mut client = repo.client();
    assert_matches!(client.refresh(), Err(Error::Expired { role, .. }) if role == "timestamp");
    assert_eq!(client.root_version(), 2);
    assert_eq!(client.stored("root.json"), Some(repo.file("2.root.json")));
}

/// `Updater::get_target_info` first updates if the last update failed, or if
/// there was none.
#[test]
fn looking_up_a_target_updates_first_if_needed() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file", b"data");
    repo.timestamp.expires = expired();
    repo.commit();
    let mut client = repo.client();
    assert!(client.refresh().is_err());

    repo.timestamp.expires = far_future();
    repo.publish_timestamp();
    assert!(client.get_target_info("file").unwrap().is_some());
}

/// Every metadata file the client accepts is persisted, and a restarted
/// client starts from what it persisted: it needs no shipped root, and
/// downloads nothing that has not changed.
#[test]
fn a_restarted_client_starts_from_the_metadata_it_persisted() {
    let repo = TestRepo::new();
    let mut client = repo.client();
    client.refresh().unwrap();
    for name in [
        "root.json",
        "timestamp.json",
        "snapshot.json",
        "targets.json",
    ] {
        assert_eq!(client.stored(name), Some(repo.file(name)), "{name}");
    }

    repo.requests();
    let mut restarted = client.restart();
    restarted.refresh().unwrap();
    assert_eq!(repo.requests(), ["2.root.json", "timestamp.json"]);
}

/// Only the metadata that changed is downloaded again: here the top-level
/// targets metadata, but not the delegated metadata of "a".
#[test]
fn only_changed_metadata_is_downloaded_again() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["a/*"]));
    repo.add_target("a", "a/file", b"a");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.find("a/file").as_deref(), Some("a"));

    repo.add_target("targets", "new", b"new");
    repo.commit();
    repo.requests();
    client.refresh().unwrap();
    assert_eq!(client.find("a/file").as_deref(), Some("a"));
    assert_eq!(
        repo.requests(),
        [
            "2.root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json"
        ]
    );
}

/// Persisted metadata that cannot be loaded, here because it is corrupt, is
/// ignored: the client downloads the metadata again and persists it.
#[test]
fn invalid_persisted_metadata_is_downloaded_again() {
    let mut repo = TestRepo::new();
    repo.delegate("targets", Delegation::to("a").paths(&["*"]));
    repo.add_target("a", "file", b"data");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.find("file").as_deref(), Some("a"));

    let names = ["timestamp.json", "snapshot.json", "targets.json", "a.json"];
    for name in names {
        client.store.store(name, b"garbage").unwrap();
    }
    repo.requests();
    client.refresh().unwrap();
    assert_eq!(client.find("file").as_deref(), Some("a"));
    assert_eq!(
        repo.requests(),
        [
            "2.root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json",
            "a.json"
        ]
    );
    for name in names {
        assert_eq!(client.stored(name), Some(repo.file(name)), "{name}");
    }
}

/// Local storage whose operations fail when told to.
#[derive(Debug, Default)]
struct FaultyStore {
    files: MemoryStore,
    fail_loads: AtomicBool,
    fail_stores: AtomicBool,
    fail_removes: AtomicBool,
}

impl FaultyStore {
    fn check(fail: &AtomicBool) -> io::Result<()> {
        match fail.load(Ordering::SeqCst) {
            true => Err(io::Error::other("simulated storage failure")),
            false => Ok(()),
        }
    }
}

impl MetadataStore for FaultyStore {
    fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        Self::check(&self.fail_loads)?;
        self.files.load(name)
    }

    fn store(&self, name: &str, data: &[u8]) -> io::Result<()> {
        Self::check(&self.fail_stores)?;
        self.files.store(name, data)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        Self::check(&self.fail_removes)?;
        self.files.remove(name)
    }
}

/// Failures of local storage, whether to load, store or remove metadata,
/// abort the update and are reported with the name of the file.
#[test]
fn local_storage_failures_are_reported() {
    let mut repo = TestRepo::new();
    let store = Arc::new(FaultyStore::default());
    let updater = |store: &Arc<FaultyStore>| {
        Updater::builder(repo.transport.clone(), store.clone())
            .initial_root(repo.initial_root())
            .build()
    };

    store.fail_loads.store(true, Ordering::SeqCst);
    assert_matches!(updater(&store), Err(Error::Store { name, .. }) if name == "root.json");
    store.fail_loads.store(false, Ordering::SeqCst);

    let mut updater = updater(&store).unwrap();
    store.fail_stores.store(true, Ordering::SeqCst);
    assert_matches!(
        block_on(updater.refresh_at(now())),
        Err(Error::Store { name, .. }) if name == "timestamp.json"
    );
    store.fail_stores.store(false, Ordering::SeqCst);
    block_on(updater.refresh_at(now())).unwrap();

    // Rotating the timestamp key makes the update remove the trusted
    // timestamp and snapshot metadata (5.3.11).
    repo.rotate_key(RoleType::Timestamp);
    repo.publish_root();
    store.fail_removes.store(true, Ordering::SeqCst);
    assert_matches!(
        block_on(updater.refresh_at(now())),
        Err(Error::Store { name, .. }) if name == "timestamp.json"
    );
}
