//! Updating again.
//!
//! The introduction of section 5: if a step fails, "the client should still
//! be able to update again in the future. Errors raised during the update
//! process should not leave clients in an unrecoverable state." Between
//! updates, the client relies on the metadata it persisted (5.3.8, 5.4.5,
//! 5.5.7, 5.6.6).

use std::io;

use futures_executor::block_on;
use rftuf::store::{MemoryStore, MetadataStore};
use rftuf::{Error, Updater};

use crate::support::{Delegation, TestRepo, assert_err, expired, far_future, now};

/// After a failed update the client trusts no metadata but root, and once
/// the repository is repaired, the next update succeeds.
#[test]
fn an_update_can_be_repeated_after_a_failure() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file", b"data");
    repo.timestamp.expires = expired();
    repo.commit();
    let mut client = repo.client();
    assert_err!(client.refresh(), Error::Expired { role, .. } if role == "timestamp");
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
    assert_err!(client.refresh(), Error::Expired { role, .. } if role == "timestamp");
    assert!(client.updater.trusted().is_none());
    assert_err!(
        client.get_target_info("file"),
        Error::Expired { role, .. } if role == "timestamp"
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
    assert_err!(client.refresh(), Error::Expired { role, .. } if role == "timestamp");
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

/// Failures of local storage abort the update and are reported.
#[test]
fn local_storage_failures_are_reported() {
    /// Storage that holds a root but cannot be written to.
    struct ReadOnly(MemoryStore);

    impl MetadataStore for ReadOnly {
        fn load(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
            self.0.load(name)
        }

        fn store(&self, _: &str, _: &[u8]) -> io::Result<()> {
            Err(io::Error::other("read-only"))
        }

        fn remove(&self, _: &str) -> io::Result<()> {
            Err(io::Error::other("read-only"))
        }
    }

    let repo = TestRepo::new();
    let store = ReadOnly(MemoryStore::new());
    store.0.store("root.json", &repo.initial_root()).unwrap();
    let mut updater = Updater::builder(repo.transport.clone(), &store)
        .build()
        .unwrap();
    assert_err!(
        block_on(updater.refresh_at(now())),
        Error::Store { name, .. } if name == "timestamp.json"
    );
}
