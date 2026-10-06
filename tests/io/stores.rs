//! Metadata stores keep the metadata an updater persists (5.3.8, 5.4.5,
//! 5.5.7, 5.6.6) by file name. `FilesystemStore` keeps it in one directory,
//! which names cannot escape, and writes files atomically.

use rftuf::store::{FilesystemStore, MemoryStore, MetadataStore};

/// What every store does.
fn check_store(store: &dyn MetadataStore) {
    assert_eq!(store.load("root.json").unwrap(), None);
    store.store("root.json", b"one").unwrap();
    store.store("root.json", b"two").unwrap();
    store.store("team%2Fweb.json", b"role").unwrap();
    assert_eq!(store.load("root.json").unwrap(), Some(b"two".to_vec()));
    assert_eq!(
        store.load("team%2Fweb.json").unwrap(),
        Some(b"role".to_vec())
    );

    store.remove("root.json").unwrap();
    assert_eq!(store.load("root.json").unwrap(), None);
    // Removing a file that does not exist is not an error.
    store.remove("root.json").unwrap();
}

#[test]
fn memory_store_stores_loads_and_removes() {
    check_store(&MemoryStore::new());
}

#[test]
fn filesystem_store_stores_loads_and_removes() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::new(dir.path().join("nested/metadata")).unwrap();
    check_store(&store);
}

/// What a `FilesystemStore` stores is still there for the next one on the
/// same directory, as plain files, without temporary files left behind.
#[test]
fn filesystem_store_keeps_files_in_its_directory() {
    let dir = tempfile::tempdir().unwrap();
    FilesystemStore::new(dir.path())
        .unwrap()
        .store("timestamp.json", b"timestamp")
        .unwrap();

    let reopened = FilesystemStore::new(dir.path()).unwrap();
    assert_eq!(
        reopened.load("timestamp.json").unwrap(),
        Some(b"timestamp".to_vec())
    );
    let files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(files, ["timestamp.json"]);
}

#[test]
fn filesystem_store_names_cannot_escape_its_directory() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::new(dir.path().join("metadata")).unwrap();
    for name in ["../root.json", "a/b.json", "", ".", ".."] {
        assert!(store.store(name, b"x").is_err(), "{name:?}");
        assert!(store.load(name).is_err(), "{name:?}");
        assert!(store.remove(name).is_err(), "{name:?}");
    }
    assert!(!dir.path().join("root.json").exists());
}

/// Failures other than a missing file are reported, not taken for a missing
/// file.
#[test]
fn filesystem_store_reports_files_that_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::new(dir.path()).unwrap();
    std::fs::create_dir(dir.path().join("root.json")).unwrap();
    assert!(store.load("root.json").is_err());
}
