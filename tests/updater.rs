//! End-to-end tests of the `Updater`.

mod common;

use std::path::Path;
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use common::{TestRepo, encode_role, expired, now};
use futures_executor::block_on;
use rftuf::metadata::RoleType;
use rftuf::store::{FilesystemStore, MemoryStore, MetadataStore};
use rftuf::transport::{FilesystemTransport, TransportError};
use rftuf::{Error, Updater, UpdaterConfig};

type TestUpdater = Updater<Arc<common::RecordingTransport>, Arc<MemoryStore>>;

fn updater(repo: &TestRepo, store: &Arc<MemoryStore>) -> TestUpdater {
    updater_with(repo, store, UpdaterConfig::default())
}

fn updater_with(repo: &TestRepo, store: &Arc<MemoryStore>, config: UpdaterConfig) -> TestUpdater {
    Updater::builder(repo.transport.clone(), store.clone())
        .initial_root(repo.initial_root())
        .config(config)
        .build()
        .unwrap()
}

fn refresh(updater: &mut TestUpdater) -> rftuf::Result<()> {
    block_on(updater.refresh_at(now()))
}

/// Refreshes and looks up a target, returning the role that lists it.
fn find(updater: &mut TestUpdater, path: &str) -> Option<String> {
    refresh(updater).unwrap();
    block_on(updater.get_target_info(path))
        .unwrap()
        .map(|info| info.role)
}

fn stored(store: &MemoryStore, name: &str) -> Option<Vec<u8>> {
    store.load(name).unwrap()
}

#[test]
fn downloads_a_target() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "dir/file.txt", b"hello");
    repo.commit();
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));

    refresh(&mut updater).unwrap();
    let info = block_on(updater.get_target_info("dir/file.txt"))
        .unwrap()
        .unwrap();
    assert_eq!((info.role.as_str(), info.file.length), ("targets", 5));
    assert_eq!(block_on(updater.download_target(&info)).unwrap(), b"hello");
    assert!(
        block_on(updater.get_target_info("missing.txt"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn persists_trusted_metadata_and_starts_from_it() {
    let repo = TestRepo::new();
    let store = Arc::new(MemoryStore::new());
    refresh(&mut updater(&repo, &store)).unwrap();
    for name in [
        "root.json",
        "timestamp.json",
        "snapshot.json",
        "targets.json",
    ] {
        assert_eq!(stored(&store, name), Some(repo.file(name)), "{name}");
    }

    // A new updater needs no initial root, and downloads nothing that has
    // not changed.
    repo.transport.take_requests();
    let mut restarted = Updater::builder(repo.transport.clone(), store.clone())
        .build()
        .unwrap();
    refresh(&mut restarted).unwrap();
    assert_eq!(
        repo.transport.take_requests(),
        ["2.root.json", "timestamp.json"]
    );
}

#[test]
fn downloads_only_changed_metadata() {
    let mut repo = TestRepo::new();
    repo.add_delegation("targets", "a", &["a/*"], false);
    repo.add_target("a", "a/file", b"a");
    repo.commit();
    let store = Arc::new(MemoryStore::new());
    let mut updater = updater(&repo, &store);
    assert_eq!(find(&mut updater, "a/file").as_deref(), Some("a"));

    repo.add_target("targets", "new", b"new");
    repo.commit();
    repo.transport.take_requests();
    assert_eq!(find(&mut updater, "a/file").as_deref(), Some("a"));
    assert_eq!(
        repo.transport.take_requests(),
        [
            "2.root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json"
        ]
    );
}

#[test]
fn walks_through_every_new_root_version() {
    let mut repo = TestRepo::new();
    for _ in 0..3 {
        repo.rotate_key(RoleType::Root);
        repo.publish_root();
    }
    let store = Arc::new(MemoryStore::new());
    let mut updater = updater(&repo, &store);
    refresh(&mut updater).unwrap();
    assert_eq!(updater.root().signed().version, 4);
    assert_eq!(stored(&store, "root.json"), Some(repo.file("4.root.json")));
    assert_eq!(
        repo.transport.take_requests()[..4],
        ["2.root.json", "3.root.json", "4.root.json", "5.root.json"]
    );
}

#[test]
fn limits_root_versions_per_refresh() {
    let mut repo = TestRepo::new();
    for _ in 0..3 {
        repo.publish_root();
    }
    let mut config = UpdaterConfig::default();
    config.max_root_rotations = 2;
    let mut updater = updater_with(&repo, &Arc::new(MemoryStore::new()), config);
    refresh(&mut updater).unwrap();
    assert_eq!(updater.root().signed().version, 3);
    refresh(&mut updater).unwrap();
    assert_eq!(updater.root().signed().version, 4);
}

#[test]
fn rejects_root_not_signed_by_the_trusted_root_keys() {
    let mut repo = TestRepo::new();
    repo.rotate_key(RoleType::Root);
    let mut next = repo.root.clone();
    next.version = 2;
    let forged = TestRepo::sign_with(&next, &[&repo.signers["root"][0]]);
    repo.write("2.root.json", forged);

    let store = Arc::new(MemoryStore::new());
    let mut updater = updater(&repo, &store);
    assert!(matches!(
        refresh(&mut updater),
        Err(Error::SignatureThreshold { role, .. }) if role == "root"
    ));
    assert_eq!(updater.root().signed().version, 1);
    assert_eq!(stored(&store, "root.json"), Some(repo.initial_root()));
    assert!(updater.trusted().is_none());
}

#[test]
fn keeps_new_root_when_a_later_step_fails() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    repo.timestamp.expires = expired();
    repo.publish_timestamp();
    let store = Arc::new(MemoryStore::new());
    let mut updater = updater(&repo, &store);
    assert!(matches!(refresh(&mut updater), Err(Error::Expired { .. })));
    assert_eq!(updater.root().signed().version, 2);
    assert_eq!(stored(&store, "root.json"), Some(repo.file("2.root.json")));
}

#[test]
fn detects_freeze_attacks() {
    for role in ["timestamp", "snapshot", "targets"] {
        let mut repo = TestRepo::new();
        match role {
            "timestamp" => repo.timestamp.expires = expired(),
            "snapshot" => repo.snapshot.expires = expired(),
            _ => repo.targets_mut("targets").expires = expired(),
        }
        repo.commit();
        let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
        let result = refresh(&mut updater);
        assert!(
            matches!(&result, Err(Error::Expired { role: r, .. }) if r == role),
            "{result:?}"
        );
        assert!(updater.trusted().is_none());
    }
}

#[test]
fn detects_rollback_attacks() {
    let mut repo = TestRepo::new();
    let old_timestamp = repo.file("timestamp.json");
    repo.commit();
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
    refresh(&mut updater).unwrap();

    repo.write("timestamp.json", old_timestamp);
    assert!(matches!(
        refresh(&mut updater),
        Err(Error::Rollback { role, trusted: 2, new: 1 }) if role == "timestamp"
    ));
}

#[test]
fn recovers_from_fast_forward_attacks() {
    let mut repo = TestRepo::new();
    let store = Arc::new(MemoryStore::new());
    let mut updater = updater(&repo, &store);
    refresh(&mut updater).unwrap();

    // An attacker holding the timestamp key publishes a huge version...
    repo.timestamp.version = 999;
    repo.publish_timestamp();
    refresh(&mut updater).unwrap();

    // ...so the repository replaces the key and starts over.
    repo.rotate_key(RoleType::Timestamp);
    repo.publish_root();
    repo.timestamp.version = 1;
    repo.publish_timestamp();
    refresh(&mut updater).unwrap();
    assert_eq!(
        updater
            .trusted()
            .unwrap()
            .timestamp()
            .unwrap()
            .signed()
            .version,
        2
    );
    assert_eq!(
        stored(&store, "timestamp.json"),
        Some(repo.file("timestamp.json"))
    );
}

#[test]
fn rejects_tampered_targets() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file", b"genuine");
    repo.commit();
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
    refresh(&mut updater).unwrap();
    let info = block_on(updater.get_target_info("file")).unwrap().unwrap();

    for (served, check) in [
        (
            &b"forged!"[..],
            (|e: &Error| matches!(e, Error::HashMismatch { .. })) as fn(&Error) -> bool,
        ),
        (b"genuine, plus endless data", |e| {
            matches!(e, Error::TooLarge { max: 7, .. })
        }),
        (b"genuin", |e| {
            matches!(
                e,
                Error::LengthMismatch {
                    expected: 7,
                    actual: 6,
                    ..
                }
            )
        }),
    ] {
        repo.transport.inner.insert_target("file", served.to_vec());
        let error = block_on(updater.download_target(&info)).unwrap_err();
        assert!(check(&error), "{error:?}");
    }
}

#[test]
fn download_to_file_writes_only_verified_data() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file", b"genuine");
    repo.commit();
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
    refresh(&mut updater).unwrap();
    let info = block_on(updater.get_target_info("file")).unwrap().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("file");

    block_on(updater.download_target_to(&info, &destination)).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"genuine");
    assert!(info.matches_file(&destination).unwrap());

    std::fs::remove_file(&destination).unwrap();
    repo.transport
        .inner
        .insert_target("file", b"forged!".to_vec());
    assert!(block_on(updater.download_target_to(&info, &destination)).is_err());
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "no file or temporary file is left"
    );
}

#[test]
fn limits_metadata_size() {
    let repo = TestRepo::new();
    let mut config = UpdaterConfig::default();
    config.timestamp_max_length = 64;
    let mut updater = updater_with(&repo, &Arc::new(MemoryStore::new()), config);
    assert!(matches!(
        refresh(&mut updater),
        Err(Error::TooLarge { name, max: 64 }) if name == "timestamp.json"
    ));
}

#[test]
fn searches_delegations_in_priority_order() {
    let mut repo = TestRepo::new();
    repo.add_delegation("targets", "a", &["a/*"], false);
    repo.add_delegation("targets", "b", &["a/*", "b"], false);
    repo.add_target("a", "a/shared", b"from a");
    repo.add_target("b", "a/shared", b"from b");
    repo.add_target("b", "a/only-b", b"b");
    repo.add_target("b", "b", b"b");
    repo.commit();
    let store = Arc::new(MemoryStore::new());
    let mut updater = updater(&repo, &store);

    assert_eq!(find(&mut updater, "a/shared").as_deref(), Some("a"));
    assert_eq!(find(&mut updater, "a/only-b").as_deref(), Some("b"));
    assert_eq!(find(&mut updater, "b").as_deref(), Some("b"));
    assert_eq!(find(&mut updater, "c"), None);
    assert_eq!(stored(&store, "a.json"), Some(repo.file("a.json")));
    assert_eq!(stored(&store, "b.json"), Some(repo.file("b.json")));

    // The repository serves one file per path, last written by "b"; it does
    // not match what the higher-priority role "a" lists.
    let info = block_on(updater.get_target_info("a/shared"))
        .unwrap()
        .unwrap();
    assert!(matches!(
        block_on(updater.download_target(&info)),
        Err(Error::HashMismatch { .. })
    ));
    repo.transport
        .inner
        .insert_target("a/shared", b"from a".to_vec());
    assert_eq!(block_on(updater.download_target(&info)).unwrap(), b"from a");
}

#[test]
fn terminating_delegations_hide_lower_priorities() {
    let mut repo = TestRepo::new();
    repo.add_delegation("targets", "a", &["a/*"], true);
    repo.add_delegation("targets", "b", &["a/*"], false);
    repo.add_target("b", "a/only-b", b"b");
    repo.commit();
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
    assert_eq!(find(&mut updater, "a/only-b"), None);
}

#[test]
fn a_role_is_verified_for_each_delegation_it_is_reached_through() {
    // "a" and "b" both delegate to "shared", with different keys; "shared" is
    // signed only with the key "a" trusts.
    let mut repo = TestRepo::new();
    repo.add_delegation("targets", "a", &["a/*"], false);
    repo.add_delegation("targets", "b", &["b/*"], false);
    repo.add_delegation("a", "shared", &["a/*"], false);
    let key_trusted_by_a = repo.signers["shared"].clone();
    repo.add_delegation("b", "shared", &["b/*"], false);
    repo.signers.insert("shared".to_owned(), key_trusted_by_a);
    repo.add_target("shared", "a/file", b"trusted");
    repo.add_target("shared", "b/file", b"malicious");
    repo.commit();
    let store = Arc::new(MemoryStore::new());

    let mut client = updater(&repo, &store);
    assert_eq!(find(&mut client, "a/file").as_deref(), Some("shared"));
    let through_b = block_on(client.get_target_info("b/file"));
    assert!(
        matches!(&through_b, Err(Error::SignatureThreshold { role, .. }) if role == "shared"),
        "{through_b:?}"
    );

    // A new session reaching "shared" through "b" first, from the cache.
    let mut restarted = updater(&repo, &store);
    refresh(&mut restarted).unwrap();
    assert!(matches!(
        block_on(restarted.get_target_info("b/file")),
        Err(Error::SignatureThreshold { .. })
    ));
}

#[test]
fn percent_encodes_role_names_in_file_names() {
    let mut repo = TestRepo::new();
    repo.add_delegation("targets", "team/web", &["*"], false);
    repo.add_target("team/web", "page", b"html");
    repo.commit();
    let store = Arc::new(MemoryStore::new());
    let mut updater = updater(&repo, &store);
    assert_eq!(find(&mut updater, "page").as_deref(), Some("team/web"));
    assert_eq!(encode_role("team/web"), "team%2Fweb");
    assert!(
        repo.transport
            .take_requests()
            .contains(&"team%2Fweb.json".to_owned())
    );
    assert!(stored(&store, "team%2Fweb.json").is_some());
}

#[test]
fn uses_consistent_snapshot_file_names() {
    let mut repo = TestRepo::with_consistent_snapshot(true);
    repo.add_target("targets", "dir/file.txt", b"content");
    repo.commit();
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
    refresh(&mut updater).unwrap();
    let info = block_on(updater.get_target_info("dir/file.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(
        block_on(updater.download_target(&info)).unwrap(),
        b"content"
    );

    let sha256 = info.file.hashes.get("sha256").unwrap();
    assert_eq!(
        repo.transport.take_requests(),
        [
            "2.root.json".to_owned(),
            "timestamp.json".to_owned(),
            "2.snapshot.json".to_owned(),
            "2.targets.json".to_owned(),
            format!("target:dir/{sha256}.file.txt"),
        ]
    );
}

#[test]
fn can_fetch_targets_without_hash_prefixes() {
    let mut repo = TestRepo::with_consistent_snapshot(true);
    repo.add_target("targets", "file.txt", b"content");
    repo.commit();
    repo.transport
        .inner
        .insert_target("file.txt", b"content".to_vec());
    let mut config = UpdaterConfig::default();
    config.prefix_targets_with_hash = false;
    let mut updater = updater_with(&repo, &Arc::new(MemoryStore::new()), config);
    refresh(&mut updater).unwrap();
    let info = block_on(updater.get_target_info("file.txt"))
        .unwrap()
        .unwrap();
    repo.transport.take_requests();
    assert_eq!(
        block_on(updater.download_target(&info)).unwrap(),
        b"content"
    );
    assert_eq!(repo.transport.take_requests(), ["target:file.txt"]);
}

#[test]
fn builder_starts_from_the_newest_trusted_root() {
    let mut repo = TestRepo::new();
    repo.publish_root();
    repo.publish_root();
    let build = |store: &Arc<MemoryStore>, initial: Option<Vec<u8>>| {
        let builder = Updater::builder(repo.transport.clone(), store.clone());
        match initial {
            Some(root) => builder.initial_root(root).build(),
            None => builder.build(),
        }
    };

    let empty = Arc::new(MemoryStore::new());
    assert!(matches!(build(&empty, None), Err(Error::NoTrustedRoot)));

    let newer_stored = Arc::new(MemoryStore::new());
    newer_stored
        .store("root.json", &repo.file("3.root.json"))
        .unwrap();
    let updater = build(&newer_stored, Some(repo.initial_root())).unwrap();
    assert_eq!(updater.root().signed().version, 3);

    let older_stored = Arc::new(MemoryStore::new());
    older_stored
        .store("root.json", &repo.initial_root())
        .unwrap();
    let updater = build(&older_stored, Some(repo.file("3.root.json"))).unwrap();
    assert_eq!(updater.root().signed().version, 3);
    assert_eq!(
        stored(&older_stored, "root.json"),
        Some(repo.file("3.root.json"))
    );

    let corrupt = Arc::new(MemoryStore::new());
    corrupt.store("root.json", b"garbage").unwrap();
    assert!(matches!(build(&corrupt, None), Err(Error::Decode(_))));
    let updater = build(&corrupt, Some(repo.initial_root())).unwrap();
    assert_eq!(updater.root().signed().version, 1);
    assert_eq!(stored(&corrupt, "root.json"), Some(repo.initial_root()));
}

#[test]
fn looking_up_a_target_refreshes_if_needed() {
    let mut repo = TestRepo::new();
    repo.add_target("targets", "file", b"data");
    repo.timestamp.expires = expired();
    repo.commit();
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
    assert!(refresh(&mut updater).is_err());
    assert!(updater.trusted().is_none());

    repo.timestamp.expires = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap();
    repo.publish_timestamp();
    let info = block_on(updater.get_target_info("file")).unwrap();
    assert!(info.is_some());
}

#[test]
fn reports_missing_targets_metadata() {
    let mut repo = TestRepo::new();
    repo.add_delegation("targets", "a", &["*"], false);
    repo.commit();
    repo.transport.inner.remove_metadata("a.json");
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
    refresh(&mut updater).unwrap();
    assert!(matches!(
        block_on(updater.get_target_info("file")),
        Err(Error::Transport(TransportError::NotFound(name))) if name == "a.json"
    ));
}

#[test]
fn updates_from_the_reference_implementations_repository_on_disk() {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/python-tuf");
    let transport = FilesystemTransport::new(data.join("metadata"), data.join("targets"));
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::new(dir.path().join("metadata")).unwrap();
    let mut updater = Updater::builder(transport, store)
        .initial_root(std::fs::read(data.join("metadata/root.json")).unwrap())
        .build()
        .unwrap();

    block_on(updater.refresh_at(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap())).unwrap();
    let file1 = block_on(updater.get_target_info("file1.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(
        file1.file.custom,
        Some(serde_json::json!({"file_permissions": "0644"}))
    );

    // file3.txt is listed by the delegated role "role1".
    let file3 = block_on(updater.get_target_info("file3.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(file3.role, "role1");
    let destination = dir.path().join("file3.txt");
    block_on(updater.download_target_to(&file3, &destination)).unwrap();
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        std::fs::read(data.join("targets/file3.txt")).unwrap()
    );

    for name in [
        "root.json",
        "timestamp.json",
        "snapshot.json",
        "targets.json",
        "role1.json",
    ] {
        assert!(
            dir.path().join("metadata").join(name).exists(),
            "{name} is persisted"
        );
    }

    // After 2030, the repository's metadata has expired.
    let late = Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0).unwrap();
    assert!(matches!(
        block_on(updater.refresh_at(late)),
        Err(Error::Expired { .. })
    ));
}

#[test]
fn updater_futures_are_send() {
    fn assert_send<T: Send>(_: &T) {}
    let repo = TestRepo::new();
    let mut updater = updater(&repo, &Arc::new(MemoryStore::new()));
    assert_send(&updater.refresh());
    assert_send(&updater.get_target_info("file"));
    let info = rftuf::TargetInfo {
        path: "file".into(),
        role: "targets".into(),
        file: rftuf::metadata::TargetFile::from_bytes(b"", &rftuf::crypto::HashAlgorithm::ALL),
    };
    assert_send(&updater.download_target(&info));
    assert_send(&updater.download_target_to(&info, Path::new("x")));
}
