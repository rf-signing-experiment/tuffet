//! 6.2 Consistent snapshots, as clients read them (6.2.2 defers to the
//! client workflow).
//!
//! When root metadata sets `consistent_snapshot`, the client downloads
//! snapshot and targets metadata by version, as `VERSION.FILENAME.EXT`
//! (5.5.1, 5.6.1), and targets by hash, as `HASH.FILENAME.EXT` (5.7.3).
//! Root is always downloaded by version (5.3.3) and timestamp never
//! (5.4.1).

use rftuf::crypto::HashAlgorithm;
use rftuf::{TargetInfo, UpdaterConfig};

use crate::support::{Delegation, TestRepo};

/// Publishes a delegated role, `team/web`, that lists a target in a
/// directory; downloads that target with a new client; and returns the
/// target and the requests made.
fn download_from(mut repo: TestRepo) -> (TargetInfo, Vec<String>) {
    repo.delegate("targets", Delegation::to("team/web").paths(&["dir/*"]));
    repo.add_target("team/web", "dir/file.txt", b"content");
    repo.commit();

    let mut client = repo.client();
    client.refresh().unwrap();
    let target = client.get_target_info("dir/file.txt").unwrap().unwrap();
    assert_eq!(client.download(&target).unwrap(), b"content");
    (target, repo.requests())
}

/// 5.5.1, 5.6.1, 5.7.3: with consistent snapshots, metadata is downloaded by
/// the version the trusted timestamp or snapshot lists (for delegated
/// roles, too) and the target with a hash its targets metadata lists, in
/// the same directory.
#[test]
fn files_are_downloaded_by_version_and_by_hash() {
    let (target, requests) = download_from(TestRepo::builder().consistent_snapshots().build());
    let sha256 = target.file.hashes.get("sha256").unwrap();
    assert_eq!(
        requests,
        [
            "2.root.json",
            "timestamp.json",
            "2.snapshot.json",
            "2.targets.json",
            "1.team%2Fweb.json",
            format!("target:dir/{sha256}.file.txt").as_str(),
        ]
    );
}

/// 5.5.1, 5.6.1, 5.7.3: "If consistent snapshots are not used", files are
/// downloaded by their plain names.
#[test]
fn without_consistent_snapshots_files_are_downloaded_by_name() {
    let (_, requests) = download_from(TestRepo::new());
    assert_eq!(
        requests,
        [
            "2.root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json",
            "team%2Fweb.json",
            "target:dir/file.txt",
        ]
    );
}

/// 5.7.3: "HASH is one of the hashes of the targets file listed in the
/// targets metadata file". rftuf uses the SHA-256 hash if it is listed, and
/// otherwise another hash it supports.
#[test]
fn targets_are_downloaded_with_a_hash_their_metadata_lists() {
    let mut repo = TestRepo::builder().consistent_snapshots().build();
    let listed = repo.add_target_with_hashes("targets", "file", b"data", &[HashAlgorithm::Sha512]);
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();
    let target = client.get_target_info("file").unwrap().unwrap();
    repo.requests();

    assert_eq!(client.download(&target).unwrap(), b"data");
    let sha512 = listed.hashes.get("sha512").unwrap();
    assert_eq!(repo.requests(), [format!("target:{sha512}.file")]);
}

/// `UpdaterConfig::prefix_targets_with_hash`: some repositories with
/// consistent snapshots store target files under their plain names, which
/// clients can be configured to download.
#[test]
fn targets_can_be_downloaded_without_hash_prefixes() {
    let mut repo = TestRepo::builder().consistent_snapshots().build();
    repo.add_target("targets", "file.txt", b"content");
    repo.commit();
    repo.serve_target("file.txt", b"content");
    let mut config = UpdaterConfig::default();
    config.prefix_targets_with_hash = false;
    let mut client = repo.client_with(config);
    client.refresh().unwrap();
    let target = client.get_target_info("file.txt").unwrap().unwrap();
    repo.requests();

    assert_eq!(client.download(&target).unwrap(), b"content");
    assert_eq!(repo.requests(), ["target:file.txt"]);
}

/// 5.5.7, 5.6.6: metadata downloaded as `VERSION.FILENAME.EXT` is persisted
/// as `FILENAME.EXT`.
#[test]
fn metadata_is_persisted_without_the_version() {
    let mut repo = TestRepo::builder().consistent_snapshots().build();
    repo.delegate("targets", Delegation::to("a").paths(&["*"]));
    repo.add_target("a", "file", b"data");
    repo.commit();
    let mut client = repo.client();
    client.refresh().unwrap();
    assert_eq!(client.find("file").as_deref(), Some("a"));

    for (persisted, downloaded) in [
        ("snapshot.json", "2.snapshot.json"),
        ("targets.json", "2.targets.json"),
        ("a.json", "1.a.json"),
    ] {
        assert_eq!(client.stored(persisted), Some(repo.file(downloaded)));
        assert_eq!(client.stored(downloaded), None);
    }
}
