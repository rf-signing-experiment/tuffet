//! An updater that reads a repository from disk (`FilesystemTransport`) and
//! persists metadata on disk (`FilesystemStore`).

use futures_executor::block_on;
use rftuf::Updater;
use rftuf::store::FilesystemStore;
use rftuf::transport::FilesystemTransport;

use crate::support::{Delegation, TestRepo, now};

#[test]
fn updates_from_a_repository_on_disk() {
    let mut repo = TestRepo::builder().consistent_snapshots().build();
    repo.publish_root();
    repo.delegate("targets", Delegation::to("team/web").paths(&["dir/*"]));
    repo.add_target("team/web", "dir/file.txt", b"content");
    repo.commit();
    let dir = tempfile::tempdir().unwrap();
    repo.export(&dir.path().join("repository"));

    let transport = FilesystemTransport::new(
        dir.path().join("repository/metadata"),
        dir.path().join("repository/targets"),
    );
    let store = FilesystemStore::new(dir.path().join("client")).unwrap();
    let mut updater = Updater::builder(transport, store)
        .initial_root(repo.initial_root())
        .build()
        .unwrap();
    block_on(updater.refresh_at(now())).unwrap();
    assert_eq!(updater.root().signed().version, 2);

    let target = block_on(updater.get_target_info("dir/file.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(target.role, "team/web");
    let destination = dir.path().join("file.txt");
    block_on(updater.download_target_to(&target, &destination)).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"content");

    let mut persisted: Vec<_> = std::fs::read_dir(dir.path().join("client"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    persisted.sort();
    assert_eq!(
        persisted,
        [
            "root.json",
            "snapshot.json",
            "targets.json",
            "team%2Fweb.json",
            "timestamp.json"
        ]
    );
    assert_eq!(
        std::fs::read(dir.path().join("client/root.json")).unwrap(),
        repo.file("2.root.json")
    );
}
