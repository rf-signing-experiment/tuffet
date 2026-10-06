//! The built-in transports and metadata stores, and an updater that uses the
//! filesystem ones.

#[path = "../support/mod.rs"]
mod support;

// `FilesystemTransport`
mod filesystem_transport;

// `MemoryTransport`
mod memory_transport;

// `FilesystemStore` and `MemoryStore`
mod stores;

// An updater with `FilesystemTransport` and `FilesystemStore`
mod repository_on_disk;

use std::path::Path;

use rftuf::TargetInfo;
use rftuf::crypto::HashAlgorithm;
use rftuf::metadata::TargetFile;

use support::TestRepo;

/// The updater's futures are `Send` (as `Transport`'s are required to be),
/// so that it can run on multi-threaded executors.
#[test]
fn updater_futures_are_send() {
    fn assert_send<T: Send>(_: &T) {}
    let repo = TestRepo::new();
    let mut client = repo.client();
    assert_send(&client.updater.refresh());
    assert_send(&client.updater.get_target_info("file"));
    let target = TargetInfo {
        path: "file".to_owned(),
        role: "targets".to_owned(),
        file: TargetFile::from_bytes(b"", &HashAlgorithm::ALL),
    };
    assert_send(&client.updater.download_target(&target));
    assert_send(
        &client
            .updater
            .download_target_to(&target, Path::new("file")),
    );
}
