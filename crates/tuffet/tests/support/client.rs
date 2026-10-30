//! A client of a [`TestRepo`].

use std::sync::Arc;

use futures_executor::block_on;
use tuffet::store::{MemoryStore, MetadataStore};
use tuffet::{TargetInfo, TrustedMetadata, Updater, UpdaterConfig};

use super::{RecordingTransport, TestRepo, now};

pub type TestUpdater = Updater<Arc<RecordingTransport>, Arc<MemoryStore>>;

/// An [`Updater`] of a [`TestRepo`], with in-memory local storage and a fixed
/// update start time.
pub struct Client {
    pub updater: TestUpdater,
    /// The client's local metadata storage.
    pub store: Arc<MemoryStore>,
    /// The update start time (5.1) of [`refresh`](Self::refresh); [`now`] by
    /// default.
    pub time: jiff::Timestamp,
    transport: Arc<RecordingTransport>,
    config: UpdaterConfig,
}

impl Client {
    /// A client of `repo` that trusts version 1 of its root metadata and has
    /// no local metadata yet.
    pub fn new(repo: &TestRepo, config: UpdaterConfig) -> Self {
        let store = Arc::new(MemoryStore::new());
        let updater = Updater::builder(repo.transport.clone(), store.clone())
            .initial_root(repo.initial_root())
            .config(config.clone())
            .build()
            .unwrap();
        Client {
            updater,
            store,
            time: now(),
            transport: repo.transport.clone(),
            config,
        }
    }

    /// The same client after a restart: a new `Updater` that starts from the
    /// local storage alone.
    pub fn restart(&self) -> Self {
        self.restart_from(None)
    }

    /// The same client after a restart of an application that ships
    /// `initial_root`: a new `Updater` that starts from it and the local
    /// storage.
    pub fn restart_with(&self, initial_root: Vec<u8>) -> Self {
        self.restart_from(Some(initial_root))
    }

    fn restart_from(&self, initial_root: Option<Vec<u8>>) -> Self {
        let mut builder = Updater::builder(self.transport.clone(), self.store.clone())
            .config(self.config.clone());
        if let Some(root) = initial_root {
            builder = builder.initial_root(root);
        }
        let updater = builder.build().unwrap();
        Client {
            updater,
            store: self.store.clone(),
            time: self.time,
            transport: self.transport.clone(),
            config: self.config.clone(),
        }
    }

    /// Runs the client workflow up to the top-level targets metadata.
    pub fn refresh(&mut self) -> tuffet::Result<()> {
        block_on(self.updater.refresh_at(self.time))
    }

    /// Looks up a target, searching delegations (5.6.7).
    pub fn get_target_info(&mut self, path: &str) -> tuffet::Result<Option<TargetInfo>> {
        block_on(self.updater.get_target_info(path))
    }

    /// The role that lists the target at `path`, if any.
    pub fn find(&mut self, path: &str) -> Option<String> {
        self.get_target_info(path)
            .unwrap_or_else(|error| panic!("looking up {path}: {error}"))
            .map(|target| target.role)
    }

    /// Downloads and verifies a target (5.7).
    pub fn download(&self, target: &TargetInfo) -> tuffet::Result<Vec<u8>> {
        block_on(self.updater.download_target(target))
    }

    /// The metadata file `name` in local storage.
    pub fn stored(&self, name: &str) -> Option<Vec<u8>> {
        self.store.load(name).unwrap()
    }

    /// The version of the trusted root metadata.
    pub fn root_version(&self) -> u64 {
        self.updater.root().signed().version
    }

    /// The metadata trusted by the last refresh, which must have succeeded.
    pub fn trusted(&self) -> &TrustedMetadata {
        self.updater.trusted().expect("the last refresh succeeded")
    }
}
