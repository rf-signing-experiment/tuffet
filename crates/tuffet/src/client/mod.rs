//! The high-level client, which runs the complete client workflow.
//!
//! An [`Updater`] fetches metadata through a [`Transport`], verifies it with
//! [`TrustedMetadata`], persists what it trusts in a [`MetadataStore`], and
//! downloads and verifies target files.
//!
//! ```no_run
//! use tuffet::store::FilesystemStore;
//! use tuffet::transport::FilesystemTransport;
//! use tuffet::Updater;
//!
//! # async fn example() -> tuffet::Result<()> {
//! let transport = FilesystemTransport::new("/mnt/repo/metadata", "/mnt/repo/targets");
//! let store = FilesystemStore::new("/var/lib/app/tuf")?;
//! let mut updater = Updater::builder(transport, store)
//!     .initial_root(std::fs::read("/usr/share/app/root.json")?)
//!     .build()?;
//!
//! updater.refresh().await?;
//! if let Some(target) = updater.get_target_info("app-1.2.tar.gz").await? {
//!     updater.download_target_to(&target, "/tmp/app-1.2.tar.gz".as_ref()).await?;
//! }
//! # Ok(())
//! # }
//! ```

use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;

use crate::error::{Error, Result};
use crate::metadata::{Metadata, Root};
use crate::pouf::{Json, Pouf};
use crate::store::MetadataStore;
use crate::transport::Transport;
use crate::trusted::{TargetInfo, TargetSearch, TrustedMetadata};

mod workflow;

use workflow::Workflow;

/// Limits and options for an [`Updater`].
///
/// The defaults match those of the reference implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdaterConfig {
    /// The maximum number of new root versions to accept in one refresh.
    pub max_root_rotations: u32,
    /// The maximum number of targets roles to visit when looking up a target.
    pub max_delegations: usize,
    /// The maximum size of root metadata, in bytes.
    pub root_max_length: u64,
    /// The maximum size of timestamp metadata, in bytes.
    pub timestamp_max_length: u64,
    /// The maximum size of snapshot metadata whose length timestamp metadata
    /// does not list, in bytes.
    pub snapshot_max_length: u64,
    /// The maximum size of targets metadata whose length snapshot metadata
    /// does not list, in bytes.
    pub targets_max_length: u64,
    /// Whether to fetch targets as `HASH.FILENAME` when the repository uses
    /// consistent snapshots. Some repositories store target files under their
    /// plain names even then.
    pub prefix_targets_with_hash: bool,
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        UpdaterConfig {
            max_root_rotations: 256,
            max_delegations: 32,
            root_max_length: 512_000,
            timestamp_max_length: 16_384,
            snapshot_max_length: 2_000_000,
            targets_max_length: 5_000_000,
            prefix_targets_with_hash: true,
        }
    }
}

/// A TUF client for one repository.
///
/// Create one with [`Updater::builder`]. Call [`refresh`](Self::refresh) to
/// update the trusted metadata, then look up targets with
/// [`get_target_info`](Self::get_target_info) and download them.
///
/// `P` is the [POUF](crate::pouf) of the repository's metadata.
#[derive(Debug)]
pub struct Updater<T, S, P: Pouf = Json> {
    workflow: Workflow<T, S>,
    /// The latest trusted root, from which each refresh starts.
    root: Metadata<Root, P>,
    /// The trusted metadata, after a successful refresh.
    trusted: Option<TrustedMetadata<P>>,
}

impl<T: Transport, S: MetadataStore> Updater<T, S> {
    /// Starts building an updater that fetches files through `transport` and
    /// persists trusted metadata in `store`.
    pub fn builder(transport: T, store: S) -> UpdaterBuilder<T, S> {
        UpdaterBuilder {
            transport,
            store,
            config: UpdaterConfig::default(),
            initial_root: None,
            pouf: PhantomData,
        }
    }
}

impl<T: Transport, S: MetadataStore, P: Pouf> Updater<T, S, P> {
    /// Updates the trusted metadata from the repository, using the current
    /// time as the update start time.
    pub async fn refresh(&mut self) -> Result<()> {
        self.refresh_at(jiff::Timestamp::now()).await
    }

    /// Updates the trusted metadata from the repository, checking expiry
    /// against `reference_time`.
    ///
    /// Updates root metadata through every new version (5.3), then timestamp
    /// (5.4), snapshot (5.5) and top-level targets metadata (5.6). Delegated
    /// targets metadata is loaded when a target lookup needs it.
    ///
    /// On error the updater trusts no metadata other than root until the
    /// next successful refresh. New root versions accepted before the error
    /// remain trusted.
    #[tracing::instrument(name = "refresh", skip_all)]
    pub async fn refresh_at(&mut self, reference_time: jiff::Timestamp) -> Result<()> {
        self.trusted = None;
        let mut trusted = TrustedMetadata::from_root(self.root.clone(), reference_time)?;
        let result = self.workflow.refresh(&mut trusted).await;
        self.root = trusted.root().clone();
        result?;
        self.trusted = Some(trusted);
        Ok(())
    }

    /// Looks up a target by path, searching delegated roles as needed.
    /// Refreshes first if there is no trusted metadata.
    ///
    /// Returns `None` if no trusted role lists the target.
    #[tracing::instrument(skip(self))]
    pub async fn get_target_info(&mut self, path: &str) -> Result<Option<TargetInfo>> {
        if self.trusted.is_none() {
            self.refresh().await?;
        }
        let trusted = self.trusted.as_mut().expect("refreshed");
        let mut search = TargetSearch::new(path, self.workflow.config.max_delegations);
        while let Some(step) = search.next_step() {
            let targets = self
                .workflow
                .load_targets(trusted, &step.role, &step.delegator)
                .await?;
            if let Some(found) = search.visit(&step, targets.signed()) {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Downloads a target into memory and verifies it.
    pub async fn download_target(&self, target: &TargetInfo) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        self.workflow
            .download_target(&self.root, target, |chunk| {
                data.extend_from_slice(chunk);
                Ok(())
            })
            .await?;
        Ok(data)
    }

    /// Downloads a target to `destination` and verifies it.
    ///
    /// The file is written to a temporary file next to `destination` and only
    /// moved into place once it has been verified, so `destination` never
    /// holds unverified data.
    pub async fn download_target_to(&self, target: &TargetInfo, destination: &Path) -> Result<()> {
        let dir = match destination.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        self.workflow
            .download_target(&self.root, target, |chunk| file.write_all(chunk))
            .await?;
        file.as_file().sync_all()?;
        file.persist(destination)
            .map_err(|error| Error::Io(error.error))?;
        Ok(())
    }

    /// The latest trusted root metadata.
    pub fn root(&self) -> &Metadata<Root, P> {
        &self.root
    }

    /// The trusted metadata, if the last refresh succeeded.
    pub fn trusted(&self) -> Option<&TrustedMetadata<P>> {
        self.trusted.as_ref()
    }

    pub fn config(&self) -> &UpdaterConfig {
        &self.workflow.config
    }

    pub fn transport(&self) -> &T {
        &self.workflow.transport
    }

    pub fn store(&self) -> &S {
        &self.workflow.store
    }
}

/// Builds an [`Updater`].
#[derive(Debug)]
pub struct UpdaterBuilder<T, S, P = Json> {
    transport: T,
    store: S,
    config: UpdaterConfig,
    initial_root: Option<Vec<u8>>,
    pouf: PhantomData<fn() -> P>,
}

impl<T: Transport, S: MetadataStore, P: Pouf> UpdaterBuilder<T, S, P> {
    /// Root metadata to trust initially, normally shipped with the
    /// application. It is the trust anchor: root metadata in local storage is
    /// only trusted if it descends from it. Without an initial root, the root
    /// in local storage is trusted as it is.
    pub fn initial_root(mut self, root: impl Into<Vec<u8>>) -> Self {
        self.initial_root = Some(root.into());
        self
    }

    pub fn config(mut self, config: UpdaterConfig) -> Self {
        self.config = config;
        self
    }

    /// Uses a different POUF than the default JSON one.
    pub fn pouf<Q: Pouf>(self) -> UpdaterBuilder<T, S, Q> {
        UpdaterBuilder {
            transport: self.transport,
            store: self.store,
            config: self.config,
            initial_root: self.initial_root,
            pouf: PhantomData,
        }
    }

    /// Creates the updater. It starts from the initial root or, without one,
    /// from the root in local storage, followed by the newer root versions
    /// that earlier updates persisted. Fails if there is neither an initial
    /// root nor a root in local storage.
    pub fn build(self) -> Result<Updater<T, S, P>> {
        let workflow = Workflow {
            transport: self.transport,
            store: self.store,
            config: self.config,
        };
        let root = workflow.load_trusted_root(self.initial_root)?;
        Ok(Updater {
            workflow,
            root,
            trusted: None,
        })
    }
}
