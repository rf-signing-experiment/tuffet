//! The steps of the client workflow (section 5 of the specification), run
//! against the transport and the metadata store.

use std::io;

use futures_util::StreamExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use super::UpdaterConfig;
use crate::error::{Error, Result};
use crate::metadata::{FileVerifier, Metadata, RoleType, Root, Targets};
use crate::paths;
use crate::pouf::Pouf;
use crate::store::MetadataStore;
use crate::transport::{ByteStream, Transport, TransportError};
use crate::trusted::{TargetInfo, TimestampUpdate, TrustedMetadata};

/// Characters escaped in role names when they are used in file names: all
/// but unreserved URL characters, so that the names are safe as both URL
/// path segments and local file names.
const ROLE_NAME: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub(super) struct Workflow<T, S> {
    pub(super) transport: T,
    pub(super) store: S,
    pub(super) config: UpdaterConfig,
}

impl<T: Transport, S: MetadataStore> Workflow<T, S> {
    /// 5.2: loads the trusted root metadata: the initial root or, without
    /// one, the root in local storage, followed by the newer root versions
    /// that earlier updates kept in local storage. Each version must be
    /// signed by the root keys of the one before it, so roots in local
    /// storage are only trusted if they descend from the initial root.
    ///
    /// The result is persisted as the root to start from without an initial
    /// root.
    pub(super) fn load_trusted_root<P: Pouf>(
        &self,
        initial_root: Option<Vec<u8>>,
    ) -> Result<Metadata<Root, P>> {
        let root_name = P::file_name(RoleType::Root.as_str());
        let stored = self.load(&root_name)?;
        let mut data = match initial_root {
            Some(data) => data,
            None => stored.clone().ok_or(Error::NoTrustedRoot)?,
        };
        // Root updates do not check expiry, so the time does not matter.
        let mut trusted = TrustedMetadata::<P>::new(&data, jiff::Timestamp::now())?;
        while let Some(version) = trusted.root().signed().version.checked_add(1)
            && let Some(next) = self.load(&format!("{version}.{root_name}"))?
        {
            if let Err(error) = trusted.update_root(&next) {
                tracing::warn!(version, %error, "ignoring root metadata in local storage");
                break;
            }
            data = next;
        }
        if stored.as_ref() != Some(&data) {
            self.persist(&root_name, &data)?;
        }
        Ok(trusted.root().clone())
    }

    /// Runs the workflow up to and including the top-level targets metadata.
    pub(super) async fn refresh<P: Pouf>(&self, trusted: &mut TrustedMetadata<P>) -> Result<()> {
        self.update_root(trusted).await?;
        self.update_timestamp(trusted).await?;
        self.update_snapshot(trusted).await?;
        let (targets, root) = (RoleType::Targets.as_str(), RoleType::Root.as_str());
        self.load_targets(trusted, targets, root).await?;
        Ok(())
    }

    /// 5.3: downloads all newer versions of root metadata, and keeps each one
    /// for [`load_trusted_root`](Self::load_trusted_root).
    async fn update_root<P: Pouf>(&self, trusted: &mut TrustedMetadata<P>) -> Result<()> {
        let root_name = P::file_name(RoleType::Root.as_str());
        for _ in 0..self.config.max_root_rotations {
            let Some(next_version) = trusted.root().signed().version.checked_add(1) else {
                return Ok(());
            };
            let name = format!("{next_version}.{root_name}");
            let data = match self
                .fetch_metadata(&name, self.config.root_max_length)
                .await
            {
                Err(Error::MetadataNotFound(_)) => return Ok(()),
                result => result?,
            };
            let old_roles = trusted.root().signed().roles.clone();
            let roles = &trusted.update_root(&data)?.signed().roles;

            // 5.3.11: after timestamp or snapshot keys are rotated, forget the
            // cached metadata of those roles, so that versions inflated by an
            // attacker who held the old keys cannot block future updates
            // (recovery from a fast-forward attack). Do it before persisting
            // the new root, from which the next update starts.
            if roles.timestamp != old_roles.timestamp || roles.snapshot != old_roles.snapshot {
                tracing::debug!(
                    "timestamp or snapshot keys changed; removing their cached metadata"
                );
                self.remove(&P::file_name(RoleType::Timestamp.as_str()))?;
                self.remove(&P::file_name(RoleType::Snapshot.as_str()))?;
            }
            self.persist(&name, &data)?;
            self.persist(&root_name, &data)?;
        }
        // Not an error: the next refresh continues from the last new root.
        tracing::debug!(
            max_root_rotations = self.config.max_root_rotations,
            "stopped updating root after the maximum number of new versions"
        );
        Ok(())
    }

    /// 5.4: timestamp metadata is always downloaded.
    async fn update_timestamp<P: Pouf>(&self, trusted: &mut TrustedMetadata<P>) -> Result<()> {
        let name = P::file_name(RoleType::Timestamp.as_str());
        if let Some(cached) = self.load(&name)?
            && let Err(error) = trusted.load_cached_timestamp(&cached)
        {
            tracing::debug!(name, %error, "ignoring cached metadata");
        }
        let data = self
            .fetch_metadata(&name, self.config.timestamp_max_length)
            .await?;
        if trusted.update_timestamp(&data)? == TimestampUpdate::Updated {
            self.persist(&name, &data)?;
        }
        Ok(())
    }

    /// 5.5: snapshot metadata is downloaded unless the cached copy is current.
    async fn update_snapshot<P: Pouf>(&self, trusted: &mut TrustedMetadata<P>) -> Result<()> {
        let name = P::file_name(RoleType::Snapshot.as_str());
        if let Some(cached) = self.load(&name)? {
            match trusted.load_cached_snapshot(&cached) {
                Ok(true) => {
                    tracing::debug!(name, "using cached metadata");
                    return Ok(());
                }
                Ok(false) => {}
                Err(error) => tracing::debug!(name, %error, "ignoring cached metadata"),
            }
        }
        let meta = trusted
            .snapshot_meta()
            .ok_or(Error::InvalidState("timestamp is not loaded"))?;
        let remote_name = remote_metadata_name(trusted.root(), &name, meta.version);
        let max_length = meta.length.unwrap_or(self.config.snapshot_max_length);
        let data = self.fetch_metadata(&remote_name, max_length).await?;
        trusted.update_snapshot(&data)?;
        self.persist(&name, &data)
    }

    /// 5.6: returns the trusted targets metadata of `role`, as delegated by
    /// `delegator`, loading it from the cache or the remote repository if it
    /// is not trusted yet.
    pub(super) async fn load_targets<'t, P: Pouf>(
        &self,
        trusted: &'t mut TrustedMetadata<P>,
        role: &str,
        delegator: &str,
    ) -> Result<&'t Metadata<Targets, P>> {
        // Metadata loaded earlier, possibly through another delegation, must
        // also satisfy this one.
        if trusted.delegated_targets(role, delegator)?.is_none() {
            self.update_targets(trusted, role, delegator).await?;
        }
        Ok(trusted
            .targets_role(role)
            .expect("targets metadata was just loaded"))
    }

    async fn update_targets<P: Pouf>(
        &self,
        trusted: &mut TrustedMetadata<P>,
        role: &str,
        delegator: &str,
    ) -> Result<()> {
        let name = P::file_name(&utf8_percent_encode(role, ROLE_NAME).to_string());
        if let Some(cached) = self.load(&name)? {
            match trusted.update_delegated_targets(&cached, role, delegator) {
                Ok(_) => {
                    tracing::debug!(name, "using cached metadata");
                    return Ok(());
                }
                Err(error) => tracing::debug!(name, %error, "ignoring cached metadata"),
            }
        }
        let meta = trusted
            .targets_meta(role)
            .ok_or_else(|| Error::NotInSnapshot(P::file_name(role)))?;
        let remote_name = remote_metadata_name(trusted.root(), &name, meta.version);
        let max_length = meta.length.unwrap_or(self.config.targets_max_length);
        let data = self.fetch_metadata(&remote_name, max_length).await?;
        trusted.update_delegated_targets(&data, role, delegator)?;
        self.persist(&name, &data)
    }

    /// 5.7: downloads a target, feeding verified-so-far chunks to `sink`.
    /// The data must not be used unless this returns `Ok`.
    #[tracing::instrument(skip_all, fields(path = target.path))]
    pub(super) async fn download_target<P: Pouf>(
        &self,
        root: &Metadata<Root, P>,
        target: &TargetInfo,
        sink: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> Result<()> {
        let verifier = FileVerifier::for_target(&target.path, &target.file)?;
        // Whatever the transport, the path must be a relative file path. The
        // hash prefix below cannot make it unsafe.
        if paths::relative_path(&target.path).is_none() {
            return Err(Error::UnsafePath(target.path.clone()));
        }
        let remote_path =
            if root.signed().uses_consistent_snapshots() && self.config.prefix_targets_with_hash {
                let digest = target
                    .file
                    .hashes
                    .preferred()
                    .expect("the verifier requires a supported hash");
                match target.path.rsplit_once('/') {
                    Some((dir, file_name)) => format!("{dir}/{digest}.{file_name}"),
                    None => format!("{digest}.{}", target.path),
                }
            } else {
                target.path.clone()
            };
        tracing::debug!(remote_path, "fetching target");
        let fetched = self
            .transport
            .fetch_target(&remote_path, target.file.length)
            .await;
        let stream = match fetched {
            Err(TransportError::NotFound) => {
                return Err(Error::TargetNotFound(target.path.clone()));
            }
            result => result.map_err(|error| verifier.fetch_error(error))?,
        };
        drain(stream, verifier, sink).await
    }

    async fn fetch_metadata(&self, name: &str, max_length: u64) -> Result<Vec<u8>> {
        tracing::debug!(name, "fetching metadata");
        let verifier = FileVerifier::new(name, max_length);
        let stream = match self.transport.fetch_metadata(name, max_length).await {
            Err(TransportError::NotFound) => return Err(Error::MetadataNotFound(name.to_owned())),
            result => result.map_err(|error| verifier.fetch_error(error))?,
        };
        let mut data = Vec::new();
        drain(stream, verifier, |chunk| {
            data.extend_from_slice(chunk);
            Ok(())
        })
        .await?;
        Ok(data)
    }

    pub(super) fn load(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.store
            .load(name)
            .map_err(|source| store_error(name, source))
    }

    pub(super) fn persist(&self, name: &str, data: &[u8]) -> Result<()> {
        self.store
            .store(name, data)
            .map_err(|source| store_error(name, source))
    }

    fn remove(&self, name: &str) -> Result<()> {
        self.store
            .remove(name)
            .map_err(|source| store_error(name, source))
    }
}

/// The name of a metadata file on the remote repository: with consistent
/// snapshots, prefixed with its version.
fn remote_metadata_name<P: Pouf>(root: &Metadata<Root, P>, name: &str, version: u64) -> String {
    if root.signed().uses_consistent_snapshots() {
        format!("{version}.{name}")
    } else {
        name.to_owned()
    }
}

/// Reads `stream` to the end through `verifier` into `sink`.
async fn drain(
    mut stream: ByteStream,
    mut verifier: FileVerifier,
    mut sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<()> {
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| verifier.fetch_error(error))?;
        verifier.update(&chunk)?;
        sink(&chunk)?;
    }
    verifier.finish()
}

fn store_error(name: &str, source: io::Error) -> Error {
    Error::Store {
        name: name.to_owned(),
        source,
    }
}
