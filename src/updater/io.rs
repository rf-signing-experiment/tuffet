//! The updater's I/O: fetching metadata and targets, and the local cache.

use std::io;

use futures_util::StreamExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use super::UpdaterConfig;
use crate::error::{Error, Result};
use crate::metadata::{FileVerifier, Metadata, RoleType, Root, Targets};
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

pub(super) struct Io<T, S> {
    pub(super) transport: T,
    pub(super) store: S,
    pub(super) config: UpdaterConfig,
}

impl<T: Transport, S: MetadataStore> Io<T, S> {
    /// Runs the workflow up to and including the top-level targets metadata.
    pub(super) async fn refresh<P: Pouf>(&self, trusted: &mut TrustedMetadata<P>) -> Result<()> {
        self.update_root(trusted).await?;
        self.update_timestamp(trusted).await?;
        self.update_snapshot(trusted).await?;
        let (targets, root) = (RoleType::Targets.as_str(), RoleType::Root.as_str());
        self.load_targets(trusted, targets, root).await?;
        Ok(())
    }

    /// 5.3: walks through all newer versions of root metadata.
    async fn update_root<P: Pouf>(&self, trusted: &mut TrustedMetadata<P>) -> Result<()> {
        let root_name = P::file_name(RoleType::Root.as_str());
        let initial_roles = trusted.root().signed().roles.clone();
        for _ in 0..self.config.max_root_rotations {
            let Some(next_version) = trusted.root().signed().version.checked_add(1) else {
                break;
            };
            let name = format!("{next_version}.{root_name}");
            let data = match self
                .fetch_metadata(&name, self.config.root_max_length)
                .await
            {
                Err(Error::Transport(TransportError::NotFound(_))) => break,
                result => result?,
            };
            trusted.update_root(&data)?;
            self.persist(&root_name, &data)?;
        }

        // 5.3.11: after timestamp or snapshot keys are rotated, forget the
        // cached metadata of those roles, so that versions inflated by an
        // attacker who held the old keys cannot block future updates
        // (recovery from a fast-forward attack).
        let roles = &trusted.root().signed().roles;
        if roles.timestamp != initial_roles.timestamp || roles.snapshot != initial_roles.snapshot {
            self.remove(&P::file_name(RoleType::Timestamp.as_str()))?;
            self.remove(&P::file_name(RoleType::Snapshot.as_str()))?;
        }
        Ok(())
    }

    /// 5.4: timestamp metadata is always downloaded.
    async fn update_timestamp<P: Pouf>(&self, trusted: &mut TrustedMetadata<P>) -> Result<()> {
        let name = P::file_name(RoleType::Timestamp.as_str());
        if let Some(cached) = self.load(&name)?
            && let Err(error) = trusted.load_cached_timestamp(&cached)
        {
            log::debug!("ignoring cached {name}: {error}");
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
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) => log::debug!("ignoring cached {name}: {error}"),
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

    /// 5.6: returns the trusted targets metadata of `role`, loading it from
    /// the cache or the remote repository if it is not trusted yet.
    pub(super) async fn load_targets<'t, P: Pouf>(
        &self,
        trusted: &'t mut TrustedMetadata<P>,
        role: &str,
        delegator: &str,
    ) -> Result<&'t Metadata<Targets, P>> {
        if trusted.targets_role(role).is_none() {
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
                Ok(_) => return Ok(()),
                Err(error) => log::debug!("ignoring cached {name}: {error}"),
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
    pub(super) async fn download_target<P: Pouf>(
        &self,
        root: &Metadata<Root, P>,
        target: &TargetInfo,
        sink: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> Result<()> {
        let verifier = FileVerifier::for_target(&target.path, &target.file)?;
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
        let stream = self.transport.fetch_target(&remote_path).await?;
        drain(stream, verifier, sink).await
    }

    async fn fetch_metadata(&self, name: &str, max_length: u64) -> Result<Vec<u8>> {
        let stream = self.transport.fetch_metadata(name).await?;
        let mut data = Vec::new();
        drain(stream, FileVerifier::new(name, max_length), |chunk| {
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
        let chunk = chunk?;
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
