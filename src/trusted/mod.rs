//! The client workflow's verification rules, without any I/O.
//!
//! [`TrustedMetadata`] holds the metadata a client currently trusts and checks
//! each new metadata file against it, following the specification's
//! "Detailed client workflow". It never fetches or stores anything: the caller
//! feeds it bytes, from the remote repository or from a local cache, in the
//! order the workflow requires:
//!
//! 1. [`TrustedMetadata::new`] with the trusted root metadata;
//! 2. [`update_root`](TrustedMetadata::update_root) with each newer root
//!    version, until there is none;
//! 3. optionally [`load_cached_timestamp`](TrustedMetadata::load_cached_timestamp),
//!    then [`update_timestamp`](TrustedMetadata::update_timestamp);
//! 4. optionally [`load_cached_snapshot`](TrustedMetadata::load_cached_snapshot),
//!    then, unless the cached snapshot is current,
//!    [`update_snapshot`](TrustedMetadata::update_snapshot);
//! 5. [`update_targets`](TrustedMetadata::update_targets), then
//!    [`update_delegated_targets`](TrustedMetadata::update_delegated_targets)
//!    for the delegated roles a [`TargetSearch`] asks for.
//!
//! Any error aborts the update. Calls made out of order fail with
//! [`Error::InvalidState`]. The [`Updater`](crate::updater::Updater) is the
//! standard driver of this state machine; use it directly to supply your own
//! I/O.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::error::{Error, Result};
use crate::metadata::{MetaFile, Metadata, Role, RoleType, Root, Snapshot, Targets, Timestamp};
use crate::pouf::{Json, Pouf};

mod search;

pub use search::{SearchStep, TargetInfo, TargetSearch};

/// Metadata trusted during one run of the client workflow.
///
/// All expiry checks use the fixed reference time given at creation (the
/// "update start time").
#[derive(Debug, Clone)]
pub struct TrustedMetadata<P: Pouf = Json> {
    reference_time: DateTime<Utc>,
    root: Metadata<Root, P>,
    timestamp: Option<Metadata<Timestamp, P>>,
    snapshot: Option<Metadata<Snapshot, P>>,
    /// The top-level targets role and delegated roles, by role name.
    targets: HashMap<String, Metadata<Targets, P>>,
}

/// The outcome of [`TrustedMetadata::update_timestamp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampUpdate {
    /// The new timestamp metadata is newer and is now trusted; persist it.
    Updated,
    /// The new timestamp metadata has the same version as the trusted one,
    /// which remains trusted: the repository has not changed.
    Unchanged,
}

impl<P: Pouf> TrustedMetadata<P> {
    /// Starts from trusted root metadata: either the root shipped with the
    /// application, or the root persisted by an earlier update (5.2).
    ///
    /// The root must be signed by a threshold of its own root keys. Its
    /// expiry is not checked yet, because a newer root may replace it.
    pub fn new(root: &[u8], reference_time: DateTime<Utc>) -> Result<Self> {
        Self::from_root(Metadata::from_bytes(root)?, reference_time)
    }

    /// Like [`new`](Self::new), for root metadata that is already decoded.
    pub fn from_root(root: Metadata<Root, P>, reference_time: DateTime<Utc>) -> Result<Self> {
        root.signed().verify_role(&root)?;
        Ok(TrustedMetadata {
            reference_time,
            root,
            timestamp: None,
            snapshot: None,
            targets: HashMap::new(),
        })
    }

    /// The fixed time against which expiry is checked.
    pub fn reference_time(&self) -> DateTime<Utc> {
        self.reference_time
    }

    pub fn root(&self) -> &Metadata<Root, P> {
        &self.root
    }

    pub fn timestamp(&self) -> Option<&Metadata<Timestamp, P>> {
        self.timestamp.as_ref()
    }

    pub fn snapshot(&self) -> Option<&Metadata<Snapshot, P>> {
        self.snapshot.as_ref()
    }

    /// The top-level targets metadata.
    pub fn targets(&self) -> Option<&Metadata<Targets, P>> {
        self.targets_role(RoleType::Targets.as_str())
    }

    /// The metadata of the top-level targets role or of a delegated role.
    pub fn targets_role(&self, role: &str) -> Option<&Metadata<Targets, P>> {
        self.targets.get(role)
    }

    /// What the trusted timestamp metadata says about the snapshot metadata:
    /// the version to download next and, possibly, its length and hashes.
    pub fn snapshot_meta(&self) -> Option<&MetaFile> {
        self.timestamp.as_ref().map(Self::snapshot_meta_of)
    }

    /// What the trusted snapshot metadata says about the targets metadata of
    /// `role`: the version to download next and, possibly, its length and
    /// hashes.
    pub fn targets_meta(&self, role: &str) -> Option<&MetaFile> {
        self.snapshot
            .as_ref()?
            .signed()
            .meta
            .get(&P::file_name(role))
    }

    /// Updates the root metadata to the next version (5.3.4–5.3.7).
    ///
    /// The new root must be signed by a threshold of the keys of both the
    /// trusted root and the new root itself, and its version must be exactly
    /// one more than the trusted version. Its expiry is checked later, when
    /// timestamp metadata is loaded, because yet another root may replace it.
    pub fn update_root(&mut self, data: &[u8]) -> Result<&Metadata<Root, P>> {
        if self.timestamp.is_some() {
            return Err(Error::InvalidState(
                "root cannot be updated once timestamp is loaded",
            ));
        }
        let new_root = Metadata::<Root, P>::from_bytes(data)?;
        self.root.signed().verify_role(&new_root)?;
        new_root.signed().verify_role(&new_root)?;

        let trusted_version = self.root.signed().version;
        let new_version = new_root.signed().version;
        if new_version.checked_sub(1) != Some(trusted_version) {
            return Err(Error::VersionMismatch {
                role: RoleType::Root.to_string(),
                expected: trusted_version.saturating_add(1),
                actual: new_version,
            });
        }
        self.root = new_root;
        Ok(&self.root)
    }

    /// Loads timestamp metadata from the local cache.
    ///
    /// Cached metadata is only re-checked for signatures, against the current
    /// root (which may have rotated keys). It may be expired: it still serves
    /// as the baseline for rollback checks in
    /// [`update_timestamp`](Self::update_timestamp). If loading fails, the
    /// cache should simply be ignored.
    pub fn load_cached_timestamp(&mut self, data: &[u8]) -> Result<()> {
        if self.timestamp.is_some() {
            return Err(Error::InvalidState("timestamp is already loaded"));
        }
        let timestamp = Metadata::from_bytes(data)?;
        self.root.signed().verify_role(&timestamp)?;
        self.timestamp = Some(timestamp);
        Ok(())
    }

    /// Updates timestamp metadata with newly downloaded data (5.3.10,
    /// 5.4.2–5.4.4).
    ///
    /// First checks that the final root metadata has not expired. Then the
    /// new timestamp must be signed by the root's timestamp keys, must not
    /// roll back the timestamp or snapshot version of the trusted timestamp,
    /// and must not be expired.
    pub fn update_timestamp(&mut self, data: &[u8]) -> Result<TimestampUpdate> {
        if self.snapshot.is_some() {
            return Err(Error::InvalidState(
                "timestamp cannot be updated once snapshot is loaded",
            ));
        }
        check_expiry(
            RoleType::Root.as_str(),
            self.root.signed(),
            self.reference_time,
        )?;
        let new_timestamp = Metadata::<Timestamp, P>::from_bytes(data)?;
        self.root.signed().verify_role(&new_timestamp)?;

        if let Some(trusted) = &self.timestamp {
            let (trusted_version, new_version) =
                (trusted.signed().version, new_timestamp.signed().version);
            if new_version < trusted_version {
                return Err(rollback(
                    RoleType::Timestamp.as_str(),
                    trusted_version,
                    new_version,
                ));
            }
            if new_version == trusted_version {
                // Keep the trusted copy, but only if it is still valid.
                check_expiry(
                    RoleType::Timestamp.as_str(),
                    trusted.signed(),
                    self.reference_time,
                )?;
                return Ok(TimestampUpdate::Unchanged);
            }
            let trusted_snapshot = Self::snapshot_meta_of(trusted).version;
            let new_snapshot = Self::snapshot_meta_of(&new_timestamp).version;
            if new_snapshot < trusted_snapshot {
                return Err(rollback(
                    RoleType::Snapshot.as_str(),
                    trusted_snapshot,
                    new_snapshot,
                ));
            }
        }
        check_expiry(
            RoleType::Timestamp.as_str(),
            new_timestamp.signed(),
            self.reference_time,
        )?;
        self.timestamp = Some(new_timestamp);
        Ok(TimestampUpdate::Updated)
    }

    /// Loads snapshot metadata from the local cache.
    ///
    /// As with [`load_cached_timestamp`](Self::load_cached_timestamp), only
    /// signatures are re-checked, and the snapshot becomes the baseline for
    /// rollback checks. Returns whether it is also *current* (unexpired and
    /// at the version listed in timestamp metadata), in which case no new
    /// snapshot needs to be downloaded.
    pub fn load_cached_snapshot(&mut self, data: &[u8]) -> Result<bool> {
        if self.snapshot.is_some() {
            return Err(Error::InvalidState("snapshot is already loaded"));
        }
        self.final_timestamp()?;
        let snapshot = Metadata::from_bytes(data)?;
        self.root.signed().verify_role(&snapshot)?;
        self.snapshot = Some(snapshot);
        Ok(self.final_snapshot().is_ok())
    }

    /// Updates snapshot metadata with newly downloaded data (5.5.2–5.5.6).
    ///
    /// The data must match the length and hashes listed in timestamp
    /// metadata, be signed by the root's snapshot keys, have the version
    /// listed in timestamp metadata, not be expired, and not remove or roll
    /// back any targets metadata listed by the trusted snapshot.
    pub fn update_snapshot(&mut self, data: &[u8]) -> Result<()> {
        if !self.targets.is_empty() {
            return Err(Error::InvalidState(
                "snapshot cannot be updated once targets are loaded",
            ));
        }
        let meta = Self::snapshot_meta_of(self.final_timestamp()?);
        meta.verify(&P::file_name(RoleType::Snapshot.as_str()), data)?;
        let expected_version = meta.version;

        let new_snapshot = Metadata::<Snapshot, P>::from_bytes(data)?;
        self.root.signed().verify_role(&new_snapshot)?;
        check_version(
            RoleType::Snapshot.as_str(),
            expected_version,
            new_snapshot.signed().version,
        )?;

        if let Some(trusted) = &self.snapshot {
            for (name, trusted_meta) in &trusted.signed().meta {
                let Some(new_meta) = new_snapshot.signed().meta.get(name) else {
                    return Err(Error::RemovedFromSnapshot(name.clone()));
                };
                if new_meta.version < trusted_meta.version {
                    return Err(rollback(name, trusted_meta.version, new_meta.version));
                }
            }
        }
        check_expiry(
            RoleType::Snapshot.as_str(),
            new_snapshot.signed(),
            self.reference_time,
        )?;
        self.snapshot = Some(new_snapshot);
        Ok(())
    }

    /// Updates the top-level targets metadata (5.6.2–5.6.5), from either the
    /// local cache or the remote repository.
    ///
    /// The data must match the length and hashes listed in snapshot metadata,
    /// be signed by the root's targets keys, have the version listed in
    /// snapshot metadata, and not be expired.
    pub fn update_targets(&mut self, data: &[u8]) -> Result<&Metadata<Targets, P>> {
        self.update_delegated_targets(data, RoleType::Targets.as_str(), RoleType::Root.as_str())
    }

    /// Updates the targets metadata of `role`, which is delegated by the
    /// already trusted targets metadata of `delegator`.
    ///
    /// The checks are those of [`update_targets`](Self::update_targets),
    /// except that the signatures must come from the keys `delegator`
    /// delegates `role` to. (With `delegator` `"root"` and `role`
    /// `"targets"`, this is `update_targets`.)
    pub fn update_delegated_targets(
        &mut self,
        data: &[u8],
        role: &str,
        delegator: &str,
    ) -> Result<&Metadata<Targets, P>> {
        let snapshot = self.final_snapshot()?;
        let name = P::file_name(role);
        let meta = snapshot
            .signed()
            .meta
            .get(&name)
            .ok_or_else(|| Error::NotInSnapshot(name.clone()))?;
        meta.verify(&name, data)?;
        let expected_version = meta.version;

        let new_targets = Metadata::<Targets, P>::from_bytes(data)?;
        if delegator == RoleType::Root.as_str() {
            if role != RoleType::Targets.as_str() {
                return Err(Error::UnknownDelegation(role.to_owned()));
            }
            self.root.signed().verify_role(&new_targets)?;
        } else {
            let parent = self.targets.get(delegator).ok_or(Error::InvalidState(
                "the delegating targets metadata is not loaded",
            ))?;
            parent.signed().verify_delegate(role, &new_targets)?;
        }
        check_version(role, expected_version, new_targets.signed().version)?;
        check_expiry(role, new_targets.signed(), self.reference_time)?;

        self.targets.insert(role.to_owned(), new_targets);
        Ok(&self.targets[role])
    }

    /// The timestamp metadata, provided it and the root are unexpired.
    fn final_timestamp(&self) -> Result<&Metadata<Timestamp, P>> {
        check_expiry(
            RoleType::Root.as_str(),
            self.root.signed(),
            self.reference_time,
        )?;
        let timestamp = self
            .timestamp
            .as_ref()
            .ok_or(Error::InvalidState("timestamp is not loaded"))?;
        check_expiry(
            RoleType::Timestamp.as_str(),
            timestamp.signed(),
            self.reference_time,
        )?;
        Ok(timestamp)
    }

    /// The snapshot metadata, provided it is unexpired, has the version
    /// listed in timestamp metadata, and the timestamp is final.
    fn final_snapshot(&self) -> Result<&Metadata<Snapshot, P>> {
        let expected_version = Self::snapshot_meta_of(self.final_timestamp()?).version;
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or(Error::InvalidState("snapshot is not loaded"))?;
        check_expiry(
            RoleType::Snapshot.as_str(),
            snapshot.signed(),
            self.reference_time,
        )?;
        check_version(
            RoleType::Snapshot.as_str(),
            expected_version,
            snapshot.signed().version,
        )?;
        Ok(snapshot)
    }

    fn snapshot_meta_of(timestamp: &Metadata<Timestamp, P>) -> &MetaFile {
        timestamp
            .signed()
            .meta
            .get(&P::file_name(RoleType::Snapshot.as_str()))
            .expect("validated timestamp metadata lists snapshot metadata")
    }
}

fn check_expiry<R: Role>(role: &str, metadata: &R, reference_time: DateTime<Utc>) -> Result<()> {
    if metadata.is_expired(reference_time) {
        return Err(Error::Expired {
            role: role.to_owned(),
            expires: metadata.expires(),
        });
    }
    Ok(())
}

fn check_version(role: &str, expected: u64, actual: u64) -> Result<()> {
    if actual != expected {
        return Err(Error::VersionMismatch {
            role: role.to_owned(),
            expected,
            actual,
        });
    }
    Ok(())
}

fn rollback(role: &str, trusted: u64, new: u64) -> Error {
    Error::Rollback {
        role: role.to_owned(),
        trusted,
        new,
    }
}
