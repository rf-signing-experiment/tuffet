//! TUF metadata: the formats of the four top-level roles, and signing and
//! verification of individual metadata files.
//!
//! This is the lowest layer of the crate. It knows nothing about the update
//! workflow (see [`trusted`](crate::trusted) and [`updater`](crate::updater)
//! for that), so it is also what repository tooling uses to *create*
//! metadata: build a role payload such as [`Targets`], wrap it in
//! [`Metadata`], [sign](Metadata::sign) it and [encode](Metadata::to_bytes) it.
//!
//! Fields this implementation does not know are kept in each object's
//! `unrecognized_fields`, so that they survive re-encoding as the
//! specification requires.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};
use crate::pouf::Pouf;

mod datetime;
mod envelope;
mod hashes;
mod hex;
mod key;
mod pattern;
mod root;
mod snapshot;
mod targets;
mod timestamp;

pub use envelope::{Metadata, Signature};
pub use hashes::{FileVerifier, Hashes};
pub use hex::HexBytes;
pub use key::{Key, KeyId, KeyType, KeyVal, SignatureScheme};
pub use root::{RoleKeys, Root, RootRoles};
pub use serde_json::Value;
pub use snapshot::{MetaFile, Snapshot};
pub use targets::{DelegatedRole, Delegations, TargetFile, Targets};
pub use timestamp::Timestamp;

/// The specification version this implementation follows. New metadata is
/// written with this version, and metadata with a different major version is
/// rejected.
pub const SPEC_VERSION: &str = "1.0.36";

/// Fields of a metadata object that this implementation does not recognize.
pub type UnrecognizedFields = BTreeMap<String, Value>;

/// The top-level roles.
///
/// The optional "mirrors" role is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleType {
    Root,
    Timestamp,
    Snapshot,
    Targets,
}

impl RoleType {
    /// The role's name, which is also the `_type` of its metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            RoleType::Root => "root",
            RoleType::Timestamp => "timestamp",
            RoleType::Snapshot => "snapshot",
            RoleType::Targets => "targets",
        }
    }

    /// Whether `name` is one of the top-level role names.
    pub fn is_top_level(name: &str) -> bool {
        ["root", "timestamp", "snapshot", "targets"].contains(&name)
    }
}

impl fmt::Display for RoleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The signed payload of a role's metadata: [`Root`], [`Timestamp`],
/// [`Snapshot`] or [`Targets`] (which is also used by delegated roles).
pub trait Role: Serialize + DeserializeOwned + Clone + fmt::Debug {
    /// The role's type, which is also the value of the `_type` field.
    const TYPE: RoleType;

    fn spec_version(&self) -> &str;

    fn version(&self) -> u64;

    fn expires(&self) -> DateTime<Utc>;

    /// Whether the metadata is expired at `time`. Metadata is only valid
    /// while its expiration time is *later* than the reference time.
    fn is_expired(&self, time: DateTime<Utc>) -> bool {
        self.expires() <= time
    }

    /// Checks the rules of the specification that the Rust types cannot
    /// express. Called whenever metadata is decoded or wrapped for signing,
    /// so a [`Metadata`] always holds a valid payload.
    fn validate<P: Pouf>(&self) -> Result<()>;
}

/// The `_type` field of a role payload.
///
/// It encodes as the role's type and refuses to decode anything else, so that
/// metadata of one role can never be mistaken for another.
pub(crate) struct TypeField<R>(PhantomData<fn() -> R>);

impl<R> Default for TypeField<R> {
    fn default() -> Self {
        TypeField(PhantomData)
    }
}

impl<R> Clone for TypeField<R> {
    fn clone(&self) -> Self {
        TypeField::default()
    }
}

impl<R> PartialEq for TypeField<R> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<R> Eq for TypeField<R> {}

impl<R> fmt::Debug for TypeField<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TypeField")
    }
}

impl<R: Role> Serialize for TypeField<R> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(R::TYPE.as_str())
    }
}

impl<'de, R: Role> Deserialize<'de> for TypeField<R> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let found = std::borrow::Cow::<str>::deserialize(deserializer)?;
        if found != R::TYPE.as_str() {
            return Err(D::Error::custom(format!(
                "expected _type {:?}, found {found:?}",
                R::TYPE.as_str()
            )));
        }
        Ok(TypeField::default())
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidMetadata(message.into())
}

/// Validates the fields common to all roles.
fn validate_common<R: Role>(role: &R) -> Result<()> {
    validate_spec_version(role.spec_version())?;
    if role.version() == 0 {
        return Err(invalid(format!(
            "{} version must be greater than 0",
            R::TYPE
        )));
    }
    Ok(())
}

/// Accepts `MAJOR.MINOR` or `MAJOR.MINOR.PATCH` with the supported major version.
fn validate_spec_version(spec_version: &str) -> Result<()> {
    let parts: Vec<&str> = spec_version.split('.').collect();
    let well_formed = matches!(parts.len(), 2 | 3)
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if !well_formed {
        return Err(invalid(format!("malformed spec_version {spec_version:?}")));
    }
    let supported_major = SPEC_VERSION.split('.').next();
    if Some(parts[0]) != supported_major {
        return Err(invalid(format!(
            "unsupported spec_version {spec_version:?}"
        )));
    }
    Ok(())
}

/// Validates a set of keys authorized for a role.
fn validate_role_keys(role: &str, keyids: &[KeyId], threshold: u64) -> Result<()> {
    if threshold == 0 {
        return Err(invalid(format!(
            "threshold of role {role:?} must be at least 1"
        )));
    }
    let mut seen = HashSet::new();
    if let Some(duplicate) = keyids.iter().find(|id| !seen.insert(*id)) {
        return Err(invalid(format!(
            "role {role:?} lists key {duplicate} more than once"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
