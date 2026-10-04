//! Snapshot metadata (`snapshot.json`), and the `METAFILES` entries it shares
//! with timestamp metadata.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    FileVerifier, Hashes, Role, RoleType, SPEC_VERSION, TypeField, UnrecognizedFields, datetime,
    invalid, validate_common,
};
use crate::crypto::HashAlgorithm;
use crate::error::Result;
use crate::pouf::Pouf;

/// The signed payload of snapshot metadata, which lists the current version
/// of every targets metadata file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "_type")]
    type_field: TypeField<Snapshot>,
    pub spec_version: String,
    pub version: u64,
    #[serde(with = "datetime")]
    pub expires: DateTime<Utc>,
    /// Targets metadata files, keyed by file name (e.g. `targets.json`).
    pub meta: BTreeMap<String, MetaFile>,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

/// Describes a metadata file in snapshot or timestamp metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaFile {
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Hashes>,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

impl Snapshot {
    /// Creates version 1 of snapshot metadata, listing no files.
    pub fn new(expires: DateTime<Utc>) -> Self {
        Snapshot {
            type_field: TypeField::default(),
            spec_version: SPEC_VERSION.to_owned(),
            version: 1,
            expires,
            meta: BTreeMap::new(),
            unrecognized_fields: BTreeMap::new(),
        }
    }
}

impl MetaFile {
    /// Describes a file by version only.
    pub fn new(version: u64) -> Self {
        MetaFile {
            version,
            length: None,
            hashes: None,
            unrecognized_fields: BTreeMap::new(),
        }
    }

    /// Describes `data` by version, length and hashes.
    pub fn from_bytes(version: u64, data: &[u8], algorithms: &[HashAlgorithm]) -> Self {
        MetaFile {
            length: Some(data.len() as u64),
            hashes: Some(Hashes::compute(data, algorithms)),
            ..MetaFile::new(version)
        }
    }

    /// Checks `data` against the length and hashes listed here, if any.
    /// `name` identifies the file in errors.
    pub fn verify(&self, name: &str, data: &[u8]) -> Result<()> {
        FileVerifier::for_meta(name, self, u64::MAX)?.verify(data)
    }

    pub(super) fn validate(&self, name: &str) -> Result<()> {
        if self.version == 0 {
            return Err(invalid(format!("version of {name} must be greater than 0")));
        }
        if self.hashes.as_ref().is_some_and(Hashes::is_empty) {
            return Err(invalid(format!("hashes of {name} must not be empty")));
        }
        Ok(())
    }
}

impl Role for Snapshot {
    const TYPE: RoleType = RoleType::Snapshot;

    fn spec_version(&self) -> &str {
        &self.spec_version
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    fn validate<P: Pouf>(&self) -> Result<()> {
        validate_common(self)?;
        self.meta
            .iter()
            .try_for_each(|(name, meta)| meta.validate(name))
    }
}
