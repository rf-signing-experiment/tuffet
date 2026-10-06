//! Timestamp metadata (`timestamp.json`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    MetaFile, Role, RoleType, SPEC_VERSION, TypeField, UnrecognizedFields, datetime, invalid,
    validate_common,
};
use crate::error::Result;
use crate::pouf::Pouf;

/// The signed payload of timestamp metadata, which identifies the current
/// snapshot metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    #[serde(rename = "_type")]
    type_field: TypeField<Timestamp>,
    pub spec_version: String,
    pub version: u64,
    #[serde(with = "datetime")]
    pub expires: jiff::Timestamp,
    /// Lists exactly one file: the snapshot metadata (e.g. `snapshot.json`).
    pub meta: BTreeMap<String, MetaFile>,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

impl Timestamp {
    /// Creates version 1 of timestamp metadata. Its `meta` is empty and must
    /// be given an entry for the snapshot metadata before it is valid.
    pub fn new(expires: jiff::Timestamp) -> Self {
        Timestamp {
            type_field: TypeField::default(),
            spec_version: SPEC_VERSION.to_owned(),
            version: 1,
            expires,
            meta: BTreeMap::new(),
            unrecognized_fields: BTreeMap::new(),
        }
    }
}

impl Role for Timestamp {
    const TYPE: RoleType = RoleType::Timestamp;

    fn spec_version(&self) -> &str {
        &self.spec_version
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn expires(&self) -> jiff::Timestamp {
        self.expires
    }

    fn validate<P: Pouf>(&self) -> Result<()> {
        validate_common(self)?;
        let snapshot = P::file_name(RoleType::Snapshot.as_str());
        if self.meta.len() != 1 || !self.meta.contains_key(&snapshot) {
            return Err(invalid(format!(
                "timestamp meta must list exactly {snapshot}"
            )));
        }
        self.meta
            .iter()
            .try_for_each(|(name, meta)| meta.validate(name))
    }
}
