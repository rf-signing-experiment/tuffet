//! Root metadata (`root.json`).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    Key, KeyId, Metadata, Role, RoleType, SPEC_VERSION, TypeField, UnrecognizedFields, datetime,
    validate_common, validate_role_keys,
};
use crate::error::Result;
use crate::pouf::Pouf;

/// The signed payload of root metadata, which lists the keys trusted for
/// each top-level role (including root itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    #[serde(rename = "_type")]
    type_field: TypeField<Root>,
    pub spec_version: String,
    /// Whether the repository uses consistent snapshots. Absent in some old
    /// metadata, which is equivalent to `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistent_snapshot: Option<bool>,
    pub version: u64,
    #[serde(with = "datetime")]
    pub expires: DateTime<Utc>,
    pub keys: BTreeMap<KeyId, Key>,
    pub roles: RootRoles,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

/// The keys trusted for each top-level role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRoles {
    pub root: RoleKeys,
    pub snapshot: RoleKeys,
    pub targets: RoleKeys,
    pub timestamp: RoleKeys,
    /// Other roles, such as the unsupported "mirrors" role. Preserved, but
    /// otherwise ignored.
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

/// The keys authorized to sign for a role, and how many of them must sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleKeys {
    pub keyids: Vec<KeyId>,
    pub threshold: u64,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

impl RoleKeys {
    pub fn new(keyids: Vec<KeyId>, threshold: u64) -> Self {
        RoleKeys {
            keyids,
            threshold,
            unrecognized_fields: BTreeMap::new(),
        }
    }
}

impl RootRoles {
    pub fn get(&self, role: RoleType) -> &RoleKeys {
        match role {
            RoleType::Root => &self.root,
            RoleType::Timestamp => &self.timestamp,
            RoleType::Snapshot => &self.snapshot,
            RoleType::Targets => &self.targets,
        }
    }

    pub fn get_mut(&mut self, role: RoleType) -> &mut RoleKeys {
        match role {
            RoleType::Root => &mut self.root,
            RoleType::Timestamp => &mut self.timestamp,
            RoleType::Snapshot => &mut self.snapshot,
            RoleType::Targets => &mut self.targets,
        }
    }
}

impl Root {
    /// Creates version 1 of root metadata with consistent snapshots enabled
    /// and no keys. Every role has a threshold of 1.
    pub fn new(expires: DateTime<Utc>) -> Self {
        let no_keys = || RoleKeys::new(Vec::new(), 1);
        Root {
            type_field: TypeField::default(),
            spec_version: SPEC_VERSION.to_owned(),
            consistent_snapshot: Some(true),
            version: 1,
            expires,
            keys: BTreeMap::new(),
            roles: RootRoles {
                root: no_keys(),
                snapshot: no_keys(),
                targets: no_keys(),
                timestamp: no_keys(),
                unrecognized_fields: BTreeMap::new(),
            },
            unrecognized_fields: BTreeMap::new(),
        }
    }

    /// Whether the repository uses consistent snapshots.
    pub fn uses_consistent_snapshots(&self) -> bool {
        self.consistent_snapshot.unwrap_or(false)
    }

    /// Authorizes `key` (whose key ID is `keyid`) to sign for `role`.
    pub fn add_key(&mut self, role: RoleType, keyid: KeyId, key: Key) {
        let role_keys = self.roles.get_mut(role);
        if !role_keys.keyids.contains(&keyid) {
            role_keys.keyids.push(keyid.clone());
        }
        self.keys.insert(keyid, key);
    }

    /// Verifies that `metadata` is signed by a threshold of the keys this
    /// root trusts for the metadata's role.
    pub fn verify_role<R: Role, P: Pouf>(&self, metadata: &Metadata<R, P>) -> Result<()> {
        let role_keys = self.roles.get(R::TYPE);
        metadata.verify_signatures(
            R::TYPE.as_str(),
            &self.keys,
            &role_keys.keyids,
            role_keys.threshold,
        )
    }
}

impl Role for Root {
    const TYPE: RoleType = RoleType::Root;

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
        for role in [
            RoleType::Root,
            RoleType::Timestamp,
            RoleType::Snapshot,
            RoleType::Targets,
        ] {
            let role_keys = self.roles.get(role);
            validate_role_keys(role.as_str(), &role_keys.keyids, role_keys.threshold)?;
        }
        Ok(())
    }
}
