//! Targets metadata (`targets.json` and delegated targets metadata).

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    FileVerifier, Hashes, Key, KeyId, Metadata, Role, RoleType, SPEC_VERSION, TypeField,
    UnrecognizedFields, Value, datetime, invalid, pattern, validate_common, validate_role_keys,
};
use crate::crypto::HashAlgorithm;
use crate::error::{Error, Result};
use crate::pouf::Pouf;

/// The signed payload of targets metadata, used by both the top-level
/// targets role and delegated roles. It lists target files and may delegate
/// trust for some of them to other roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Targets {
    #[serde(rename = "_type")]
    type_field: TypeField<Targets>,
    pub spec_version: String,
    pub version: u64,
    #[serde(with = "datetime")]
    pub expires: DateTime<Utc>,
    /// Target files, keyed by target path.
    pub targets: BTreeMap<String, TargetFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegations: Option<Delegations>,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

/// Describes a target file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetFile {
    pub length: u64,
    pub hashes: Hashes,
    /// Application-specific information about the file, opaque to TUF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<Value>,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

/// The roles a targets role delegates to, and their keys.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Delegations {
    pub keys: BTreeMap<KeyId, Key>,
    /// Delegated roles in order of priority: earlier roles are trusted over
    /// later ones.
    pub roles: Vec<DelegatedRole>,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

/// A delegation to a role.
///
/// The paths the role is trusted for are given either by `paths` or by
/// `path_hash_prefixes`. If neither is set, the role is trusted for nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedRole {
    pub name: String,
    pub keyids: Vec<KeyId>,
    pub threshold: u64,
    /// If set, a target matching this delegation is never looked up in
    /// delegations of lower priority.
    pub terminating: bool,
    /// Shell-style patterns of the target paths the role is trusted for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Hex prefixes of the SHA-256 digests of the target paths the role is
    /// trusted for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_hash_prefixes: Option<Vec<String>>,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

impl Targets {
    /// Creates version 1 of targets metadata, listing no targets.
    pub fn new(expires: DateTime<Utc>) -> Self {
        Targets {
            type_field: TypeField::default(),
            spec_version: SPEC_VERSION.to_owned(),
            version: 1,
            expires,
            targets: BTreeMap::new(),
            delegations: None,
            unrecognized_fields: BTreeMap::new(),
        }
    }

    /// The delegation to the role called `name`, if any.
    pub fn delegated_role(&self, name: &str) -> Option<&DelegatedRole> {
        self.delegations
            .as_ref()?
            .roles
            .iter()
            .find(|role| role.name == name)
    }

    /// Verifies that `metadata` is signed by a threshold of the keys this
    /// role delegates the role called `role` to.
    pub fn verify_delegate<P: Pouf>(
        &self,
        role: &str,
        metadata: &Metadata<Targets, P>,
    ) -> Result<()> {
        let (Some(delegations), Some(delegated)) = (&self.delegations, self.delegated_role(role))
        else {
            return Err(Error::UnknownDelegation(role.to_owned()));
        };
        metadata.verify_signatures(
            role,
            &delegations.keys,
            &delegated.keyids,
            delegated.threshold,
        )
    }
}

impl TargetFile {
    /// Describes `data` by its length and hashes.
    pub fn from_bytes(data: &[u8], algorithms: &[HashAlgorithm]) -> Self {
        TargetFile {
            length: data.len() as u64,
            hashes: Hashes::compute(data, algorithms),
            custom: None,
            unrecognized_fields: BTreeMap::new(),
        }
    }

    /// Checks `data` against this description. `name` identifies the file in
    /// errors.
    pub fn verify(&self, name: &str, data: &[u8]) -> Result<()> {
        FileVerifier::for_target(name, self)?.verify(data)
    }
}

impl Delegations {
    pub fn new() -> Self {
        Delegations::default()
    }

    /// The roles trusted for `target_path`, in order of priority.
    pub fn roles_for_target<'a>(
        &'a self,
        target_path: &'a str,
    ) -> impl Iterator<Item = &'a DelegatedRole> + 'a {
        self.roles
            .iter()
            .filter(move |role| role.is_delegated_path(target_path))
    }

    fn validate(&self) -> Result<()> {
        let mut names = HashSet::new();
        for role in &self.roles {
            if role.name.is_empty() || collides_with_top_level(&role.name) {
                return Err(invalid(format!(
                    "invalid delegated role name {:?}",
                    role.name
                )));
            }
            if !names.insert(role.name.as_str()) {
                return Err(invalid(format!(
                    "role {:?} is delegated more than once",
                    role.name
                )));
            }
            if role.paths.is_some() && role.path_hash_prefixes.is_some() {
                return Err(invalid(format!(
                    "delegation to {:?} sets both paths and path_hash_prefixes",
                    role.name
                )));
            }
            validate_role_keys(&role.name, &role.keyids, role.threshold)?;
        }
        Ok(())
    }
}

/// Whether a delegated role called `name` would be stored like top-level
/// metadata (`timestamp.json`) or a version of root metadata
/// (`2.root.json`), ignoring case as case-insensitive filesystems do.
/// Clients store a role's metadata under its name, so such a role could
/// overwrite the metadata they trust.
fn collides_with_top_level(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let root_version = name.strip_suffix(".root").is_some_and(|version| {
        !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
    });
    RoleType::is_top_level(&name) || root_version
}

impl DelegatedRole {
    /// Creates a non-terminating delegation that is not yet trusted for any
    /// paths.
    pub fn new(name: impl Into<String>, keyids: Vec<KeyId>, threshold: u64) -> Self {
        DelegatedRole {
            name: name.into(),
            keyids,
            threshold,
            terminating: false,
            paths: None,
            path_hash_prefixes: None,
            unrecognized_fields: BTreeMap::new(),
        }
    }

    /// Whether the role is trusted for `target_path`.
    pub fn is_delegated_path(&self, target_path: &str) -> bool {
        if let Some(patterns) = &self.paths {
            return patterns
                .iter()
                .any(|pattern| pattern::matches_path(pattern, target_path));
        }
        if let Some(prefixes) = &self.path_hash_prefixes {
            let digest = hex::encode(HashAlgorithm::Sha256.digest(target_path.as_bytes()));
            return prefixes
                .iter()
                .any(|prefix| digest.starts_with(prefix.as_str()));
        }
        false
    }
}

impl Role for Targets {
    const TYPE: RoleType = RoleType::Targets;

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
        if let Some((path, _)) = self.targets.iter().find(|(_, file)| file.hashes.is_empty()) {
            return Err(invalid(format!(
                "hashes of target {path:?} must not be empty"
            )));
        }
        match &self.delegations {
            Some(delegations) => delegations.validate(),
            None => Ok(()),
        }
    }
}
