//! A TUF repository for tests, built with the public metadata API.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

use rftuf::TrustedMetadata;
use rftuf::crypto::{HashAlgorithm, PrivateKey, Signer};
use rftuf::metadata::{
    DelegatedRole, Delegations, Hashes, MetaFile, Metadata, Role, RoleType, Root, Snapshot,
    TargetFile, Targets, Timestamp,
};
use rftuf::updater::UpdaterConfig;

use super::keys::{key, key_id};
use super::{Client, RecordingTransport, far_future, now};

const TOP_LEVEL_ROLES: [RoleType; 4] = [
    RoleType::Root,
    RoleType::Timestamp,
    RoleType::Snapshot,
    RoleType::Targets,
];

/// Configures a new [`TestRepo`].
pub struct RepoBuilder {
    name: String,
    consistent_snapshot: bool,
    keys: HashMap<RoleType, (usize, u64)>,
    expires: HashMap<RoleType, jiff::Timestamp>,
    meta_lengths: bool,
    meta_hashes: bool,
}

impl RepoBuilder {
    /// Names the repository. Keys are derived from it, so repositories with
    /// different names have different keys.
    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_owned();
        self
    }

    /// Uses consistent snapshots (6.2).
    pub fn consistent_snapshots(mut self) -> Self {
        self.consistent_snapshot = true;
        self
    }

    /// Gives the top-level `role` `count` keys, `threshold` of which must
    /// sign. (The default is one key with a threshold of 1.)
    pub fn keys(mut self, role: RoleType, count: usize, threshold: u64) -> Self {
        self.keys.insert(role, (count, threshold));
        self
    }

    /// Sets when version 1 of a top-level role's metadata expires (by
    /// default, [`far_future`]).
    pub fn expires(mut self, role: RoleType, time: jiff::Timestamp) -> Self {
        self.expires.insert(role, time);
        self
    }

    /// Makes timestamp and snapshot metadata list the lengths of the files
    /// they describe (`METAFILES` `LENGTH`). By default they don't.
    pub fn meta_lengths(mut self) -> Self {
        self.meta_lengths = true;
        self
    }

    /// Makes timestamp and snapshot metadata list the SHA-256 hashes of the
    /// files they describe (`METAFILES` `HASHES`). By default they don't.
    pub fn meta_hashes(mut self) -> Self {
        self.meta_hashes = true;
        self
    }

    /// Creates the repository and publishes version 1 of every top-level
    /// role's metadata.
    pub fn build(self) -> TestRepo {
        let expires = |role| self.expires.get(&role).copied().unwrap_or_else(far_future);
        let mut root = Root::new(expires(RoleType::Root));
        root.consistent_snapshot = Some(self.consistent_snapshot);
        let mut targets = Targets::new(expires(RoleType::Targets));
        targets.version = 0;
        let mut snapshot = Snapshot::new(expires(RoleType::Snapshot));
        snapshot.version = 0;
        let mut timestamp = Timestamp::new(expires(RoleType::Timestamp));
        timestamp.version = 0;

        let mut repo = TestRepo {
            name: self.name,
            transport: Arc::new(RecordingTransport::default()),
            root,
            timestamp,
            snapshot,
            targets: BTreeMap::from([("targets".to_owned(), targets)]),
            signers: HashMap::new(),
            meta_lengths: self.meta_lengths,
            meta_hashes: self.meta_hashes,
            trusted_root_signers: Vec::new(),
            dirty: BTreeSet::from(["targets".to_owned()]),
            published: BTreeMap::new(),
            published_targets: BTreeMap::new(),
            keys_created: 0,
        };
        for role in TOP_LEVEL_ROLES {
            let (count, threshold) = self.keys.get(&role).copied().unwrap_or((1, 1));
            for _ in 0..count {
                repo.add_key(role);
            }
            repo.root.roles.get_mut(role).threshold = threshold;
        }

        let root = repo.sign("root", &repo.root);
        repo.write("1.root.json", root.clone());
        repo.write("root.json", root);
        repo.trusted_root_signers = repo.signers["root"].clone();
        repo.commit();
        repo
    }
}

/// A delegation for [`TestRepo::delegate`].
///
/// ```ignore
/// repo.delegate("targets", Delegation::to("a").paths(&["a/*"]).terminating());
/// ```
pub struct Delegation {
    name: String,
    paths: Option<Vec<String>>,
    path_hash_prefixes: Option<Vec<String>>,
    terminating: bool,
    keys: DelegationKeys,
    threshold: u64,
}

enum DelegationKeys {
    New(usize),
    Existing(Vec<Arc<PrivateKey>>),
}

impl Delegation {
    /// A non-terminating delegation to `role`, to one new key with a
    /// threshold of 1, and trusted for no paths.
    pub fn to(role: &str) -> Self {
        Delegation {
            name: role.to_owned(),
            paths: None,
            path_hash_prefixes: None,
            terminating: false,
            keys: DelegationKeys::New(1),
            threshold: 1,
        }
    }

    /// Trusts the role for the target paths that match `patterns`.
    pub fn paths(mut self, patterns: &[&str]) -> Self {
        self.paths = Some(patterns.iter().map(|p| p.to_string()).collect());
        self
    }

    /// Trusts the role for the target paths whose SHA-256 hashes start with
    /// one of `prefixes`.
    pub fn path_hash_prefixes(mut self, prefixes: &[&str]) -> Self {
        self.path_hash_prefixes = Some(prefixes.iter().map(|p| p.to_string()).collect());
        self
    }

    pub fn terminating(mut self) -> Self {
        self.terminating = true;
        self
    }

    /// Delegates to `count` new keys, `threshold` of which must sign.
    pub fn keys(mut self, count: usize, threshold: u64) -> Self {
        self.keys = DelegationKeys::New(count);
        self.threshold = threshold;
        self
    }

    /// Delegates to existing keys, such as those another delegation to the
    /// same role uses.
    pub fn signed_by(mut self, keys: &[Arc<PrivateKey>]) -> Self {
        self.keys = DelegationKeys::Existing(keys.to_vec());
        self
    }
}

/// A TUF repository that publishes to a [`RecordingTransport`].
///
/// Change the role payloads through the public fields and the helpers, then
/// publish them: [`commit`](Self::commit) publishes changed targets roles
/// and new snapshot and timestamp versions (6.3), and
/// [`publish_root`](Self::publish_root) the next root version. Payloads
/// that are published get the next version number.
///
/// Every key is derived from the repository's name and is the same in every
/// run (see [`keys`](super::keys)).
pub struct TestRepo {
    name: String,
    /// Serves everything the repository publishes, to [`Client`]s.
    pub transport: Arc<RecordingTransport>,
    /// The root payload; it becomes the next root version when published.
    pub root: Root,
    pub timestamp: Timestamp,
    pub snapshot: Snapshot,
    /// The payloads of the top-level targets role and the delegated roles.
    pub targets: BTreeMap<String, Targets>,
    /// The keys each role's metadata is signed with.
    pub signers: HashMap<String, Vec<Arc<PrivateKey>>>,
    /// Whether timestamp and snapshot metadata list file lengths.
    pub meta_lengths: bool,
    /// Whether timestamp and snapshot metadata list file hashes.
    pub meta_hashes: bool,
    /// The root keys of the latest published root version, which must also
    /// sign the next one (5.3.4).
    trusted_root_signers: Vec<Arc<PrivateKey>>,
    /// Targets roles changed since the last commit.
    dirty: BTreeSet<String>,
    published: BTreeMap<String, Vec<u8>>,
    published_targets: BTreeMap<String, Vec<u8>>,
    keys_created: usize,
}

impl TestRepo {
    /// A repository without consistent snapshots, in which each top-level
    /// role has one key.
    pub fn new() -> Self {
        Self::builder().build()
    }

    pub fn builder() -> RepoBuilder {
        RepoBuilder {
            name: "repo".to_owned(),
            consistent_snapshot: false,
            keys: HashMap::new(),
            expires: HashMap::new(),
            meta_lengths: false,
            meta_hashes: false,
        }
    }

    fn consistent(&self) -> bool {
        self.root.uses_consistent_snapshots()
    }

    // Published files.

    /// The bytes last published as the metadata file `name`.
    pub fn file(&self, name: &str) -> Vec<u8> {
        match self.published.get(name) {
            Some(data) => data.clone(),
            None => panic!("{name} has not been published"),
        }
    }

    /// Version 1 of root metadata, which clients are shipped with.
    pub fn initial_root(&self) -> Vec<u8> {
        self.file("1.root.json")
    }

    /// Publishes raw bytes as the metadata file `name`.
    pub fn write(&mut self, name: &str, data: Vec<u8>) {
        self.transport.inner.insert_metadata(name, data.clone());
        self.published.insert(name.to_owned(), data);
    }

    /// Stops serving the metadata file `name`.
    pub fn remove(&mut self, name: &str) {
        self.transport.inner.remove_metadata(name);
        self.published.remove(name);
    }

    /// Serves `data` as the target file at `path` (which, with consistent
    /// snapshots, includes the hash prefix).
    pub fn serve_target(&mut self, path: &str, data: &[u8]) {
        self.transport.inner.insert_target(path, data.to_vec());
        self.published_targets
            .insert(path.to_owned(), data.to_vec());
    }

    /// The requests clients made since the last call, as metadata file names
    /// and `target:PATH`.
    pub fn requests(&self) -> Vec<String> {
        self.transport.take_requests()
    }

    /// Writes everything published to `dir/metadata` and `dir/targets`.
    pub fn export(&self, dir: &Path) {
        let write = |path: std::path::PathBuf, data: &[u8]| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, data).unwrap();
        };
        for (name, data) in &self.published {
            write(dir.join("metadata").join(name), data);
        }
        for (path, data) in &self.published_targets {
            write(dir.join("targets").join(path), data);
        }
    }

    // Signing.

    /// Signs a payload with the keys of `role` and encodes it. Root payloads
    /// are also signed with the keys of the latest published root.
    pub fn sign<T: Role>(&self, role: &str, payload: &T) -> Vec<u8> {
        let mut signers = self.signers[role].clone();
        if role == "root" {
            signers.extend(self.trusted_root_signers.iter().cloned());
        }
        let signers: Vec<&PrivateKey> = signers.iter().map(|key| key.as_ref()).collect();
        Self::sign_with(payload, &signers)
    }

    /// Signs a payload with arbitrary keys and encodes it.
    pub fn sign_with<T: Role>(payload: &T, signers: &[&PrivateKey]) -> Vec<u8> {
        let mut metadata = Metadata::<T>::new(payload.clone()).unwrap();
        for signer in signers {
            metadata.sign(*signer).unwrap();
        }
        metadata.to_bytes().unwrap()
    }

    // Targets.

    /// Mutable access to a targets role's payload, which is published at the
    /// next commit.
    pub fn targets_mut(&mut self, role: &str) -> &mut Targets {
        self.dirty.insert(role.to_owned());
        self.targets
            .get_mut(role)
            .unwrap_or_else(|| panic!("no targets role {role:?}"))
    }

    /// Lists a target in `role`, with its SHA-256 and SHA-512 hashes, and
    /// serves its content.
    pub fn add_target(&mut self, role: &str, path: &str, data: &[u8]) -> TargetFile {
        self.add_target_with_hashes(role, path, data, &HashAlgorithm::ALL)
    }

    /// Lists a target in `role` with the hashes of `algorithms`, and serves
    /// its content: with consistent snapshots, once for each hash, as
    /// `HASH.FILENAME` (6.2).
    pub fn add_target_with_hashes(
        &mut self,
        role: &str,
        path: &str,
        data: &[u8],
        algorithms: &[HashAlgorithm],
    ) -> TargetFile {
        let file = TargetFile::from_bytes(data, algorithms);
        if self.consistent() {
            let (dir, name) = match path.rsplit_once('/') {
                Some((dir, name)) => (format!("{dir}/"), name),
                None => (String::new(), path),
            };
            for (_, digest) in file.hashes.iter() {
                self.serve_target(&format!("{dir}{digest}.{name}"), data);
            }
        } else {
            self.serve_target(path, data);
        }
        self.targets_mut(role)
            .targets
            .insert(path.to_owned(), file.clone());
        file
    }

    /// Makes `delegator` delegate to a role. A new role starts out signed by
    /// the delegation's keys; a role that is already delegated to elsewhere
    /// keeps the keys it is signed with.
    pub fn delegate(&mut self, delegator: &str, delegation: Delegation) {
        let keys = match delegation.keys {
            DelegationKeys::New(count) => (0..count).map(|_| self.new_key()).collect(),
            DelegationKeys::Existing(keys) => keys,
        };
        let mut role = DelegatedRole::new(
            &delegation.name,
            keys.iter().map(|key| key_id(key)).collect(),
            delegation.threshold,
        );
        role.terminating = delegation.terminating;
        role.paths = delegation.paths;
        role.path_hash_prefixes = delegation.path_hash_prefixes;

        let delegations = self
            .targets_mut(delegator)
            .delegations
            .get_or_insert_with(Delegations::new);
        for key in &keys {
            delegations
                .keys
                .insert(key_id(key), key.public_key().clone());
        }
        delegations.roles.push(role);

        if !self.targets.contains_key(&delegation.name) {
            let mut targets = Targets::new(far_future());
            targets.version = 0;
            self.targets.insert(delegation.name.clone(), targets);
            self.signers.insert(delegation.name.clone(), keys);
            self.dirty.insert(delegation.name);
        }
    }

    // Publishing.

    /// Publishes the targets roles changed since the last commit (6.3.1),
    /// then a new snapshot version and a new timestamp version.
    pub fn commit(&mut self) {
        for role in std::mem::take(&mut self.dirty) {
            let targets = self.targets.get_mut(&role).unwrap();
            targets.version += 1;
            let targets = targets.clone();
            let data = self.sign(&role, &targets);
            let name = format!("{}.json", encode_role(&role));
            if self.consistent() {
                self.write(&format!("{}.{name}", targets.version), data.clone());
            }
            self.write(&name, data.clone());
            let meta = self.meta_file(targets.version, &data);
            self.snapshot.meta.insert(format!("{role}.json"), meta);
        }
        self.publish_snapshot();
    }

    /// Publishes a new snapshot version (6.3.2), then a new timestamp
    /// version that lists it.
    pub fn publish_snapshot(&mut self) {
        self.snapshot.version += 1;
        let data = self.sign("snapshot", &self.snapshot);
        if self.consistent() {
            self.write(
                &format!("{}.snapshot.json", self.snapshot.version),
                data.clone(),
            );
        }
        self.write("snapshot.json", data.clone());
        let meta = self.meta_file(self.snapshot.version, &data);
        self.timestamp.meta = BTreeMap::from([("snapshot.json".to_owned(), meta)]);
        self.publish_timestamp();
    }

    /// Publishes a new timestamp version (6.3.3).
    pub fn publish_timestamp(&mut self) {
        self.timestamp.version += 1;
        let data = self.sign("timestamp", &self.timestamp);
        self.write("timestamp.json", data);
    }

    /// Publishes the next root version as `VERSION.root.json` and
    /// `root.json`, signed with the keys of the previous and of the new
    /// version (6.1).
    pub fn publish_root(&mut self) {
        self.root.version += 1;
        let data = self.sign("root", &self.root);
        self.write(&format!("{}.root.json", self.root.version), data.clone());
        self.write("root.json", data);
        self.trusted_root_signers = self.signers["root"].clone();
    }

    fn meta_file(&self, version: u64, data: &[u8]) -> MetaFile {
        let mut meta = MetaFile::new(version);
        if self.meta_lengths {
            meta.length = Some(data.len() as u64);
        }
        if self.meta_hashes {
            meta.hashes = Some(Hashes::compute(data, &[HashAlgorithm::Sha256]));
        }
        meta
    }

    // Keys.

    /// A key that has not been used in this repository yet.
    pub fn new_key(&mut self) -> Arc<PrivateKey> {
        self.keys_created += 1;
        key(&format!("{}/{}", self.name, self.keys_created))
    }

    /// Authorizes a new key for a top-level role (in the next root version)
    /// and signs the role's metadata with it too.
    pub fn add_key(&mut self, role: RoleType) -> Arc<PrivateKey> {
        let key = self.new_key();
        self.root
            .add_key(role, key_id(&key), key.public_key().clone());
        self.signers
            .entry(role.as_str().to_owned())
            .or_default()
            .push(key.clone());
        key
    }

    /// Replaces the keys of a top-level role with one new key (in the next
    /// root version), keeping its threshold.
    pub fn rotate_key(&mut self, role: RoleType) -> Arc<PrivateKey> {
        let old = std::mem::take(&mut self.root.roles.get_mut(role).keyids);
        for keyid in old {
            let used = TOP_LEVEL_ROLES
                .iter()
                .any(|&role| self.root.roles.get(role).keyids.contains(&keyid));
            if !used {
                self.root.keys.remove(&keyid);
            }
        }
        self.signers.insert(role.as_str().to_owned(), Vec::new());
        self.add_key(role)
    }

    // Clients.

    /// A client that trusts version 1 of root metadata and has no local
    /// metadata yet.
    pub fn client(&self) -> Client {
        Client::new(self, UpdaterConfig::default())
    }

    pub fn client_with(&self, config: UpdaterConfig) -> Client {
        Client::new(self, config)
    }

    /// Verification state at the update start time, trusting version 1 of
    /// root metadata.
    pub fn trusted(&self) -> TrustedMetadata {
        TrustedMetadata::new(&self.initial_root(), now()).unwrap()
    }

    /// Verification state trusting the latest root and timestamp.
    pub fn trusted_with_timestamp(&self) -> TrustedMetadata {
        let mut trusted = TrustedMetadata::new(&self.file("root.json"), now()).unwrap();
        trusted
            .update_timestamp(&self.file("timestamp.json"))
            .unwrap();
        trusted
    }

    /// Verification state trusting the latest root, timestamp and snapshot.
    pub fn trusted_with_snapshot(&self) -> TrustedMetadata {
        let mut trusted = self.trusted_with_timestamp();
        trusted
            .update_snapshot(&self.file("snapshot.json"))
            .unwrap();
        trusted
    }

    /// Verification state trusting the latest root, timestamp, snapshot and
    /// top-level targets.
    pub fn trusted_with_targets(&self) -> TrustedMetadata {
        let mut trusted = self.trusted_with_snapshot();
        trusted.update_targets(&self.file("targets.json")).unwrap();
        trusted
    }
}

/// Percent-encodes a role name the way the updater does in file names: all
/// but unreserved URL characters are escaped.
pub fn encode_role(role: &str) -> String {
    role.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
