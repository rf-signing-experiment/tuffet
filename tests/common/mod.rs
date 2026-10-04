//! A TUF repository for tests, built with the public metadata API.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, TimeZone, Utc};
use rftuf::crypto::{HashAlgorithm, PrivateKey, Signer};
use rftuf::metadata::{
    DelegatedRole, Delegations, MetaFile, Metadata, Role, RoleType, Root, Snapshot, TargetFile,
    Targets, Timestamp,
};
use rftuf::pouf::{Json, Pouf};
use rftuf::transport::{ByteStream, MemoryTransport, Transport, TransportError};

/// The fixed "current time" of the tests.
pub fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 6, 1, 12, 0, 0).unwrap()
}

pub fn expired() -> DateTime<Utc> {
    now() - Duration::days(1)
}

/// Far enough in the future that refreshing at the actual current time works too.
fn valid_until() -> DateTime<Utc> {
    now() + Duration::days(100 * 365)
}

fn new_key() -> Arc<PrivateKey> {
    Arc::new(PrivateKey::generate(&rftuf::metadata::SignatureScheme::Ed25519).unwrap())
}

/// Percent-encodes a role name the way the updater names its files.
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

/// A repository that publishes to a [`MemoryTransport`].
///
/// Edit role payloads through the public fields and helpers, then call
/// [`commit`](Self::commit) (targets, snapshot and timestamp) or
/// [`publish_root`](Self::publish_root).
pub struct TestRepo {
    pub transport: Arc<RecordingTransport>,
    pub root: Root,
    pub snapshot: Snapshot,
    pub timestamp: Timestamp,
    /// The top-level targets role and delegated roles.
    pub targets: BTreeMap<String, Targets>,
    /// Signing keys of each role.
    pub signers: HashMap<String, Vec<Arc<PrivateKey>>>,
    /// Root keys of the previous root version, which must also sign the next.
    previous_root_signers: Vec<Arc<PrivateKey>>,
    /// Targets roles changed since the last commit.
    dirty: BTreeSet<String>,
    /// Whether snapshot and timestamp list lengths and hashes.
    pub meta_hashes: bool,
    published: HashMap<String, Vec<u8>>,
}

impl TestRepo {
    pub fn new() -> Self {
        Self::with_consistent_snapshot(false)
    }

    pub fn with_consistent_snapshot(consistent: bool) -> Self {
        let mut root = Root::new(valid_until());
        root.consistent_snapshot = Some(consistent);
        let mut signers = HashMap::new();
        for role in [
            RoleType::Root,
            RoleType::Timestamp,
            RoleType::Snapshot,
            RoleType::Targets,
        ] {
            let key = new_key();
            root.add_key(
                role,
                Json::key_id(key.public_key()).unwrap(),
                key.public_key().clone(),
            );
            signers.insert(role.as_str().to_owned(), vec![key]);
        }

        let mut targets = Targets::new(valid_until());
        targets.version = 0;
        let mut snapshot = Snapshot::new(valid_until());
        snapshot.version = 0;
        let mut timestamp = Timestamp::new(valid_until());
        timestamp.version = 0;

        let mut repo = TestRepo {
            transport: Arc::new(RecordingTransport::default()),
            root,
            snapshot,
            timestamp,
            targets: BTreeMap::from([("targets".to_owned(), targets)]),
            signers,
            previous_root_signers: Vec::new(),
            dirty: BTreeSet::from(["targets".to_owned()]),
            meta_hashes: false,
            published: HashMap::new(),
        };
        let root_bytes = repo.sign("root", &repo.root.clone());
        repo.write("1.root.json", root_bytes.clone());
        repo.write("root.json", root_bytes);
        repo.commit();
        repo
    }

    fn consistent(&self) -> bool {
        self.root.uses_consistent_snapshots()
    }

    /// The bytes most recently published under `name`.
    pub fn file(&self, name: &str) -> Vec<u8> {
        self.published[name].clone()
    }

    /// The first version of root metadata, to bootstrap clients with.
    pub fn initial_root(&self) -> Vec<u8> {
        self.file("1.root.json")
    }

    /// Publishes raw bytes under a metadata file name.
    pub fn write(&mut self, name: &str, data: Vec<u8>) {
        self.transport.inner.insert_metadata(name, data.clone());
        self.published.insert(name.to_owned(), data);
    }

    /// Signs a payload with the keys of `role` and encodes it.
    pub fn sign<T: Role>(&self, role: &str, payload: &T) -> Vec<u8> {
        let mut metadata = Metadata::<T>::new(payload.clone()).unwrap();
        let mut signers = self.signers[role].clone();
        if role == "root" {
            signers.extend(self.previous_root_signers.iter().cloned());
        }
        for signer in signers {
            metadata.sign(signer.as_ref()).unwrap();
        }
        metadata.to_bytes().unwrap()
    }

    /// Signs a payload with arbitrary keys and encodes it.
    pub fn sign_with<T: Role>(payload: &T, signers: &[&PrivateKey]) -> Vec<u8> {
        let mut metadata = Metadata::<T>::new(payload.clone()).unwrap();
        for signer in signers {
            metadata.sign(*signer).unwrap();
        }
        metadata.to_bytes().unwrap()
    }

    /// Mutable access to a targets role; it is re-signed at the next commit.
    pub fn targets_mut(&mut self, role: &str) -> &mut Targets {
        self.dirty.insert(role.to_owned());
        self.targets.get_mut(role).unwrap()
    }

    /// Lists a target in `role` and publishes its content.
    pub fn add_target(&mut self, role: &str, path: &str, data: &[u8]) {
        let file = TargetFile::from_bytes(data, &HashAlgorithm::ALL);
        if self.consistent() {
            let (dir, name) = match path.rsplit_once('/') {
                Some((dir, name)) => (format!("{dir}/"), name),
                None => (String::new(), path),
            };
            for (_, digest) in file.hashes.iter() {
                self.transport
                    .inner
                    .insert_target(format!("{dir}{digest}.{name}"), data.to_vec());
            }
        } else {
            self.transport.inner.insert_target(path, data.to_vec());
        }
        self.targets_mut(role).targets.insert(path.to_owned(), file);
    }

    /// Makes `parent` delegate `paths` to a new role `child` with its own key.
    pub fn add_delegation(&mut self, parent: &str, child: &str, paths: &[&str], terminating: bool) {
        let key = new_key();
        let keyid = Json::key_id(key.public_key()).unwrap();
        let mut role = DelegatedRole::new(child, vec![keyid.clone()], 1);
        role.paths = Some(paths.iter().map(|p| p.to_string()).collect());
        role.terminating = terminating;

        let delegations = self
            .targets_mut(parent)
            .delegations
            .get_or_insert_with(Delegations::new);
        delegations.keys.insert(keyid, key.public_key().clone());
        delegations.roles.push(role);

        let mut targets = Targets::new(valid_until());
        targets.version = 0;
        self.targets.insert(child.to_owned(), targets);
        self.dirty.insert(child.to_owned());
        self.signers.insert(child.to_owned(), vec![key]);
    }

    /// Publishes changed targets roles, then new snapshot and timestamp versions.
    pub fn commit(&mut self) {
        for role in std::mem::take(&mut self.dirty) {
            let mut targets = self.targets[&role].clone();
            targets.version += 1;
            self.targets.insert(role.clone(), targets.clone());
            let data = self.sign(&role, &targets);
            let file_name = format!("{}.json", encode_role(&role));
            let meta = self.meta_file(targets.version, &data);
            self.snapshot.meta.insert(format!("{role}.json"), meta);
            if self.consistent() {
                self.write(&format!("{}.{file_name}", targets.version), data.clone());
            }
            self.write(&file_name, data);
        }
        self.publish_snapshot();
    }

    /// Publishes a new snapshot version, then a new timestamp version.
    pub fn publish_snapshot(&mut self) {
        self.snapshot.version += 1;
        let data = self.sign("snapshot", &self.snapshot.clone());
        if self.consistent() {
            self.write(
                &format!("{}.snapshot.json", self.snapshot.version),
                data.clone(),
            );
        }
        self.write("snapshot.json", data.clone());
        self.timestamp.meta = BTreeMap::from([(
            "snapshot.json".to_owned(),
            self.meta_file(self.snapshot.version, &data),
        )]);
        self.publish_timestamp();
    }

    /// Publishes a new timestamp version.
    pub fn publish_timestamp(&mut self) {
        self.timestamp.version += 1;
        let data = self.sign("timestamp", &self.timestamp.clone());
        self.write("timestamp.json", data);
    }

    fn meta_file(&self, version: u64, data: &[u8]) -> MetaFile {
        if self.meta_hashes {
            MetaFile::from_bytes(version, data, &[HashAlgorithm::Sha256])
        } else {
            MetaFile::new(version)
        }
    }

    /// Replaces the keys of a top-level role with a new key. Takes effect
    /// when root is published.
    pub fn rotate_key(&mut self, role: RoleType) {
        let key = new_key();
        let role_keys = self.root.roles.get_mut(role);
        for old in std::mem::take(&mut role_keys.keyids) {
            self.root.keys.remove(&old);
        }
        let keyid = Json::key_id(key.public_key()).unwrap();
        self.root.add_key(role, keyid, key.public_key().clone());
        let old_signers = self
            .signers
            .insert(role.as_str().to_owned(), vec![key])
            .unwrap();
        if role == RoleType::Root && self.previous_root_signers.is_empty() {
            self.previous_root_signers = old_signers;
        }
    }

    /// Publishes the next root version, signed by the previous and the
    /// current root keys.
    pub fn publish_root(&mut self) {
        self.root.version += 1;
        let data = self.sign("root", &self.root.clone());
        self.previous_root_signers.clear();
        self.write(&format!("{}.root.json", self.root.version), data.clone());
        self.write("root.json", data);
    }
}

/// A [`MemoryTransport`] that records what is fetched.
#[derive(Default)]
pub struct RecordingTransport {
    pub inner: MemoryTransport,
    requests: Mutex<Vec<String>>,
}

impl RecordingTransport {
    /// The files fetched since the last call, as `name` for metadata and
    /// `target:path` for targets.
    pub fn take_requests(&self) -> Vec<String> {
        std::mem::take(&mut self.requests.lock().unwrap())
    }
}

impl Transport for RecordingTransport {
    async fn fetch_metadata(&self, name: &str) -> Result<ByteStream, TransportError> {
        self.requests.lock().unwrap().push(name.to_owned());
        self.inner.fetch_metadata(name).await
    }

    async fn fetch_target(&self, path: &str) -> Result<ByteStream, TransportError> {
        self.requests.lock().unwrap().push(format!("target:{path}"));
        self.inner.fetch_target(path).await
    }
}
