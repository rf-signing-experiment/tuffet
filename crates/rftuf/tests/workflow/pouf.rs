//! TAP 11 (which 1.5.4 lists among the TAPs this version of the
//! specification adheres to): the metadata format is defined by a POUF. The
//! updater takes it as a type parameter, and uses its file extension for
//! every metadata file name (3.1.2: "All metadata filenames will have an
//! extension (EXT) based on the metaformat").

use std::collections::BTreeMap;
use std::sync::Arc;

use futures_executor::block_on;
use rftuf::crypto::{HashAlgorithm, PrivateKey, Signer};
use rftuf::metadata::{
    Key, KeyId, MetaFile, Metadata, Role, RoleType, Root, Signature, Snapshot, TargetFile, Targets,
    Timestamp, UnrecognizedFields,
};
use rftuf::pouf::{Decoded, Json, Pouf};
use rftuf::store::{MemoryStore, MetadataStore};
use rftuf::{Updater, UpdaterConfig};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::support::keys::key;
use crate::support::{RecordingTransport, far_future, now};

/// JSON metadata in files named `*.jsn`.
struct Jsn;

impl Pouf for Jsn {
    const EXTENSION: &'static str = "jsn";

    fn decode<T: DeserializeOwned>(bytes: &[u8]) -> rftuf::Result<Decoded<T>> {
        Json::decode(bytes)
    }

    fn encode<T: Serialize>(
        signed: &T,
        signatures: &[Signature],
        unrecognized_fields: &UnrecognizedFields,
    ) -> rftuf::Result<Vec<u8>> {
        Json::encode(signed, signatures, unrecognized_fields)
    }

    fn canonicalize<T: Serialize + ?Sized>(value: &T) -> rftuf::Result<Vec<u8>> {
        Json::canonicalize(value)
    }
}

fn sign<T: Role>(payload: T, signer: &PrivateKey) -> Vec<u8> {
    let mut metadata = Metadata::<T, Jsn>::new(payload).unwrap();
    metadata.sign(signer).unwrap();
    metadata.to_bytes().unwrap()
}

fn key_id(key: &Key) -> KeyId {
    Jsn::key_id(key).unwrap()
}

#[test]
fn the_updater_names_metadata_files_with_the_extension_of_its_pouf() {
    let signer = key("all roles");
    let mut root = Root::new(far_future());
    root.consistent_snapshot = Some(false);
    for role in [
        RoleType::Root,
        RoleType::Timestamp,
        RoleType::Snapshot,
        RoleType::Targets,
    ] {
        let public = signer.public_key();
        root.add_key(role, key_id(public), public.clone());
    }
    let mut targets = Targets::new(far_future());
    targets.targets.insert(
        "file".to_owned(),
        TargetFile::from_bytes(b"data", &HashAlgorithm::ALL),
    );
    let mut snapshot = Snapshot::new(far_future());
    snapshot
        .meta
        .insert("targets.jsn".to_owned(), MetaFile::new(1));
    let mut timestamp = Timestamp::new(far_future());
    timestamp.meta = BTreeMap::from([("snapshot.jsn".to_owned(), MetaFile::new(1))]);

    let transport = Arc::new(RecordingTransport::default());
    let root = sign(root, &signer);
    transport.inner.insert_metadata("1.root.jsn", root.clone());
    transport
        .inner
        .insert_metadata("timestamp.jsn", sign(timestamp, &signer));
    transport
        .inner
        .insert_metadata("snapshot.jsn", sign(snapshot, &signer));
    transport
        .inner
        .insert_metadata("targets.jsn", sign(targets, &signer));
    transport.inner.insert_target("file", b"data".to_vec());

    let store = Arc::new(MemoryStore::new());
    let mut updater = Updater::builder(transport.clone(), store.clone())
        .pouf::<Jsn>()
        .initial_root(root)
        .config(UpdaterConfig::default())
        .build()
        .unwrap();
    block_on(updater.refresh_at(now())).unwrap();
    let target = block_on(updater.get_target_info("file")).unwrap().unwrap();
    assert_eq!(block_on(updater.download_target(&target)).unwrap(), b"data");

    assert_eq!(
        transport.take_requests(),
        [
            "2.root.jsn",
            "timestamp.jsn",
            "snapshot.jsn",
            "targets.jsn",
            "target:file"
        ]
    );
    for name in ["root.jsn", "timestamp.jsn", "snapshot.jsn", "targets.jsn"] {
        assert!(store.load(name).unwrap().is_some(), "{name}");
    }
}
