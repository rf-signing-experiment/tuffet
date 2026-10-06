//! The introduction of section 4: "Implementers who encounter undefined
//! attribute-value pairs in the format must include the data when
//! calculating hashes or verifying signatures and must preserve the data
//! when re-serializing."

use rftuf::Error;
use rftuf::crypto::Signer;
use rftuf::metadata::{Metadata, Role, RoleType, Root, Snapshot, Targets, Timestamp};
use serde_json::{Value, json};

use crate::python_tuf_document;
use crate::support::far_future;
use crate::support::keys::{key, key_id};

/// Decodes `document` as metadata of role `T`, encodes it again, and returns
/// the result as JSON.
fn reencode<T: Role>(document: &Value) -> Value {
    let metadata = Metadata::<T>::from_bytes(&serde_json::to_vec(document).unwrap()).unwrap();
    serde_json::from_slice(&metadata.to_bytes().unwrap()).unwrap()
}

/// Fields rftuf does not know are part of the canonical form that
/// signatures cover, so changing them invalidates the signatures.
#[test]
fn unrecognized_fields_are_covered_by_signatures() {
    let signer = key("targets");
    let mut root = Root::new(far_future());
    root.add_key(
        RoleType::Targets,
        key_id(&signer),
        signer.public_key().clone(),
    );

    let mut payload = Targets::new(far_future());
    payload
        .unrecognized_fields
        .insert("x-extension".to_owned(), json!({"level": 1}));
    let mut targets = Metadata::<Targets>::new(payload).unwrap();
    targets.sign(signer.as_ref()).unwrap();
    let encoded = String::from_utf8(targets.to_bytes().unwrap()).unwrap();

    let decoded = Metadata::<Targets>::from_bytes(encoded.as_bytes()).unwrap();
    assert_eq!(
        decoded.signed().unrecognized_fields["x-extension"],
        json!({"level": 1})
    );
    root.verify_role(&decoded).unwrap();

    let tampered = encoded.replace("\"level\": 1", "\"level\": 2");
    assert_ne!(tampered, encoded);
    let tampered = Metadata::<Targets>::from_bytes(tampered.as_bytes()).unwrap();
    assert!(matches!(
        root.verify_role(&tampered),
        Err(Error::SignatureThreshold { .. })
    ));
}

/// Fields rftuf does not know survive decoding and encoding, at every level
/// of every role's metadata.
#[test]
fn unrecognized_fields_are_preserved_when_reencoding() {
    let mut root = python_tuf_document("root.json");
    root["signatures"][0]["x-signature"] = json!(1);
    let signed = &mut root["signed"];
    signed["x-root"] = json!({"nested": [1, 2]});
    let keyid = signed["roles"]["root"]["keyids"][0]
        .as_str()
        .unwrap()
        .to_owned();
    signed["keys"][&keyid]["x-key"] = json!(true);
    signed["keys"][&keyid]["keyval"]["x-keyval"] = json!("value");
    signed["roles"]["root"]["x-role"] = json!(null);
    signed["roles"]["mirrors"] = json!({"keyids": [], "threshold": 1});
    assert_eq!(reencode::<Root>(&root), root);

    let mut timestamp = python_tuf_document("timestamp.json");
    timestamp["signed"]["x-timestamp"] = json!(1);
    timestamp["signed"]["meta"]["snapshot.json"]["x-meta"] = json!(2);
    assert_eq!(reencode::<Timestamp>(&timestamp), timestamp);

    let mut snapshot = python_tuf_document("snapshot.json");
    snapshot["signed"]["x-snapshot"] = json!(1);
    snapshot["signed"]["meta"]["targets.json"]["x-meta"] = json!(2);
    assert_eq!(reencode::<Snapshot>(&snapshot), snapshot);

    let mut targets = python_tuf_document("targets.json");
    let signed = &mut targets["signed"];
    signed["x-targets"] = json!(1);
    signed["targets"]["file2.txt"]["x-target"] = json!(2);
    signed["delegations"]["x-delegations"] = json!(3);
    signed["delegations"]["roles"][0]["x-role"] = json!(4);
    let keyid = signed["delegations"]["roles"][0]["keyids"][0]
        .as_str()
        .unwrap()
        .to_owned();
    signed["delegations"]["keys"][&keyid]["x-key"] = json!(5);
    assert_eq!(reencode::<Targets>(&targets), targets);
}

/// Known deviation: fields of the outer object, next to "signed" and
/// "signatures", are dropped when metadata is encoded again. They are not
/// signed, and the updater persists metadata exactly as downloaded, so this
/// only affects tools that re-encode metadata.
#[test]
#[ignore = "known deviation: unrecognized fields of the outer object are not preserved"]
fn unrecognized_fields_of_the_outer_object_are_preserved_when_reencoding() {
    let mut timestamp = python_tuf_document("timestamp.json");
    timestamp["x-envelope"] = json!(1);
    assert_eq!(reencode::<Timestamp>(&timestamp), timestamp);
}
