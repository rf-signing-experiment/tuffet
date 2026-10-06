//! Metadata formats: section 4 of the specification.
//!
//! These tests decode, validate, sign, verify and encode single metadata
//! files with the `metadata` module, independently of the client workflow
//! (the `workflow` tests cover that). The cryptography behind key types and
//! signature schemes is covered by the `crypto` tests.

#[path = "../support/mod.rs"]
mod support;

// 4.1 Metaformat: canonical JSON
mod canonical_json;

// 4.2.1 Object format
mod envelope;

// 4.2.2 Key objects, and key IDs
mod keys;

// 4.2.3 Date-time
mod date_time;

// SPEC_VERSION, VERSION and EXPIRES, in every role (4.3 to 4.6)
mod common_fields;

// 4.3 root.json
mod root;

// 4.4 snapshot.json
mod snapshot;

// 4.5 targets.json and delegated target roles
mod targets;

// 4.5 PATHPATTERN and "path_hash_prefixes"
mod path_patterns;

// 4.6 timestamp.json
mod timestamp;

// Fields this implementation does not know (the introduction of section 4)
mod unrecognized_fields;

// THRESHOLD, and how signatures count towards it
mod signatures;

// LENGTH and HASHES, as checked in 5.5.2, 5.6.2 and 5.7.3
mod file_verification;

// The encoding of each role, as snapshots
mod serialization;

use rftuf::Error;
use rftuf::metadata::{Metadata, Role};
use serde_json::{Value, json};

/// Decodes `signed` as the payload of a metadata file without signatures.
fn decode<T: Role>(signed: Value) -> rftuf::Result<Metadata<T>> {
    let document = json!({"signatures": [], "signed": signed});
    Metadata::from_bytes(&serde_json::to_vec(&document).unwrap())
}

/// Why `signed` is invalid metadata of role `T`. Panics if it decodes, or
/// fails to for another reason.
fn invalid_reason<T: Role>(signed: Value) -> String {
    match decode::<T>(signed) {
        Err(Error::InvalidMetadata(reason)) => reason,
        Err(other) => panic!("expected invalid metadata, got {other:?}"),
        Ok(_) => panic!("expected invalid metadata, got valid metadata"),
    }
}

/// A metadata file of the reference implementation's test repository, such
/// as `root.json`, as JSON.
fn python_tuf_document(name: &str) -> Value {
    serde_json::from_slice(&support::data::python_tuf(name)).unwrap()
}

/// The payload (`signed`) of a metadata file of the reference
/// implementation's test repository.
fn python_tuf_payload(name: &str) -> Value {
    python_tuf_document(name)["signed"].take()
}
