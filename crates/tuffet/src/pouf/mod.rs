//! POUFs (Protocol, Operations, Usage and Format documents): how metadata is
//! encoded on the wire and canonicalized for signing.
//!
//! The specification leaves the metadata format to implementations. A
//! [`Pouf`] supplies it; the rest of the crate works with any implementation.
//! [`Json`] is the default, matching the reference implementation: JSON
//! documents signed over their canonical JSON form.
//!
//! The metadata types implement serde's `Serialize` and `Deserialize`, which
//! form the data model a POUF works with. Fields this implementation does not
//! recognize are carried as [`Value`](crate::metadata::Value)s.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::crypto::HashAlgorithm;
use crate::error::Result;
use crate::metadata::{Key, KeyId, Signature, UnrecognizedFields};

pub mod json;

pub use json::Json;

/// A metadata wire format.
pub trait Pouf: 'static {
    /// The extension of metadata file names, without the dot (e.g. `json`).
    const EXTENSION: &'static str;

    /// Decodes a signed metadata envelope.
    ///
    /// The canonical bytes must be computed from the signed payload *as it
    /// appears in the input*, including any fields `T` does not represent,
    /// since those are what the signatures cover. Fields of the envelope
    /// itself that the format does not define must be returned as well, so
    /// that encoding the metadata again preserves them, as section 4 of the
    /// specification requires.
    fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<Decoded<T>>;

    /// Encodes a signed metadata envelope, including the fields of the
    /// envelope that were not recognized when it was decoded.
    fn encode<T: Serialize>(
        signed: &T,
        signatures: &[Signature],
        unrecognized_fields: &UnrecognizedFields,
    ) -> Result<Vec<u8>>;

    /// The canonical encoding of a value, used for signing and key IDs.
    fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>>;

    /// The file name of a role's metadata, as listed in snapshot metadata
    /// (e.g. `targets.json`).
    fn file_name(role: &str) -> String {
        format!("{role}.{}", Self::EXTENSION)
    }

    /// The key ID of a key: the hex-encoded SHA-256 digest of its canonical
    /// encoding.
    fn key_id(key: &Key) -> Result<KeyId> {
        let digest = HashAlgorithm::Sha256.digest(&Self::canonicalize(key)?);
        Ok(KeyId::new(hex::encode(digest)))
    }
}

/// A decoded metadata envelope.
#[derive(Debug)]
pub struct Decoded<T> {
    pub signed: T,
    pub signatures: Vec<Signature>,
    /// The fields of the envelope other than the payload and the signatures,
    /// which this implementation does not recognize. They are not signed.
    pub unrecognized_fields: UnrecognizedFields,
    /// The canonical encoding of the signed payload exactly as it was
    /// received: the bytes the signatures cover.
    pub canonical_signed: Vec<u8>,
}
