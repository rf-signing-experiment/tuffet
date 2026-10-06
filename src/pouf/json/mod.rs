//! The default POUF: JSON metadata signed over canonical JSON.
//!
//! A metadata file is a JSON object with two members: `signed`, the role
//! payload, and `signatures`, a list of `{"keyid", "sig"}` objects whose
//! `sig` is the hex-encoded signature over the [canonical] form
//! of `signed`.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Decoded, Pouf};
use crate::error::{Error, Result};
use crate::metadata::{Signature, UnrecognizedFields};

pub mod canonical;

/// The JSON POUF.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json;

impl Pouf for Json {
    const EXTENSION: &'static str = "json";

    fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<Decoded<T>> {
        // Deserialize the payload from the same parsed value that is
        // canonicalized, so the signed bytes and the typed payload cannot
        // disagree about what the document says.
        let envelope: Envelope<Value> = serde_json::from_slice(bytes).map_err(decode_error)?;
        let canonical_signed = canonical::to_vec(&envelope.signed).map_err(decode_error)?;
        let signed = T::deserialize(envelope.signed).map_err(decode_error)?;
        Ok(Decoded {
            signed,
            signatures: envelope.signatures,
            unrecognized_fields: envelope.unrecognized_fields,
            canonical_signed,
        })
    }

    fn encode<T: Serialize>(
        signed: &T,
        signatures: &[Signature],
        unrecognized_fields: &UnrecognizedFields,
    ) -> Result<Vec<u8>> {
        let envelope = Envelope {
            signatures,
            signed,
            unrecognized_fields,
        };
        serde_json::to_vec_pretty(&envelope).map_err(|e| Error::Encode(e.into()))
    }

    fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
        let value = serde_json::to_value(value).map_err(|e| Error::Encode(e.into()))?;
        canonical::to_vec(&value).map_err(|e| Error::Encode(e.into()))
    }
}

/// A metadata file. Being flattened, `unrecognized_fields` also makes serde
/// accept only a JSON object, as opposed to an array of the field values.
#[derive(Serialize, Deserialize)]
struct Envelope<S, T = Vec<Signature>, U = UnrecognizedFields> {
    signatures: T,
    signed: S,
    #[serde(flatten)]
    unrecognized_fields: U,
}

fn decode_error(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Decode(Box::new(error))
}
