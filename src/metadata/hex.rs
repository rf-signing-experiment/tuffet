//! Binary values encoded as hex strings.

use std::fmt;
use std::ops::Deref;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Bytes that are encoded in metadata as a hex string, such as digests and
/// signatures. Decoding accepts either case; encoding uses lowercase.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        HexBytes(bytes.into())
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(bytes: Vec<u8>) -> Self {
        HexBytes(bytes)
    }
}

impl Deref for HexBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for HexBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexBytes({self})")
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = std::borrow::Cow::<str>::deserialize(deserializer)?;
        hex::decode(encoded.as_ref())
            .map(HexBytes)
            .map_err(|e| D::Error::custom(format!("invalid hex string {encoded:?}: {e}")))
    }
}
