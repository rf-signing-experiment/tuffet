//! Public keys and key identifiers.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::UnrecognizedFields;

/// A key identifier.
///
/// New keys should be identified by the hex-encoded SHA-256 digest of their
/// canonical form, as computed by [`Pouf::key_id`](crate::pouf::Pouf::key_id).
/// When reading metadata, however, key IDs are treated as opaque labels and
/// are not recomputed; see the [crate documentation](crate#key-ids).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        KeyId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A public key, as listed in root metadata or in delegations (`KEY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    pub keytype: KeyType,
    pub scheme: SignatureScheme,
    pub keyval: KeyVal,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

impl Key {
    pub fn new(keytype: KeyType, scheme: SignatureScheme, public: String) -> Self {
        Key {
            keytype,
            scheme,
            keyval: KeyVal {
                public,
                unrecognized_fields: BTreeMap::new(),
            },
            unrecognized_fields: BTreeMap::new(),
        }
    }
}

/// The public portion of a key (`KEYVAL`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVal {
    /// The encoded public key: hex for Ed25519, PEM for ECDSA and RSA.
    pub public: String,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

/// Defines an enum of well-known metadata strings, with a catch-all variant so
/// that metadata using values this implementation does not know can still be
/// decoded (and re-encoded unchanged).
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $($(#[$vmeta:meta])* $variant:ident => $value:literal,)* }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)*
            /// A value this implementation does not support.
            Other(String),
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                match self {
                    $($name::$variant => $value,)*
                    $name::Other(value) => value,
                }
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                match value {
                    $($value => $name::$variant,)*
                    other => $name::Other(other.to_owned()),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = std::borrow::Cow::<str>::deserialize(deserializer)?;
                Ok($name::from(value.as_ref()))
            }
        }
    };
}

string_enum! {
    /// A public key signature system (`KEYTYPE`).
    pub enum KeyType {
        Ed25519 => "ed25519",
        Ecdsa => "ecdsa",
        Rsa => "rsa",
        /// ML-DSA (FIPS 204), as specified by TAP 21.
        MlDsa => "ml-dsa",
    }
}

string_enum! {
    /// A signature scheme (`SCHEME`).
    pub enum SignatureScheme {
        Ed25519 => "ed25519",
        /// ECDSA with the NIST P-256 curve and SHA-256.
        EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256",
        /// ECDSA with the NIST P-384 curve and SHA-384. Not defined by the
        /// specification, but used by other implementations.
        EcdsaSha2Nistp384 => "ecdsa-sha2-nistp384",
        /// RSA-PSS with SHA-256 and MGF1-SHA-256.
        RsassaPssSha256 => "rsassa-pss-sha256",
        /// RSA-PSS with SHA-384 and MGF1-SHA-384. Not defined by the
        /// specification, but used by other implementations.
        RsassaPssSha384 => "rsassa-pss-sha384",
        /// RSA-PSS with SHA-512 and MGF1-SHA-512. Not defined by the
        /// specification, but used by other implementations.
        RsassaPssSha512 => "rsassa-pss-sha512",
        /// ML-DSA-44 with version 1 of the TAP 21 protocol.
        MlDsa44V1 => "ml-dsa-44/1",
        /// ML-DSA-65 with version 1 of the TAP 21 protocol.
        MlDsa65V1 => "ml-dsa-65/1",
        /// ML-DSA-87 with version 1 of the TAP 21 protocol.
        MlDsa87V1 => "ml-dsa-87/1",
    }
}

impl SignatureScheme {
    /// The key type this scheme is used with, if the scheme is known.
    pub fn key_type(&self) -> Option<KeyType> {
        match self {
            SignatureScheme::Ed25519 => Some(KeyType::Ed25519),
            SignatureScheme::EcdsaSha2Nistp256 | SignatureScheme::EcdsaSha2Nistp384 => {
                Some(KeyType::Ecdsa)
            }
            SignatureScheme::RsassaPssSha256
            | SignatureScheme::RsassaPssSha384
            | SignatureScheme::RsassaPssSha512 => Some(KeyType::Rsa),
            SignatureScheme::MlDsa44V1
            | SignatureScheme::MlDsa65V1
            | SignatureScheme::MlDsa87V1 => Some(KeyType::MlDsa),
            SignatureScheme::Other(_) => None,
        }
    }
}
