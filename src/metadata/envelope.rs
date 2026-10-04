//! The signed metadata envelope.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::{HexBytes, Key, KeyId, Role, UnrecognizedFields};
use crate::crypto::{self, Signer};
use crate::error::{Error, Result};
use crate::pouf::{Decoded, Json, Pouf};

/// A signature over a metadata payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub keyid: KeyId,
    pub sig: HexBytes,
    #[serde(flatten)]
    pub unrecognized_fields: UnrecognizedFields,
}

impl Signature {
    pub fn new(keyid: KeyId, sig: impl Into<HexBytes>) -> Self {
        Signature {
            keyid,
            sig: sig.into(),
            unrecognized_fields: BTreeMap::new(),
        }
    }
}

/// Signed metadata: a role payload and its signatures.
///
/// `P` is the [POUF](crate::pouf) that defines how metadata is encoded; it
/// defaults to [`Json`].
///
/// A `Metadata` remembers the canonical bytes its signatures cover. When it is
/// decoded, these are the canonical form of the payload *exactly as
/// received*, so signatures also cover fields this implementation does not
/// understand. When it is created with [`Metadata::new`], they are computed
/// from the payload. For this reason the payload cannot be changed in place:
/// take it out with [`into_signed`](Self::into_signed), change it and wrap it
/// again, which also drops the signatures it invalidated.
pub struct Metadata<T, P = Json> {
    signed: T,
    signatures: Vec<Signature>,
    canonical_signed: Vec<u8>,
    pouf: PhantomData<fn() -> P>,
}

impl<T: Role, P: Pouf> Metadata<T, P> {
    /// Wraps a role payload, without signatures, so that it can be signed.
    pub fn new(signed: T) -> Result<Self> {
        signed.validate::<P>()?;
        let canonical_signed = P::canonicalize(&signed)?;
        Ok(Metadata {
            signed,
            signatures: Vec::new(),
            canonical_signed,
            pouf: PhantomData,
        })
    }

    /// Decodes and validates metadata. Signatures are *not* verified; that
    /// requires the keys of the delegating role (see [`Root::verify_role`]
    /// and [`Targets::verify_delegate`]).
    ///
    /// [`Root::verify_role`]: super::Root::verify_role
    /// [`Targets::verify_delegate`]: super::Targets::verify_delegate
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let Decoded {
            signed,
            signatures,
            canonical_signed,
        } = P::decode::<T>(bytes)?;
        let mut keyids = HashSet::new();
        if let Some(duplicate) = signatures.iter().find(|sig| !keyids.insert(&sig.keyid)) {
            return Err(Error::InvalidMetadata(format!(
                "{} metadata has multiple signatures by key {}",
                T::TYPE,
                duplicate.keyid
            )));
        }
        signed.validate::<P>()?;
        Ok(Metadata {
            signed,
            signatures,
            canonical_signed,
            pouf: PhantomData,
        })
    }

    /// Encodes the metadata for storage or publication.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        P::encode(&self.signed, &self.signatures)
    }

    pub fn signed(&self) -> &T {
        &self.signed
    }

    /// Takes out the payload, discarding the signatures.
    pub fn into_signed(self) -> T {
        self.signed
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// The canonical form of the payload: the bytes that signatures cover.
    pub fn canonical_signed(&self) -> &[u8] {
        &self.canonical_signed
    }

    /// Signs the payload, replacing any earlier signature by the same key.
    ///
    /// The signature is labeled with the key ID computed by
    /// [`Pouf::key_id`]. For a key that metadata lists under another ID, sign
    /// [`canonical_signed`](Self::canonical_signed) and use
    /// [`add_signature`](Self::add_signature).
    pub fn sign<S: Signer + ?Sized>(&mut self, signer: &S) -> Result<&Signature> {
        let keyid = P::key_id(signer.public_key())?;
        let sig = signer.sign(&self.canonical_signed)?;
        self.add_signature(Signature::new(keyid, sig));
        Ok(self.signatures.last().expect("just added"))
    }

    /// Adds a signature produced elsewhere over
    /// [`canonical_signed`](Self::canonical_signed), replacing any earlier
    /// signature by the same key.
    pub fn add_signature(&mut self, signature: Signature) {
        self.signatures
            .retain(|existing| existing.keyid != signature.keyid);
        self.signatures.push(signature);
    }

    pub fn clear_signatures(&mut self) {
        self.signatures.clear();
    }

    /// Checks that at least `threshold` of the keys `keyids` (looked up in
    /// `keys`) have validly signed this metadata. `role` names the role in
    /// errors.
    ///
    /// Each key counts at most once, even if it is listed under several key
    /// IDs. Signatures by other keys, by unknown keys and with unsupported
    /// schemes are ignored.
    pub fn verify_signatures(
        &self,
        role: &str,
        keys: &BTreeMap<KeyId, Key>,
        keyids: &[KeyId],
        threshold: u64,
    ) -> Result<()> {
        // Identifies keys by their material rather than by key ID.
        let mut counted: HashSet<(&str, &str)> = HashSet::new();
        for keyid in keyids {
            let Some(key) = keys.get(keyid) else { continue };
            let Some(signature) = self.signatures.iter().find(|sig| sig.keyid == *keyid) else {
                continue;
            };
            let material = (key.keytype.as_str(), key.keyval.public.as_str());
            if counted.contains(&material) {
                continue;
            }
            match crypto::verify_signature(key, &self.canonical_signed, &signature.sig) {
                Ok(()) => {
                    counted.insert(material);
                }
                Err(error) => log::debug!("ignoring signature on {role} by key {keyid}: {error}"),
            }
        }
        let valid = counted.len() as u64;
        if valid < threshold {
            return Err(Error::SignatureThreshold {
                role: role.to_owned(),
                valid,
                threshold,
            });
        }
        Ok(())
    }
}

impl<T: Clone, P> Clone for Metadata<T, P> {
    fn clone(&self) -> Self {
        Metadata {
            signed: self.signed.clone(),
            signatures: self.signatures.clone(),
            canonical_signed: self.canonical_signed.clone(),
            pouf: PhantomData,
        }
    }
}

impl<T: fmt::Debug, P> fmt::Debug for Metadata<T, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metadata")
            .field("signed", &self.signed)
            .field("signatures", &self.signatures)
            .finish_non_exhaustive()
    }
}
