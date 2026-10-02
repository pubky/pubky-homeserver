//! Stable encryption keys derived from an identity secret and canonical path.
//!
//! Directory keys are subtree seeds; file keys are terminal content keys.
//! Neither key type distinguishes read from write permissions. Derivation is
//! local and does not authenticate an imported key or authorize storage access.
//! [`ScopedEncryptionKeyBundle`] transports multiple scopes with their derivation
//! version. Serialization exposes secret bytes: encrypt and authenticate the
//! payload before delivery through a relay.
//!
//! # Derivation format
//! All outputs are 32 bytes. The root uses HKDF-SHA-256 extract-and-expand with
//! no salt (RFC 5869's 32 zero bytes) and `info` equal to
//! `pubky/hierarchical-keys/v1/root`. Each child uses HKDF-Expand-SHA-256 with
//! the parent directory seed as the PRK and `info` equal to its purpose label,
//! one zero byte, and the canonical segment's UTF-8 bytes. Purpose labels are
//! `pubky/hierarchical-keys/v1/directory` and
//! `pubky/hierarchical-keys/v1/file-content`.
//!
//! Paths are already decoded: literal percent signs are not decoded again.
//! Renaming a file changes its key. Changing these labels or their encoding
//! requires a new derivation version. The v1 labels and byte encoding are
//! permanent recovery inputs, independent of SDK release versions. Paths retain
//! their UTF-8 bytes: NFC and NFD spellings derive different keys.
//!
//! ```
//! use pubky_common::{
//!     StoragePath,
//!     encryption_keys::ScopedEncryptionKeyBundle,
//! };
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // The identity secret remains with the signer.
//! let scopes = [StoragePath::new("/pub/app/")?, StoragePath::new("/priv/chat/")?];
//! let approved_keys = ScopedEncryptionKeyBundle::from_identity_secret(&[7; 32], &scopes);
//!
//! // Encode/decode the key bundle inside an encrypted, authenticated approval.
//! let payload = postcard::to_allocvec(&approved_keys)?;
//! let app_keys: ScopedEncryptionKeyBundle = postcard::from_bytes(&payload)?;
//! let file = StoragePath::new("/pub/app/messages.json")?;
//! let content_key = app_keys.derive_for_path(&file)?;
//! let expected = ScopedEncryptionKeyBundle::from_identity_secret(
//!     &[7; 32], std::slice::from_ref(&file),
//! );
//! assert_eq!(*content_key, *expected.derive_for_path(&file)?);
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::StoragePath;

mod secret_encoding;

/// Version of the derivation format implemented by this module.
pub const DERIVATION_VERSION: &str = "v1";

const ROOT_INFO: &[u8] = b"pubky/hierarchical-keys/v1/root";
const DIRECTORY_INFO: &[u8] = b"pubky/hierarchical-keys/v1/directory";
const FILE_INFO: &[u8] = b"pubky/hierarchical-keys/v1/file-content";

/// One wire entry binding a directory seed or file secret to its canonical scope.
/// Named fields preserve the wire format and keep paths paired with their keys.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    scope: StoragePath,
    // Keep bytes in stable storage: vector growth must only move the pointer.
    // The inner Zeroizing wipes the allocation before Box releases it.
    #[serde(with = "secret_encoding")]
    secret: Box<Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntry")
            .field("scope", &self.scope)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Scoped secrets delivered together for one approval, outside its grant JWS.
///
/// The wire format is `{ "version": "v1", "keys": [...] }`. Unsupported
/// versions and inconsistent overlapping keys are rejected on deserialization.
/// JSON secrets are unpadded base64url strings; binary secrets are 32 raw bytes.
/// Empty bundles and identical duplicate entries are valid. Entry order is
/// preserved, and debug output redacts every secret.
///
/// Serialization is plaintext and needs an encrypted, authenticated envelope.
/// Decoding validates canonical paths, 32-byte secrets, and consistent overlaps.
/// Disjoint scopes cannot be checked against each other without an ancestor key.
/// Approval and identity checks belong to the auth flow. Secret storage is
/// zeroized on drop; serialized copies need their own secret handling.
#[derive(Clone, Debug, Serialize)]
pub struct ScopedEncryptionKeyBundle {
    version: DerivationVersion,
    keys: Vec<KeyEntry>,
}

impl ScopedEncryptionKeyBundle {
    /// Derive an approval bundle from the signer's high-entropy identity secret.
    ///
    /// Use the canonical 32-byte secret returned by `Keypair::secret()`, not a
    /// password or an encoded key string. Only approved scopes are retained;
    /// the temporary root seed is zeroized on return.
    /// Entries preserve request order, including overlapping or repeated scopes.
    /// The caller must limit the scopes to those approved by the user.
    pub fn from_identity_secret<'a>(
        identity_secret: &[u8; 32],
        scopes: impl IntoIterator<Item = &'a StoragePath>,
    ) -> Self {
        let root_scope = StoragePath::root();
        let root_secret = derive_root_secret(identity_secret);
        let keys = scopes
            .into_iter()
            .map(|scope| KeyEntry {
                scope: scope.clone(),
                secret: Box::new(derive_path(&root_scope, &root_secret, scope)),
            })
            .collect();

        // Deriving every entry from one source guarantees consistent overlaps.
        Self {
            version: DerivationVersion::V1,
            keys,
        }
    }

    /// Borrow approved scopes in delivery order, without exposing their entries.
    pub fn scopes(&self) -> impl ExactSizeIterator<Item = &StoragePath> {
        self.keys.iter().map(|key| &key.scope)
    }

    /// Derive an owned file content key using the first covering key.
    ///
    /// Directory paths, including `/`, are rejected. Directory seeds remain
    /// internal to the bundle. Returned bytes are zeroized on drop. Do not log
    /// them or put them in public metadata.
    ///
    /// Overlapping entries agree, so entry order cannot change the result.
    /// File entries cannot cover descendants or directories.
    ///
    /// # Errors
    /// Returns [`KeyDerivationError::DirectoryPath`] for directory paths and
    /// [`KeyDerivationError::OutsideScope`] if no bundled key covers the file,
    /// including when the bundle is empty.
    pub fn derive_for_path(
        &self,
        path: &StoragePath,
    ) -> Result<Zeroizing<[u8; 32]>, KeyDerivationError> {
        if path.is_directory() {
            return Err(KeyDerivationError::DirectoryPath {
                requested: path.clone(),
            });
        }
        self.derive_scoped_path(path)
    }

    // Also supports directory seeds for tests of the derivation hierarchy.
    fn derive_scoped_path(
        &self,
        path: &StoragePath,
    ) -> Result<Zeroizing<[u8; 32]>, KeyDerivationError> {
        let entry = self
            .keys
            .iter()
            .find(|entry| entry.scope.covers_path(path))
            .ok_or_else(|| KeyDerivationError::OutsideScope {
                requested: path.clone(),
            })?;
        Ok(derive_path(&entry.scope, &entry.secret, path))
    }
}

impl<'de> Deserialize<'de> for ScopedEncryptionKeyBundle {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireBundle {
            version: DerivationVersion,
            keys: Vec<KeyEntry>,
        }

        let wire = WireBundle::deserialize(deserializer)?;
        validate_overlap_consistency(&wire.keys).map_err(serde::de::Error::custom)?;
        Ok(Self {
            version: wire.version,
            keys: wire.keys,
        })
    }
}

// A closed enum makes unsupported wire versions fail during Serde decoding
// without accepting an arbitrary string and interpreting its keys as v1.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum DerivationVersion {
    #[serde(rename = "v1")]
    V1,
}

/// A requested path cannot yield a file content key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyDerivationError {
    /// Directory seeds are internal and cannot be derived through the public API.
    #[error("file content keys require a file path, got directory {requested}")]
    DirectoryPath {
        /// Requested directory path.
        requested: StoragePath,
    },
    /// No bundled key covers the requested file.
    #[error("no bundled key covers requested path {requested}")]
    OutsideScope {
        /// Requested file path.
        requested: StoragePath,
    },
}

/// Overlapping imported entries disagree with their common hierarchy.
#[derive(Debug, thiserror::Error)]
#[error("inconsistent keys for overlapping scopes {scope} and {other_scope}")]
struct ConflictingKeys {
    scope: StoragePath,
    other_scope: StoragePath,
}

fn validate_overlap_consistency(keys: &[KeyEntry]) -> Result<(), ConflictingKeys> {
    // Approval bundles contain few scopes. Check all overlapping pairs, even
    // those separated by unrelated entries, so lookup has one consistent result.
    for (index, entry) in keys.iter().enumerate() {
        for other in &keys[..index] {
            let (covering, covered) = if entry.scope.covers_path(&other.scope) {
                (entry, other)
            } else if other.scope.covers_path(&entry.scope) {
                (other, entry)
            } else {
                continue;
            };
            let expected = derive_path(&covering.scope, &covering.secret, &covered.scope);
            if !bool::from(expected.as_ref().ct_eq(covered.secret.as_slice())) {
                return Err(ConflictingKeys {
                    scope: covering.scope.clone(),
                    other_scope: covered.scope.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Derive the root seed with HKDF-SHA-256 extract and one expand block.
fn derive_root_secret(identity_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let root_prk = hmac_sha256(&[0; 32], &[identity_secret]);
    hmac_sha256(&root_prk, &[ROOT_INFO, b"\x01"])
}

/// Derive bytes after the constructor, lookup, or overlap check proves coverage.
fn derive_path(
    scope: &StoragePath,
    seed: &Zeroizing<[u8; 32]>,
    path: &StoragePath,
) -> Zeroizing<[u8; 32]> {
    assert!(
        scope.covers_path(path),
        "coverage must be checked before derivation"
    );
    // Coverage guarantees a directory prefix ending at a UTF-8 boundary.
    let relative_path = &path.as_str()[scope.as_str().len()..];
    let mut secret = seed.clone();
    // Retaining separators makes each segment's role explicit. An empty
    // relative path has no segments and returns the existing seed unchanged.
    for segment in relative_path.split_inclusive('/') {
        let (segment, info) = match segment.strip_suffix('/') {
            Some(directory) => (directory, DIRECTORY_INFO),
            None => (segment, FILE_INFO),
        };
        // The parent is already a PRK. RFC 5869 expand needs only block 0x01.
        secret = hmac_sha256(&secret, &[info, b"\0", segment.as_bytes(), b"\x01"]);
    }
    secret
}

/// HMAC-SHA-256 for the fixed 32-byte keys used by this derivation format.
///
/// Keep padding and digest outputs in wiping buffers. SHA-256's `zeroize`
/// feature wipes its hash state and block buffer on drop. The generic HKDF/HMAC
/// helpers do not wipe all these temporaries, so use the RFC 2104 construction
/// directly. Keys are shorter than SHA-256's 64-byte block; no key hashing or
/// variable-length HKDF output is needed.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut pad = Zeroizing::new([0x36; 64]);
    for (byte, key_byte) in pad.iter_mut().zip(key) {
        *byte ^= key_byte;
    }
    let mut inner = Sha256::new();
    inner.update(pad.as_slice());
    for part in parts {
        inner.update(part);
    }
    let mut inner_digest = Zeroizing::new([0; 32]);
    inner.finalize_into((&mut *inner_digest).into());

    // Convert K xor ipad into K xor opad without another key-bearing buffer.
    for byte in pad.iter_mut() {
        *byte ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(pad.as_slice());
    outer.update(inner_digest.as_slice());
    let mut output = Zeroizing::new([0; 32]);
    outer.finalize_into((&mut *output).into());
    output
}

#[cfg(test)]
mod tests;
