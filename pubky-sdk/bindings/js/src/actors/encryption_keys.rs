use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

#[wasm_bindgen(inline_js = r#"
export async function __pubkyImportEncryptionCryptoKey(bytes) {
    try {
        if (!globalThis.crypto?.subtle) {
            throw new Error("WebCrypto is unavailable; use a secure context.");
        }
        return await globalThis.crypto.subtle.importKey(
            "raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
    } finally {
        bytes.fill(0);
    }
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = __pubkyImportEncryptionCryptoKey)]
    fn import_crypto_key(bytes: &js_sys::Uint8Array) -> js_sys::Promise;
}

/// Verified scoped encryption keys recovered independently of authentication.
/// This object grants no storage access. Secret bytes are zeroized on free/drop.
#[wasm_bindgen]
pub struct EncryptionKeys(pub(crate) pubky_common::encryption_keys::ScopedEncryptionKeyBundle);

#[wasm_bindgen]
impl EncryptionKeys {
    /// Recover keys from an exportLocalSecret() token without network access.
    /// Verifies the signed approval and grant binding even if the grant expired
    /// or was revoked. Legacy tokens without keys return undefined.
    #[wasm_bindgen(js_name = "fromLocalSecret")]
    pub fn from_local_secret(token: &str) -> JsResult<Option<EncryptionKeys>> {
        Ok(pubky::GrantCredential::restore_encryption_keys(token)?.map(Self))
    }

    /// Approved scopes; directory scopes cover descendant files.
    #[wasm_bindgen(getter)]
    pub fn scopes(&self) -> Vec<String> {
        self.0.scopes().map(ToString::to_string).collect()
    }

    /// Derive a 32-byte content key for a canonical decoded file path.
    /// Rejects directories and files outside the approved scopes. The caller
    /// owns the JS byte copy and should clear it after use.
    #[wasm_bindgen(js_name = "deriveForPath")]
    pub fn derive_for_path(&self, path: &str) -> JsResult<js_sys::Uint8Array> {
        derive_file_key(&self.0, path)
    }

    /// Derive a non-extractable AES-GCM-256 key for WebCrypto encryption/decryption.
    /// Rejects directories and files outside approved scopes. Requires WebCrypto.
    /// Temporary JS key bytes are cleared after import, including on failure.
    #[wasm_bindgen(js_name = "deriveEncryptionCryptoKey")]
    pub async fn derive_encryption_crypto_key(&self, path: &str) -> JsResult<web_sys::CryptoKey> {
        import_encryption_crypto_key(self.derive_for_path(path)?).await
    }
}

pub(crate) async fn import_encryption_crypto_key(
    bytes: js_sys::Uint8Array,
) -> JsResult<web_sys::CryptoKey> {
    JsFuture::from(import_crypto_key(&bytes))
        .await
        .map_err(|error| {
            let message = js_sys::Error::from(error).message();
            PubkyError::new(PubkyErrorName::ClientStateError, String::from(message))
        })?
        .dyn_into()
        .map_err(|_| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                "WebCrypto returned an invalid CryptoKey.",
            )
        })
}

pub(crate) fn derive_file_key(
    keys: &pubky_common::encryption_keys::ScopedEncryptionKeyBundle,
    path: &str,
) -> JsResult<js_sys::Uint8Array> {
    let path = pubky_common::StoragePath::new(path).map_err(|_| {
        PubkyError::new(
            PubkyErrorName::InvalidInput,
            "Invalid canonical storage path.",
        )
    })?;
    let secret = keys
        .derive_for_path(&path)
        .map_err(|error| PubkyError::new(PubkyErrorName::InvalidInput, error.to_string()))?;
    Ok(js_sys::Uint8Array::from(secret.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::StoragePath;
    use serde::Deserialize;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen(inline_js = r#"
export async function __pubkyTestEncryptionCryptoKey(key, raw) {
    if (key.extractable || key.algorithm.name !== "AES-GCM" ||
        key.algorithm.length !== 256 ||
        key.usages.join(",") !== "encrypt,decrypt") {
        throw new Error("Unexpected CryptoKey properties.");
    }
    let exportRejected = false;
    try {
        await crypto.subtle.exportKey("raw", key);
    } catch (_) {
        exportRejected = true;
    }
    if (!exportRejected) throw new Error("Key was exportable.");

    const rawKey = await crypto.subtle.importKey(
        "raw", raw, "AES-GCM", false, ["decrypt"]);
    raw.fill(0);
    const algorithm = { name: "AES-GCM", iv: crypto.getRandomValues(new Uint8Array(12)) };
    const plaintext = new TextEncoder().encode("scoped content");
    const ciphertext = await crypto.subtle.encrypt(algorithm, key, plaintext);
    for (const decryptKey of [key, rawKey]) {
        const decrypted = new Uint8Array(
            await crypto.subtle.decrypt(algorithm, decryptKey, ciphertext));
        if (decrypted.toString() !== plaintext.toString()) {
            throw new Error("Derived key did not decrypt the expected content.");
        }
    }
}
"#)]
    extern "C" {
        #[wasm_bindgen(js_name = __pubkyTestEncryptionCryptoKey)]
        fn test_crypto_key(key: &web_sys::CryptoKey, raw: &js_sys::Uint8Array) -> js_sys::Promise;
    }

    #[wasm_bindgen_test]
    async fn crypto_key_matches_raw_derivation_and_enforces_scopes() {
        let bundle = pubky_common::encryption_keys::ScopedEncryptionKeyBundle::from_identity_secret(
            &[7; 32],
            &[StoragePath::new("/pub/chat/").unwrap()],
        );
        let keys = EncryptionKeys(bundle);
        let path = "/pub/chat/message";
        let key = keys.derive_encryption_crypto_key(path).await.unwrap();
        let raw = keys.derive_for_path(path).unwrap();
        JsFuture::from(test_crypto_key(&key, &raw)).await.unwrap();

        for path in ["/", "/pub/chat/", "/pub/other/message", "not-a-path"] {
            let error = keys.derive_encryption_crypto_key(path).await.unwrap_err();
            assert!(matches!(error.name, PubkyErrorName::InvalidInput));
        }
    }

    #[wasm_bindgen_test]
    async fn crypto_key_import_clears_temporary_bytes_on_success_and_failure() {
        for length in [32, 31] {
            let bytes = js_sys::Uint8Array::from(vec![7; length].as_slice());
            let result = import_encryption_crypto_key(bytes.clone()).await;
            assert_eq!(result.is_ok(), length == 32);
            assert_eq!(bytes.to_vec(), vec![0; length]);
        }
    }

    #[derive(Deserialize)]
    struct Fixture {
        version: String,
        identity_secret_hex: String,
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Vector {
        path: StoragePath,
        key_hex: String,
    }

    fn hex_bytes(hex: &str) -> [u8; 32] {
        std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
    }

    #[wasm_bindgen_test]
    fn file_keys_match_shared_vectors() {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../../../pubky-common/tests/fixtures/hierarchical-keys-v1.json"
        ))
        .unwrap();
        assert_eq!(
            fixture.version,
            pubky_common::encryption_keys::DERIVATION_VERSION
        );
        let identity_secret = hex_bytes(&fixture.identity_secret_hex);
        for vector in fixture.vectors {
            if vector.path.is_directory() {
                continue;
            }
            let parent = &vector.path.as_str()[..=vector.path.as_str().rfind('/').unwrap()];
            for scope in ["/", parent] {
                let bundle =
                    pubky_common::encryption_keys::ScopedEncryptionKeyBundle::from_identity_secret(
                        &identity_secret,
                        &[StoragePath::new(scope).unwrap()],
                    );
                let keys = EncryptionKeys(bundle);
                let actual = keys.derive_for_path(vector.path.as_str()).unwrap();
                assert_eq!(
                    actual.to_vec(),
                    hex_bytes(&vector.key_hex),
                    "{}",
                    vector.path
                );
            }
        }
    }
}
