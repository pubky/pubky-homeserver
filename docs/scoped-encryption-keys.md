# Scoped encryption keys

## Permissions

Request `approval=v1` and the `e` action for scopes that need keys. Signers may
narrow scopes or decline `e` while approving storage access.

- `r` allows storage reads; `w` allows writes. Neither delivers keys.
- `e` delivers keys for encryption and decryption, without storage access.
- `/pub/chat/:rwe` requests read/write access and keys for chat.
- `/:rw,/pub/chat/:e` requests backup access everywhere and keys for chat.
  Use `/:rw` alone for backups that do not need plaintext.

Symmetric keys allow both encryption and decryption: `we` also lets an app
decrypt ciphertext it obtains, though private storage reads still require `r`.
Signers should show separate "Encrypt and decrypt content" consent for `e`.

## Compatibility

Grant flows default to bare grants, which reject `e`. V1 approvals require
support in the app and signer, plus a homeserver that accepts `e`. V1 flows
reject bare-grant responses without downgrading. Local signer sign-ins grant
root `rwe` access because the caller already holds the identity secret.

Approval and derivation versions are `v1`. Credential storage versions are
separate; see [persistence](#persistence-and-offline-recovery).

## Scope and derivation

Directory scopes deliver seeds for descendant files; exact-file scopes deliver
only that file's key. Trailing slashes matter: `/pub/app/` does not cover the
file `/pub/app`.

Call `ScopedEncryptionKeyBundle::derive_for_path()` with a canonical
`StoragePath` to get a zeroizing 32-byte file key. Directory paths return
`KeyDerivationError::DirectoryPath`; uncovered files return `OutsideScope`.
Lookup uses the first covering entry. Decoding rejects inconsistent overlapping
keys, so entry order does not affect the result. Directory seeds stay internal.

Keys depend on the identity secret, canonical path, and derivation version.
Paths use their decoded UTF-8 bytes, without Unicode normalization or case
folding. The hierarchy uses HKDF-SHA-256 with fixed labels for root, directory,
and file keys. See the
[derivation format](../pubky-common/src/encryption_keys.rs) and
[test vectors](../pubky-common/tests/fixtures/README.md). Changes require a
new derivation version. Derive keys for other purposes with separate HKDF
context labels.

### Encryption limitations

Apps manage ciphertext formats, fresh nonces, and binding ciphertext to its
resource. The homeserver stores opaque bytes; `/pub` remains publicly readable.

- Moving or renaming a file changes its key. Re-encrypt with the destination
  key and a fresh nonce, saving the destination before deleting the source.
  Handle partial failures; both keys and storage permissions are needed.
- Revocation cannot reclaim keys. They can decrypt past and future ciphertext
  at the same paths. Rotation needs a separate scheme; there is no forward
  secrecy.
- Anyone with a symmetric key can produce authenticated ciphertext. Storage
  write authorization remains the homeserver's responsibility.
- Filenames, directory structure, and storage metadata remain public.

## Persistence and offline recovery

V1 approvals use V2 credential storage, including approvals with no `e` scopes
and an empty key bundle. Bare grants use V1 storage and contain no keys. Keep
approvals and secret tokens out of logs and public metadata, even after expiry
or revocation.

Local sessions retain the signed approval in their exported secret token.
Browser storage supports local and delegated WebCrypto signers. Delegated
metadata is non-secret; its approval is encrypted with a separate,
non-extractable AES-GCM key in IndexedDB.

Offline recovery verifies the approval signature, grant binding, and key
scopes without network access or a valid grant. It creates no session; records
without keys return no bundle. Authentication still checks expiry and the
homeserver. Browser recovery needs the saved AES-GCM wrapping key, but not the
signing key. Deleting the record deletes its wrapping key. Non-extractability
prevents key export through WebCrypto, not theft of the browser profile.

To add keys to an existing session, request a fresh V1 approval with `e` and
save the new record ID. See [browser session upgrades][session-upgrades] for
replacement and older-SDK compatibility.

[session-upgrades]: grant-session-lifecycle.md#upgrading-stored-browser-sessions

## Approval delivery

The authorization link carries a shared `secret`; its hash identifies the
relay channel. The signer encrypts the signed approval with that secret, and
the app decrypts it before validation. `approval=v1` selects this signed format
even when the signer declines `e`.

Anyone with both the link and relay payload can recover the keys. Keep links
and pending-flow state confidential; delete pending state when finished or
abandoned.

The `pubky-grant-approval` JWS binds `version`, `grant`, and
`encryption_keys`. JSON secrets are 32 bytes encoded as unpadded base64url.
The app verifies the signature, format, client binding, timestamps, and
requested permissions. Delivered key scopes must exactly match the approved
`e` scopes. The homeserver receives and verifies only the inner grant and
proof. Keys stay with the app across credential cloning and bearer refresh.

## Relay limits

`http-relay` 0.7 and `pubky-testnet` default to **2 KiB (2,048 bytes)** per
body, including encoding, signatures, and encryption overhead. Scope lengths
affect size, so there is no fixed scope-count limit.

Oversized approvals fail authentication with HTTP 413. Rust returns
`RequestError::Server`; JS returns `RequestError` with `data.statusCode` 413.
The SDK does not reduce scopes or downgrade approvals.

Relay operators can raise the limit, for example to 16 KiB:

```sh
http-relay --max-body-size 16384
```

Embedded relays use `HttpRelay::builder().max_body_size(16 * 1024)`. Size the
limit for your approvals and configure reverse proxies accordingly. Apps cannot
change a remote relay's limit through SDK configuration.
