# Scoped encryption keys

Scoped encryption keys let an app encrypt and decrypt a user's content without
holding the user's identity secret. The app requests the `e` action for one or
more storage scopes. If the user approves, the signer derives keys for those
scopes and sends them to the app together with the grant.

This guide is for app developers who request keys and for signer developers
who approve them. The [reference](#reference) at the end covers key derivation,
approval delivery, and relay limits for protocol implementers and relay
operators.

> [!WARNING]
> Keys are permanent. They're derived from the user's identity secret, so
> revoking the grant or letting it expire doesn't take them back, and there's
> no key rotation. An app that once received a key can decrypt everything
> encrypted under that key, including content written later. A key for a
> directory covers every file below it: `e` on `/` gives the app every key the
> user will ever have.

## Request keys in your app

1. Select the signed approval format: `GrantApprovalFormat::SignedApprovalV1`
   in Rust, or `approvalFormat: "signedApprovalV1"` in JS. The default bare
   grant format can't carry keys and rejects requests that contain `e`.
2. Add the `e` action to each scope that needs keys, for example
   `/pub/chat/:rwe`.
3. After the user approves, read the keys from the session. Check the approved
   scopes first: the signer may narrow them or decline `e`.
4. Derive keys with `derive_for_path()`. How you map keys to content is up to
   you. You can derive a key for each file, or derive one key from a single
   path and reuse it for many files.

For complete examples, see the [Rust SDK README](../pubky-sdk/README.md#scoped-encryption-keys)
and the [JS SDK README](../pubky-sdk/bindings/js/README.md#scoped-encryption-keys).

`signer.signin()` grants root storage access (`/:rw`) without keys. To receive
keys, you must request `e` through a signed approval flow.

## Choose scopes and actions

The `e` action is separate from storage access:

- `r` allows storage reads, and `w` allows storage writes. Neither delivers
  keys.
- `e` delivers keys for encryption and decryption. It doesn't grant storage
  access.

Examples:

- `/pub/chat/:rwe` requests read and write access and keys for `/pub/chat/`.
- `/:rw,/pub/chat/:e` requests storage access everywhere, for example for
  backups, and keys only for `/pub/chat/`. Use `/:rw` alone for backups that
  don't need plaintext.

The keys are symmetric, so every key both encrypts and decrypts. An app with
`we` can decrypt any ciphertext it obtains, even though reading private storage
still requires `r`.

Directory scopes, which end with `/`, cover every file below them. File scopes
cover only that file. Trailing slashes matter: `/pub/app/` doesn't cover the
file `/pub/app`. Request the narrowest scopes your app needs.

## Versions

Several parts of this feature have their own version. They change
independently.

| What | Where it appears | Values |
| --- | --- | --- |
| Approval format | `approval` link parameter; `GrantApprovalFormat` in Rust; `approvalFormat` in JS | Bare grant (default): no parameter, `BareGrant`, `bareGrant`. Signed approval: `approval=v1`, `SignedApprovalV1`, `signedApprovalV1`. |
| Key derivation | `version` field of the key bundle | `v1` |
| Exported secret token | Token prefix | `pubky-grant-credential-v1` for bare grants; `pubky-grant-credential-v2` for signed approvals |
| Browser session record | `version` field in IndexedDB | `pubky-session-v1` for bare grants; `pubky-session-v2` for signed approvals |

A signed approval always uses the `v2` token and record formats, even if the
signer declined `e` and the key bundle is empty.

## Compatibility and deployment

Signed approvals with `e` intentionally break compatibility. Each component
must support them:

- **Homeserver:** older homeservers reject any grant containing `e`. The app
  can't remove `e` from the grant to work around this: the signer signed the
  grant, and changing it invalidates the signature.
- **Signer:** older signers can't parse links that contain `e`.
- **App:** an app that requests a signed approval rejects a bare grant
  response. The SDK doesn't fall back to a bare grant.

Roll out support in this order:

1. Upgrade homeservers.
2. Upgrade signers.
3. Release apps that request `e`.

Requests that use only `r` and `w` remain compatible with older homeservers,
including signed approvals without `e`.

## Troubleshooting

**The grant exchange fails after the user approved a request with `e`.**
The user's homeserver probably predates `e` and rejected the grant. Ask the
homeserver operator to upgrade. Until then, request storage access without `e`.

**The app rejects the signer's response as an invalid approval.**
The signer may not support signed approvals. An older signer can ignore
`approval=v1` and return a bare grant, which the app rejects. Update the signer,
or start a bare grant flow without `e`.

**The app keeps waiting after the user approved.**
The approval may exceed the relay's body limit. The relay rejects it with HTTP
413 and the app is never notified. The signer receives the error. Request fewer
or shorter scopes, or raise the relay limit. See [relay limits](#relay-limits).

**Deriving a key fails with `OutsideScope` or `DirectoryPath`.**
`OutsideScope` means no approved scope covers the file; the signer may have
narrowed the scope or declined `e`. `DirectoryPath` means you passed a
directory path. Keys are derived only from file paths; pass a file path even if
you use the key for more than one file.

## Encryption limitations

The SDK delivers keys; it doesn't encrypt content for you. Your app chooses
the ciphertext format, generates a fresh nonce for every encryption, and binds
each ciphertext to its resource. The homeserver stores opaque bytes, and
everything under `/pub` remains publicly readable.

- **Renames can change keys.** If you derive a key per file, moving or
  renaming the file changes its key. Re-encrypt the content with the
  destination key and a fresh nonce. Save the
  destination before deleting the source, and handle partial failures. You need
  keys and storage permissions for both paths.
- **No revocation or rotation.** See the warning at the top of this guide.
  There's no forward secrecy.
- **Keys don't authenticate writers.** Anyone with a key can produce valid
  ciphertext. Storage write authorization remains the homeserver's job.
- **Metadata stays public.** Filenames, directory structure, and storage
  metadata aren't encrypted.

The SDK wipes key buffers when it drops them. Temporary copies made during
serialization or inside cryptographic libraries aren't guaranteed to be wiped.

## Persistence and offline recovery

*Restore material* is the data needed to restore a session or recover its
keys: the grant, the client key or a reference to it, and the signed approval.
The signed approval contains the keys. Keep restore material out of logs and
public metadata, even after the grant expires or is revoked.

How each storage option keeps the signed approval:

- **Exported secret token:** `export_local_secret()` and `exportLocalSecret()`
  include the signed approval in the token.
- **Browser session store:** `browserSessionStore.save()` stores restore
  material as plaintext in IndexedDB, for both local and delegated WebCrypto
  signers. Delegated signing keys stay non-extractable, but the keys inside the
  signed approval don't. IndexedDB is the trust boundary: any script on the same
  origin, or anyone with a copy of the browser profile, can read the saved keys.
  Don't log or export browser records.

Offline recovery returns the keys from saved restore material without network
access. It verifies the approval signature, its binding to the grant, and the
key scopes, but it doesn't require a valid grant and creates no session:

- Bare grant records return no key bundle.
- Signed approvals without `e` scopes return an empty bundle.
- Browser recovery needs the saved record but not the delegated signing key.
- Browser recovery checks that the approval's issuer and grant ID match the
  requested record, so it rejects swapped restore material.
- When you recover keys from saved material yourself, check whose keys they
  are. In Rust, `restore_encryption_keys_with_claims()` and
  `restore_encryption_keys_from_approval()` also return the grant claims;
  compare `iss` and `jti` with the user and grant you expect.
- Deleting the record removes its restore material.

Restoring an authenticated session still checks grant expiry and contacts the
homeserver.

To add keys to an existing session, request a new signed approval with `e` and
save the new record ID. See
[upgrading stored browser sessions][session-upgrades] for replacing the old
record and for compatibility with older SDKs.

[session-upgrades]: grant-session-lifecycle.md#upgrading-stored-browser-sessions

## Reference

### Key derivation

A key depends on the identity secret, the canonical path, and the derivation
version. Paths are used as decoded UTF-8 bytes, without Unicode normalization or
case folding, so NFC and NFD spellings of a name produce different keys.

The hierarchy uses HKDF-SHA-256 with fixed labels for the root, directory, and
file levels. A directory scope delivers a *directory seed*, from which the app
derives keys for paths below it. A file scope delivers that file's *file key*
directly. The SDK API never exposes directory seeds; it only returns file keys.

Call `derive_for_path()` on the key bundle with a canonical `StoragePath` to get
a 32-byte file key that's wiped when dropped. If several approved scopes cover
the file, they derive the same key; the SDK rejects bundles whose overlapping
entries disagree.

See the [derivation format](../pubky-common/src/encryption_keys.rs) and the
[test vectors](../pubky-common/tests/fixtures/README.md). Any change to the
derivation requires a new derivation version. To derive keys for other
purposes, use separate HKDF context labels.

### Approval delivery

The authorization link carries a shared `secret`. Its hash identifies the relay
channel. The signer encrypts the signed approval with that secret, and the app
decrypts it before validating it. With `approval=v1`, the signer sends a signed
approval even when it declines `e`.

Anyone with both the link and the relay payload can recover the keys. Keep
authorization links and pending flow state confidential, and delete pending
state when the flow finishes or is abandoned.

The signed approval is a JWS of type `pubky-grant-approval`. It binds
`version`, `grant`, and `encryption_keys`. Each secret is 32 bytes, encoded in
JSON as unpadded base64url.

The app checks:

- the signature, against the grant's issuer;
- the format and versions;
- the client binding;
- the timestamp order (`iat` before `exp`);
- that the approved capabilities don't exceed the request;
- that the delivered key scopes exactly match the approved `e` scopes.

The app leaves grant expiry to the homeserver's clock during grant exchange.
The homeserver receives and verifies only the inner grant and proof, never the
keys. Keys stay with the app across credential cloning and bearer refresh.

### Relay limits

`http-relay` 0.7 and `pubky-testnet` limit each body to **2 KiB (2,048
bytes)** by default. The limit includes encoding, signatures, and encryption
overhead. The signed grant is embedded in the approval and base64url-encoded
again as part of the outer JWS payload. This adds roughly 33% to the embedded
grant's size, on top of the key bundle and outer signature. Size depends on
scope lengths, so there's no fixed limit on the number of scopes.

When the signer posts an oversized approval, the relay rejects it with HTTP
413. The signer receives `RequestError::Server` in Rust or a `RequestError`
with `data.statusCode` 413 in JS. The app receives neither the approval nor the
error, so its flow keeps waiting until it expires or is cancelled. The SDK
doesn't reduce scopes or fall back to a bare grant.

Relay operators can raise the limit, for example to 16 KiB:

```sh
http-relay --max-body-size 16384
```

For embedded relays, use `HttpRelay::builder().max_body_size(16 * 1024)`. Size
the limit for your approvals and configure reverse proxies to match. Apps can't
change a remote relay's limit through SDK configuration.
