# Authenticate to an external service

Use an existing Pubky grant to authenticate your application to an external
service, such as an inbox. The SDK creates credentials using the grant's client
signing key. A Rust service can use the SDK verifier to check those credentials
and reject replayed proofs before issuing its own session. Exchange the grant
and proof for a service-owned credential, then use that credential for ordinary
requests.

This guide covers the APIs in this checkout:

- [Generate and submit credentials](#generate-and-submit-credentials) from JavaScript or Rust.
- [Verify credentials in a Rust service](#verify-credentials-in-a-rust-service).
- [Choose and operate a replay store](#choose-and-operate-a-replay-store).
- [Handle errors and retries](#handle-errors-and-retries).
- Look up the [protocol and verification rules](#protocol-reference).

## How the exchange works

1. Your application already has a grant-backed Pubky session from an approved
   login. The user’s root key signed the grant, which identifies a client key.
2. The SDK uses that client key to sign a proof of possession (PoP). The proof
   contains the target service's audience, the grant ID, a fresh random nonce,
   and an issue timestamp. A nonce is a single-use identifier for the exchange.
3. Your application sends `{ "grant": "<JWS>", "pop": "<JWS>" }` to the service.
   Each value uses JSON Web Signature (JWS) compact serialization.
4. The service calls `verify_and_consume`. The verifier checks the credentials
   and atomically records the nonce as consumed. Of concurrent exchanges using
   the same proof, at most one succeeds.
5. The service applies its own authorization policy to the verified identity
   and issues a service-owned session, represented by a bearer token, session
   cookie, or another mechanism the service supports.
6. Your application uses that service credential for subsequent requests. When
   the session expires, generate a fresh proof to establish another session.

Proof generation and verification make no network requests. Generating a proof
doesn't prompt the signer, export a private key, or refresh the homeserver bearer.
A valid grant still works when its homeserver bearer has expired. Existing SDK
session-restoration methods retain their network behavior.

### Use the proof to establish a session

Use the grant/PoP exchange at the service's authentication endpoint rather than
on every API request. A service session avoids repeatedly signing proofs,
transmitting the root-signed grant, verifying two signatures, and recording
nonce consumption. With the file replay store, each consumption also requires
a durable disk write.

An opaque bearer token is a straightforward choice: the application sends it in
`Authorization: Bearer <token>` on later requests. For browser applications, a
secure, HTTP-only session cookie can also fit. The service chooses the mechanism
and owns its logout, revocation, and session-management behavior.

The same grant/PoP pair cannot authenticate multiple requests: the first
successful exchange consumes its nonce. Per-request use would require a fresh
proof each time. Using a service session avoids that repeated work.

## Before you start

- Obtain a grant-backed session. Cookie-only sessions have no grant view and
  can't create these credentials.
- Agree on an audience identifier with the service. The examples use
  `inbox:production`; replace it with your service's identifier on both sides.
- Define the service's authentication endpoint and response format. The example
  URL `https://inbox.example.com/auth/session` is illustrative, not a Pubky endpoint.
- For native Rust verification, enable the `service-auth-verifier` feature.

### Choose an audience

An audience binds a proof to the service you intend to authenticate to. Without
that binding, someone who obtains a valid proof—including the service receiving
it—could submit it to another service that accepts Pubky credentials.

For example, a proof signed for `inbox:production` must be rejected by a service
configured for `calendar:production`. Because the audience is part of the signed
proof, changing it invalidates the signature.

The audience prevents cross-service replay. The nonce check prevents repeated
use at the intended service. You need both: separate services don't necessarily
share nonce history.

An audience is an opaque string of **1–1,024 UTF-8 bytes**. It doesn't need to be
a URL. The SDK preserves it exactly, without trimming, case folding, URL parsing,
or Unicode normalization. `inbox:production`, `https://inbox.example.com`, and
`Inbox` are valid identifiers, but `Inbox` and `inbox` are different audiences.

## Generate and submit credentials

Generate a fresh proof for each exchange attempt, including retries after a
failed request or a lost response. Treat the returned credentials as sensitive.

### JavaScript

Pass an existing `Session` to this function. It returns the service's response;
your application handles the service-specific bearer or session body.

```typescript
import type { Session } from "@synonymdev/pubky";

export async function authenticateService(session: Session): Promise<Response> {
  const grant = session.grant;
  if (!grant) {
    throw new Error("A grant-backed Pubky session is required");
  }

  const credentials = await grant.createServiceAuthProof("inbox:production");
  const response = await fetch("https://inbox.example.com/auth/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credentials),
  });

  if (!response.ok) {
    throw new Error(`Service authentication failed: HTTP ${response.status}`);
  }
  return response;
}
```

The method supports SDK-held keys and non-extractable browser WebCrypto keys.
Applications don't need to access IndexedDB or export the signing key.

### Rust

The Rust method returns `ServiceAuthProof`, which contains the original grant
and the signed proof. This helper handles the absence of a grant view explicitly:

```rust
use pubky::{PubkySession, ServiceAuthProof};

pub async fn create_service_credentials(
    session: &PubkySession,
) -> Result<ServiceAuthProof, Box<dyn std::error::Error>> {
    let grant = session.as_grant().ok_or_else(|| {
        std::io::Error::other("A grant-backed Pubky session is required")
    })?;
    Ok(grant.create_service_auth_proof("inbox:production").await?)
}
```

Serialize the result as JSON and submit it with your application's HTTP client.
The SDK method creates credentials; your application owns the HTTP exchange
and the resulting service session.

## Verify credentials in a Rust service

### Enable the verifier

Enable `service-auth-verifier` on your `pubky` dependency. For a service project
next to this checkout, the dependency entries look like this. Adjust the local
path to your checkout; merge these entries with your existing dependencies.

```toml
[dependencies]
pubky = { path = "../pubky-core/pubky-sdk", features = ["service-auth-verifier"] }
serde_json = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Verification and both replay stores live in the SDK. The feature adds no runtime
dependencies beyond those the SDK already uses.

### Create a long-lived verifier

Call this function once at service startup, inside your Tokio runtime. The store
creates `./inbox-replay` beneath the existing current directory. Use a persistent
location appropriate for your deployment.

```rust
use pubky::service_auth::{
    FileReplayStore, FileReplayStoreOptions, ServiceAuthVerifier,
    VerificationPolicy,
};

pub async fn create_verifier(
) -> Result<ServiceAuthVerifier<FileReplayStore>, Box<dyn std::error::Error>> {
    let store = FileReplayStore::open(
        "./inbox-replay",
        FileReplayStoreOptions {
            max_entries: 100_000,
            max_journal_bytes: 16 * 1024 * 1024,
        },
    )
    .await?;

    Ok(ServiceAuthVerifier::new(
        "inbox:production",
        VerificationPolicy::default(),
        store,
    )?)
}
```

Keep the verifier in your application's shared state. Cloning a verifier with
either built-in store shares that store's state. Don't create a new memory store
per request or try to open a new file-store owner for every handler.

### Authenticate each exchange

Configure your HTTP framework to bound request-body reading before JSON
deserialization. The verifier's JWS limits apply after the credentials have
been read; they don't bound HTTP-body allocation or JSON-envelope overhead.

Pass the bounded body to a helper like this:

```rust
use pubky::service_auth::{
    FileReplayStore, ServiceAuthProof, ServiceAuthVerifier, VerifiedServiceAuth,
};

pub async fn authenticate_request(
    verifier: &ServiceAuthVerifier<FileReplayStore>,
    body: &[u8],
) -> Result<VerifiedServiceAuth, Box<dyn std::error::Error>> {
    let credentials: ServiceAuthProof = serde_json::from_slice(body)?;
    Ok(verifier.verify_and_consume(&credentials).await?)
}
```

A successful result means both signatures, claim bindings, and time checks
passed, and the nonce was consumed. You don't need a separate nonce check.
Storage failures reject authentication rather than bypassing replay protection.

### Authorize the identity and issue your session

Use the returned `VerifiedServiceAuth` to make your service's authorization
decision. Then issue your service-owned session with an expiry no later than
`grant_expires_at()`. You can apply a shorter lifetime:

```text
session expiry = min(service-defined expiry, grant expiry)
```

Return the service credential or set the session cookie according to your API
contract. Ordinary API endpoints authenticate that credential rather than
calling `verify_and_consume` again. The SDK verifies the exchange; your service
implements session issuance and subsequent request authentication.

| Accessor | Verified value |
| --- | --- |
| `identity()` | The grant's root identity, `iss` |
| `client_id()` | The root-signed application identifier |
| `grant_id()` | The grant's `jti` |
| `grant_expires_at()` | Grant expiration in Unix seconds |
| `grant_claims()` | Immutable reference to the complete `GrantClaims` |
| `proof_claims()` | Immutable reference to the complete `ServiceProofClaims` |

Proof claims expose the audience, nonce, grant binding, and issue time for
auditing or request correlation. Reading or retaining them doesn't make the
proof reusable.

Verified provenance doesn't establish service permissions. Homeserver storage
capabilities aren't inbox permissions, and `client_id` isn't a verified web
origin. Apply your own policy to the authenticated identity.

## Choose and operate a replay store

Choose storage explicitly; neither store evicts unexpired entries to make room.

| Store | Persistence and sharing | Configuration |
| --- | --- | --- |
| `MemoryReplayStore` | Clones share process-local state. Restarting or creating a new store loses replay history. | `MemoryReplayStore::new(max_entries)`; capacity must be positive. |
| `FileReplayStore` | History survives restart. Exactly one process owns the directory; clones share that owner. | Positive `max_entries` and `max_journal_bytes` of at least 161 bytes. |

For process-local use, replace the store in the startup example with
`MemoryReplayStore::new(100_000)?` and change the verifier's type parameter to
`MemoryReplayStore`. Use file storage when you need replay protection across
restarts.

For multiple service instances on separate machines, implement `ReplayStore`
over one shared authoritative backend. `ReplayRequest` exposes the replay key,
time bounds, and policy fingerprint. The adapter must provide atomic consumption
and the same retention, clock, capacity, policy-binding, and cancellation
guarantees. Separate memory stores or separate journal directories don't provide
cross-instance replay protection.

### Maintain the file store

The store directory contains these reserved files:

- `owner.lock` holds the exclusive owner lock. Don't delete it.
- `journal` contains a versioned header and checksummed, hash-chained records.
- `journal.next` is a temporary compaction snapshot. Recovery ignores it unless
  compaction has renamed it to `journal`.

Each successful consumption follows a journal append and `sync_all`. Compaction
writes and syncs the unexpired records, atomically replaces the journal, and syncs
the directory. The separate lock file preserves ownership during replacement.

Journal size and live-entry count are bounded by your configuration. Compaction
can temporarily use a second journal's worth of disk space. Recovery also obeys
the configured journal-size limit. Blocking file work runs on Tokio's blocking
pool and continues safely if an async caller cancels.

After a write or sync failure, the open handle becomes unavailable. Reopen the
store to recover complete records conservatively as consumed. Incomplete
records, checksum failures, missing journals, and unsupported formats reject
opening; the SDK never automatically resets them. If recovery is impossible,
follow the replacement procedure below before starting with fresh state.

Use trusted local storage and an accurate system clock. Stores reject observed
clock rollback; persisted clock floors prevent cleanup followed by a restart
from making discarded nonces usable again. Restoring an older journal backup or
deleting the store can undo replay protection. Checksums detect corruption but
don't authenticate files against someone with filesystem write access.

### Change policy or replace replay state

Both stores bind themselves to an audience and verification-policy fingerprint.
Changing the audience, time settings, or input limits causes `PolicyMismatch`.
A failed file consumption can still persist this binding or a consumed nonce.

To replace replay state or change its bound policy:

1. Stop accepting authentication exchanges that use the old state.
2. Wait for the larger old/new maximum-proof-age window plus the larger old/new
   future-skew window. This lets previously acceptable proofs expire under either
   policy. With unchanged defaults, wait at least 210 seconds.
3. Close the old owner and start a verifier with fresh storage and the intended
   policy. Don't delete a live owner's files.

## Handle errors and retries

### Credential generation fails

Rust returns `ServiceAuthProofError`. JavaScript uses `PubkyError.data.reason`
for the corresponding structured reasons below. Invalid audiences use the JS
name `InvalidInput`; the other listed reasons use `AuthenticationError`.

| Rust variant | JavaScript reason | What to check |
| --- | --- | --- |
| `InvalidAudience` | `InvalidServiceAudience` | Use 1–1,024 UTF-8 bytes and the service's exact configured identifier. |
| `GrantExpired` | `GrantExpired` | Obtain a valid grant before generating another proof. |
| `InvalidGrant` | `InvalidGrant` | Check the grant's validity period and its signing-key binding. |
| `SigningKeyUnavailable` | `SigningKeyUnavailable` | Check browser storage access and whether the bound key still exists. |
| `SigningFailed` | `SigningFailed` | Inspect the signing diagnostic. |

Rust's `SessionState` variant retains the underlying SDK error for browser
coordination or local lifecycle failures. JavaScript preserves that underlying
error's shape, which may have no `data.reason`. A removed session or pending
logout rejects proof generation locally. Cookie sessions have no grant view.

### Verification or replay storage fails

`verify_and_consume` returns `ServiceAuthVerificationError`; its `Storage`
variant wraps `ReplayStoreError`. Map these errors to your service's HTTP
responses rather than treating every failure as a successful login or an
automatic retry.

| Error or symptom | Action |
| --- | --- |
| `AudienceMismatch` | Compare the client audience with trusted service configuration, including case and whitespace. |
| `InvalidTimestamp`, `GrantExpired`, or `Storage(OutsideTimeWindow)` | Check system time, grant expiry, and the acceptance window. Generate a fresh proof when the grant remains valid. |
| `Replay` | Generate a new proof. Don't resubmit the consumed credentials. |
| `InputTooLarge`, malformed credentials, or invalid signatures/bindings | Reject the exchange and check the producer's wire format and configured limits. |
| `Storage(AlreadyOpen)` | Reuse the existing owner or stop it before opening the same file store. |
| `Storage(Capacity)` | Check live-entry and journal limits. Don't evict unexpired records or reset replay history. |
| `Storage(ClockRollback)` | Restore accurate time at or beyond the recorded clock floor. Don't clear the store to bypass the check. |
| `Storage(PolicyMismatch)` | Restore the bound configuration or use the policy-change procedure above. |
| `Storage(Unavailable)`, `Storage(Io(_))`, or `Storage(Corrupt(_))` | Inspect the underlying failure and follow the file-store recovery procedure. |

An exchange can consume a nonce even if a later authorization decision, session
creation, or HTTP response fails. Cancellation and a lost response can also leave
the outcome uncertain. Generate a fresh proof for the next attempt; nonce
consumption isn't rolled back with your service's session transaction.

## Expiration and session lifecycle

The short proof window controls when credentials can be exchanged. It doesn't
set the lifetime of the resulting service session. That session must expire no
later than the grant and may expire sooner under service policy.

Any session renewal or token-refresh mechanism must preserve the grant-expiry
ceiling. To establish another session through Pubky credentials, generate a fresh
proof from a still-valid grant. Once the grant expires, obtain a valid grant
before authenticating again.

Homeserver signout or grant revocation doesn't automatically invalidate external
sessions or prevent an otherwise unexpired grant from being used at the service.
Removing a local browser session prevents further use through its managed
handles, but doesn't revoke sessions already issued by external services.

## Protocol reference

### Credentials and proof claims

The JSON body contains two compact JWS strings:

- `grant`: the original root-signed grant, unchanged. Its type is `pubky-grant`.
- `pop`: an Ed25519 proof with header
  `{"alg":"EdDSA","typ":"pubky-service-pop-v1"}`.

| Proof claim | Value |
| --- | --- |
| `aud` | Exact audience string |
| `gid` | Supplied grant's `jti` |
| `nonce` | 32 random bytes, unpadded base64url: 43 characters |
| `iat` | Issue time as integer Unix seconds |

All JWS segments use unpadded base64url. The signature covers the original ASCII
`base64url(header).base64url(payload)` bytes. The root key signs the grant; the
key identified by its `cnf` signs the proof. The grant's required fields are
`iss`, `client_id`, `caps`, `cnf`, `jti`, `iat`, and `exp`.

The verifier checks both signatures, grant validity, exact audience equality,
grant binding, nonce format, and proof freshness before allocating replay state.
It accepts only `alg` and `typ` headers and the documented grant/proof fields.
It rejects header extensions, unsupported algorithms or types, unknown claims,
duplicate fields, padded or noncanonical base64url, and extra JWS segments.
External proofs and homeserver `pubky-pop` proofs aren't interchangeable.
Decoding claims alone doesn't authenticate them.

### Verification policy

`VerificationPolicy::default()` defines these values:

| Field | Default | Accepted configuration |
| --- | --- | --- |
| `max_proof_age_seconds` | 180 | 1–86,400 seconds |
| `future_clock_skew_seconds` | 30 | 0–86,400 seconds |
| `max_grant_bytes` | 65,536 | Positive compact-JWS byte limit |
| `max_proof_bytes` | 16,384 | Positive compact-JWS byte limit |

Let `now` be the current Unix second, `max_age` the maximum proof age, and `skew`
the future-clock allowance. Acceptance requires:

- `grant.iat < grant.exp` and `now < grant.exp`, with no expiration grace.
- `max(grant.iat, proof.iat) - skew <= now < proof.iat + max_age`.
- `grant.iat - skew <= proof.iat < grant.exp`.

Subtraction saturates at zero; addition overflow is rejected. The replay
retention deadline is `min(grant.exp, proof.iat + max_age)`, exclusive. There is
no additional old-proof grace beyond `max_age`. The store checks this window
under its consumption lock, and verification checks it again after persistence.

Audience limits count bytes, not characters: `é` repeated 512 times is valid;
513 times is not. Composed and decomposed Unicode strings remain different
audiences, even if they look the same.

### Replay keys

The replay key is a BLAKE3 digest of length-prefixed issuer key bytes, grant ID,
exact audience UTF-8 bytes, and canonical encoded nonce. Each length is an
unsigned 64-bit big-endian byte count. The policy fingerprint similarly includes
the proof type, audience, maximum age, future skew, and both input limits.

### Interoperability vectors

The [service-auth v1 fixture](../pubky-sdk/tests/fixtures/service-auth-v1.json)
contains fixed test-only keys, claims, an evaluation time, and exact credentials
produced independently with Node's Ed25519 implementation. SDK tests assert
byte-identical signing and verify both signatures. Evaluate this historical
fixture at its documented time, not the current wall clock.

At that time, the vector is valid for the exact audience ` Inbox:é/生产 `.
Changing its case or whitespace must fail. The proof is acceptable at Unix
second 1,700,000,239 and expired at 1,700,000,240. Using type `pubky-pop`, adding
a duplicate `aud`, appending base64 padding, or changing a claim without resigning
must fail. Repeating a successful exchange must fail as replay.
