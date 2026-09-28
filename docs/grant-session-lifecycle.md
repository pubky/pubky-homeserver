# Grant sessions in multiple tabs

Homeservers advertising `grant-session-slots` support multiple sessions under one
grant. Each session has a slot ID and a short-lived bearer. Refresh replaces the
bearer in that slot.
The SDK reuses a valid bearer that already lasts until grant expiry.

## Browser applications

Use `browserSessionStore.save(session)` after authentication and
`browserSessionStore.restore(id)` when restoring an account. Save the session
before using it for requests. The original handle and its clones then join the
shared browser session.

- Tabs on the same origin share one slot and bearer for each stored grant.
  Opening, closing, duplicating or reloading tabs does not allocate another slot.
  Different origins and browser profiles have separate slots, even for the same grant.
- IndexedDB stores the grant restore material, current bearer and slot ID.
  Delegated WebCrypto private keys remain non-extractable. Treat the stored
  bearer as a credential; do not log or export the browser record.
- Authenticated requests hold shared Web Locks until response headers arrive.
  Refresh takes an exclusive lock and saves its result before releasing it.
  Requests can run concurrently; a slow request can delay refresh. Response
  bodies and open event streams do not retain the lock.
- A refresh marker survives a lost response or tab closure. The next operation
  exchanges into the same slot before using the bearer. A replayable request
  rejected with 401 gets at most one recovery attempt. Transport failures and
  other HTTP errors do not replay writes.
- Browser save and restore require IndexedDB, Web Locks, a secure context and
  homeserver `grant-session-slots` support. `isAvailable()` checks browser
  facilities, not homeserver support. `sessionStorage` is no longer required.
- Signout revokes the grant and all its sessions, including on other origins.
  A failed signout remains pending and blocks requests; retry signout, or restore
  the saved record to finish revocation. Successful signout removes the saved
  record and its delegated key.
- `remove`, `clear` and `clearAll` only delete local data. Browser-managed handles
  stop working after their record is removed. These operations do not revoke the
  grant or delete its server-side sessions.

The SDK dispatches `pubky-session-changed` on `window` after local removal or
successful signout, and forwards the notification to other tabs with
BroadcastChannel when available. `event.detail` contains `{ id, action }`:
`action` is `removed` for one record or `cleared` for all records (`id: null`).
Applications decide how to update their UI. Requests always check persisted
state, so missed notifications cannot restore removed credentials.

Generic Rust/JS `restore_session`/`restoreSession` creates a new independent
session on supporting homeservers. Browser applications should use the browser
store to share sessions across tabs. Requests made with a manually copied bearer
are outside this coordination.

### Upgrading stored browser sessions

Existing grant records remain readable. On the first restore, the SDK saves a
shared slot and bearer in the existing record. Per-tab sessions from older SDKs
still count toward the cap until expiry, so this transition needs a free slot.
Reload older app tabs to move them onto the shared-session SDK; older tabs do not
participate in its locks. A saved session from the new SDK keeps its slot even
when every tab closes.

## Homeserver configuration

```toml
[grant_auth]
max_sessions_per_grant = 20
session_issuance_per_minute = 60
```

Both limits must be positive. The session cap counts non-expired slots, including
the legacy slot. Rotating an active slot is allowed at capacity. New slots receive
HTTP 409 with `grant_session_limit_reached`; no existing session is evicted.

Issuance is limited to 60 successful exchanges per grant per 60-second fixed
window by default, including rotations. Excess requests receive HTTP 429 with
`grant_session_rate_limited`. Applications should back off rather than signing the
user out or retrying immediately. Existing path/IP rate limits also apply before
authentication.

The server locks the grant row while checking expiry, revocation and limits, then
issues the bearer in the same transaction. This shares the limits across server
processes. Each successful exchange also deletes up to 100 expired sessions from
other grants. Cleanup runs on traffic; expired bearers are rejected even before
their rows are deleted.

## Protocol and compatibility

`POST /auth/grant/session` accepts an optional `session_id` (the existing RandomId
format). The response echoes it in `session.session_id`. It identifies a slot only;
a valid grant and fresh proof of possession are still required for every exchange.
A retry after a lost response can rotate the same slot without consuming capacity.

Clients using slots send grant + PoP JSON to `DELETE /auth/grant/session`, so logout
works without a live bearer and does not consume issuance capacity or rate budget.
Legacy bearer-only logout sends the cached bearer. Repeating
proof logout with a fresh nonce is idempotent, including after a lost response.

- New SDK + new homeserver: shared sessions within an origin; independent slots
  across origins and browser profiles.
- Old SDK + new homeserver: requests without `session_id` rotate one legacy slot.
  They do not replace identified sessions, but old clients still compete with
  each other. The legacy slot counts toward the cap.
- New SDK + old homeserver: generic session APIs retain legacy behavior. Explicit
  browser-slot restore returns an unsupported-feature error rather than silently
  invalidating another tab. A failed feature-discovery request also prevents
  explicit slot restore; retry after discovery recovers.

Deploy the migration and new homeserver version on all nodes before relying on
multi-tab support, then release the SDK. Do not mix old and new homeserver binaries
behind one endpoint: an old binary still deletes all sessions for a grant. The
migration preserves existing bearers. Downgrading the binary restores the old
replacement behavior and may invalidate other tabs.

Sharing a grant and its client credential with another application gives it the
grant's permissions. Browser coordination does not implement that handoff.
