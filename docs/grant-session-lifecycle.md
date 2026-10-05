# Grant sessions in multiple tabs

Homeservers advertising `grant-session-slots` support independent sessions under
one grant. Each slot has one current bearer; refresh replaces only that bearer.
Browser tabs on the same origin share one slot and coordinate refresh through the
SDK. Homeservers without slot support retain one bearer per grant.

## Browser applications

Use `browserSessionStore.save(session)` after authentication and
`browserSessionStore.restore(id)` when restoring an account. Save the session
before using it for requests. The original handle and its clones then join the
shared browser session.

- Tabs share one bearer for each stored grant. Opening, closing, duplicating or
  reloading tabs reuses the saved bearer while it is valid.
- IndexedDB stores the grant restore material and current bearer. Delegated
  WebCrypto private keys remain non-extractable. Treat the stored bearer as a
  credential; do not log or export the browser record.
- Authenticated requests hold shared Web Locks until response headers arrive.
  Refresh takes an exclusive lock and saves its result before releasing it.
  Requests can run concurrently; a slow request can delay refresh. Response
  bodies and open event streams do not retain the lock.
- A refresh marker survives a lost response or tab closure. The next operation
  obtains and persists a fresh bearer before sending requests. A replayable
  request rejected with 401 gets at most one recovery attempt. Transport
  failures and other HTTP errors do not replay writes.
- Browser save and restore require IndexedDB, Web Locks and a secure context.
  `isAvailable()` checks these browser facilities. `sessionStorage` is not required.
- Signout revokes the grant for every tab. A failed signout remains pending and
  blocks requests; retry signout, or restore the saved record to finish revocation.
  Successful signout removes the saved record and its delegated key. Repeated or
  concurrent signout succeeds once the shared record is gone.
- `remove`, `clear` and `clearAll` only delete local data. Browser-managed handles
  stop working after their record is removed. These operations do not revoke the
  grant. Signout on a removed handle is a local no-op.

The SDK dispatches `pubky-session-changed` on `window` after local removal or
successful signout, and forwards the notification to other tabs with
BroadcastChannel when available. `event.detail` contains `{ id, action }`:
`action` is `removed` for one record or `cleared` for all records (`id: null`).
Applications decide how to update their UI. Requests always check persisted
state, so missed notifications cannot restore removed credentials.

## Other applications and generic restore

Coordination is limited to one origin and browser profile. Generic Rust/JS
`restore_session`/`restoreSession` creates a new independent slot on supporting
homeservers. Independent clients can use the same exported grant without
invalidating each other's bearers. Each generic restore can consume capacity;
browser applications should use the browser store to share a session across tabs.

Sharing a grant and client key gives every recipient the same permissions and
revocation scope. Credential handoff remains the application's responsibility.
Independent applications can instead authenticate with their own grants.

On older homeservers, generic restore replaces the grant's previous bearer.
Browser coordination still works through the existing single-session protocol.

## Upgrading stored browser sessions

Existing grant records remain readable. When no shared bearer exists, the SDK
selects a slot on supporting homeservers and persists its identity before
exchanging the grant. Concurrent restores and interrupted exchanges reuse it.
An existing shared legacy bearer continues to rotate without a slot ID. Reload older app tabs so they participate in the SDK's locks.
The shared bearer remains saved when every tab closes.

## Protocol and compatibility

`POST /auth/grant/session` accepts an optional `session_id` and echoes it in
`session.session_id`. Exchanges without an ID rotate the legacy slot; they do not
replace identified sessions. Slots still require a valid grant and fresh PoP.
The SDK discovers slot support before allocating one, while browser coordination
also works with older homeservers.

The server locks the grant row while checking expiry, revocation and limits,
then issues the bearer in the same transaction. The SDK reuses a valid bearer
that already lasts until grant expiry.

Homeservers advertising `grant-proof-logout` accept grant + PoP JSON at
`DELETE /auth/grant/session`. This allows logout after bearer or grant expiry.
Signature and fresh PoP checks still apply. Repeating proof logout with a fresh
nonce is idempotent, including after a lost response.

When proof logout is not advertised, the SDK retains bearer-authenticated logout
and uses the latest shared bearer. Remote revocation on those older servers
requires that bearer to remain valid. Upgrade all homeserver nodes to support
logout after expiry; mixed server versions must not advertise proof logout.


## Homeserver limits and deployment

```toml
[grant_auth]
max_sessions_per_grant = 20
session_issuance_per_minute = 60
```

Both limits must be positive. The cap counts non-expired slots, including the
legacy slot. Rotating an active slot is allowed at capacity; a new slot receives
HTTP 409 with `grant_session_limit_reached` without evicting other sessions.

The issuance budget counts successful exchanges per grant in a 60-second fixed
window. Excess requests receive HTTP 429 with `grant_session_rate_limited`.
Existing path/IP limits also apply. Each successful exchange deletes up to 100
expired sessions from other grants; expired bearers are rejected before cleanup.

Upgrade every homeserver node before using slots. The migration preserves
existing bearers, but an old binary still replaces all sessions under a grant.
Mixed old/new server binaries or a binary downgrade can invalidate other clients.
