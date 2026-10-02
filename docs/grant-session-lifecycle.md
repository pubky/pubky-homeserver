# Grant sessions in multiple tabs

A grant has one current bearer. Each exchange replaces that bearer. Browser tabs
on the same origin share it and coordinate refresh through the SDK; applications
do not need to synchronize credentials themselves.

## Browser applications

Use `browserSessionStore.save(session)` after authentication and
`browserSessionStore.restore(id)` when restoring an account. Save the session
before using it for requests. The original handle and its clones then join the
shared browser session.

- Tabs share one bearer for each stored grant. Opening, closing, duplicating or
  reloading tabs reuses the saved bearer while it is valid.
- IndexedDB stores restore material and the bearer. Delegated signing keys
  remain non-extractable; scoped-key approvals use a separate AES-GCM wrapping
  key. See [persistence][key-persistence] for recovery and protection limits.
  Do not log or export browser records.
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

Coordination is limited to one origin and browser profile. Independent apps
should authenticate with separate grants. Generic Rust/JS
`restore_session`/`restoreSession` exchanges the exported grant for a fresh bearer,
replacing its previous bearer. Copying a grant to another origin does not provide
independent sessions: those clients can invalidate each other's bearers.

Browser applications should use the browser store. Requests made with a manually
copied bearer or by older SDKs are outside this coordination.

## Upgrading stored browser sessions

Existing grant records remain readable. On first restore, the SDK exchanges the
grant once and saves a shared bearer in the existing record. Concurrent restores
reuse that bearer. Reload older app tabs so they participate in the SDK's locks.
The shared bearer remains saved when every tab closes.

Bare grants use `pubky-session-v1`; V1 approvals use `pubky-session-v2`, even
without `e` scopes. Approval and storage versions are separate.

V2 records live under `session:<id>` in `delegatedGrantKeys`; the database
version stays at 1. Older SDKs see only V1 records in `storedSessions`. The
current SDK lists both formats, but older SDKs cannot read V1 approvals or V2
secret tokens.

Current `clear` and `clearAll` remove both formats. An older SDK's `clear`
removes only V1 records; its `clearAll` deletes both formats and all keys.

To add keys, request a fresh V1 approval with `e` and save the new record ID,
even with the same `clientId`. The old grant keeps its original permissions.
To replace it, sign it out after saving the new session; deleting its local
record does not revoke it. A new bare grant does not inherit keys.

[key-persistence]: scoped-encryption-keys.md#persistence-and-offline-recovery

## Protocol and compatibility

Tab coordination uses the existing `POST /auth/grant/session` grant + PoP
exchange, without session IDs, capacity limits or a database migration.
It works with homeservers that support the existing grant session protocol.
The updated server serializes bearer replacement with other exchanges and grant
revocation, so a delayed exchange cannot create a second session or undo logout.
The SDK reuses a valid bearer that already lasts until grant expiry.

Homeservers advertising `grant-proof-logout` accept grant + PoP JSON at
`DELETE /auth/grant/session`. This allows logout after bearer or grant expiry.
Signature and fresh PoP checks still apply. Repeating proof logout with a fresh
nonce is idempotent, including after a lost response.

When proof logout is not advertised, the SDK retains bearer-authenticated logout
and uses the latest shared bearer. Remote revocation on those older servers
requires that bearer to remain valid. Upgrade all homeserver nodes to support
logout after expiry; mixed server versions must not advertise proof logout.
