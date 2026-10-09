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
- IndexedDB stores the restore material and the bearer. Delegated signing keys
  remain non-extractable, but the rest of the restore material, including any
  encryption keys, is stored as plaintext. IndexedDB is the trust boundary. Don't
  log or export browser records. See [persistence and offline
  recovery][key-persistence] for what the restore material contains.
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

### Records for signed approvals

Session records have their own version, separate from the approval format. See
[versions][key-versions].

- Bare grants use `pubky-session-v1` records in the `storedSessions` object
  store.
- Signed approvals use `pubky-session-v2` records, even when the signer declined
  `e`. They're stored under `session:<id>` in the `delegatedGrantKeys` object
  store, so older SDKs don't see them. The database version stays at 1.

The current SDK lists both record versions. Older SDKs list only
`pubky-session-v1` records, and they can't read signed approvals or
`pubky-grant-credential-v2` secret tokens.

In the current SDK, `clear` and `clearAll` remove both record versions. In an
older SDK, `clear` removes only `pubky-session-v1` records, and `clearAll`
deletes both record versions and all keys.

### Add encryption keys to an existing session

1. Request a new signed approval with `e`, even for the same `clientId`. A new
   bare grant doesn't carry keys.
2. Save the new session and use its new record ID. The old grant keeps its
   original permissions.
3. To replace the old session, sign it out. Deleting its local record doesn't
   revoke the grant.

[key-persistence]: scoped-encryption-keys.md#persistence-and-offline-recovery
[key-versions]: scoped-encryption-keys.md#versions

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
