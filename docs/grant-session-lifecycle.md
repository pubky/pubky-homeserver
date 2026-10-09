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
`action` is `saved` or `removed` for one record, or `cleared` for all records
(`id: null`).
Applications decide how to update their UI. Requests always check persisted
state, so missed notifications cannot restore removed credentials.

## Sharing one session across first-party origins

Browser storage is per origin, so `pubky.app` and `shop.pubky.app` cannot
read each other's saved sessions. A *session agent* on a dedicated same-site
origin owns the grant through the browser store and lends its bearer to apps
over `postMessage`; only the agent exchanges. See [sso-agent.md](sso-agent.md)
for the protocol, the SDK API and the deployment requirements.

The store now also dispatches `pubky-session-changed` with `action: "saved"`
after `browserSessionStore.save`, so agent frames in other tabs pick up a new
sign-in without a reload.

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
