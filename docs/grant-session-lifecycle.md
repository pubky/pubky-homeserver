# Grant sessions in multiple tabs

Homeservers advertising `grant-session-slots` support multiple sessions under one
grant. Each session has a slot ID and a short-lived bearer. Refresh replaces the
bearer in that slot.

## Browser applications

Use `browserSessionStore.save(session)` after authentication and
`browserSessionStore.restore(id)` when restoring an account. The SDK manages the
per-tab sessions.

- Each tab gets its own slot, so restoring or refreshing one tab leaves the
  others authenticated.
- Reloading a tab reuses its slot. Concurrent restores in one SDK instance share
  the same credential and bearer refreshes.
- IndexedDB stores the grant restore material. `sessionStorage` stores the public
  slot ID. A Web Lock prevents a duplicate tab from reusing the copied ID. The
  browser releases the lock when the document closes or reloads.
- Browser restore requires IndexedDB, sessionStorage, Web Locks and a secure
  context. `isAvailable()` checks browser facilities, not homeserver support.
- Closed or crashed tabs count toward the limit until their bearers expire. The
  default lifetime is one hour, capped by the grant's expiry.
- Signout revokes the grant, invalidating all its sessions and future restores.
  Other tabs discover the revocation on their next authenticated request; the
  app must update their UI. `remove`, `clear` and `clearAll` delete local data
  without revoking the grant or immediately invalidating live sessions.

Generic Rust/JS `restore_session`/`restoreSession` creates a new independent
session on supporting homeservers. Browser apps should use the browser store for
reload and duplicate-tab handling. Cloned Rust sessions share refresh state.

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
Legacy bearer-only logout remains supported. Repeating proof logout with a fresh
nonce is idempotent, including after a lost response.

- New SDK + new homeserver: independent sessions with automatic per-slot refresh.
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

Sharing a grant with another vibe still gives that vibe the grant's permissions.
