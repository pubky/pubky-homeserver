# WebDAV: What Comes Next

The `/dav` endpoint ships read-only and anonymous, serving each user's `/pub/`
and nothing else ([WEBDAV.md](./WEBDAV.md)). This is what is left for the
authenticated, writable drive, and what was learned building a full prototype
of it first. The prototype is tagged `webdav-prototype`; the design record that
preceded it is at the same commit under `docs/WEBDAV-DESIGN.md`.

Items keep their numbers from the original audit. Each is tagged **verified**
(demonstrated against a running server), **from code** (traced, not exercised)
or **pre-existing** (predates the WebDAV work).

## Contents

- [The design decision writes will reopen](#the-design-decision-writes-will-reopen)
- [Authentication](#authentication)
- [Writes](#writes)
- [Locks](#locks)
- [Separate tickets](#separate-tickets)
- [Deliberate non-goals](#deliberate-non-goals)

---

## The design decision writes will reopen

The read-only endpoint is `dav-server` with the stock `OpendalFs` — Option A of
the design record. For reads that wins cleanly: `dav-server` owns the
operation and nothing else needs to know. For writes the same property is the
problem. The prototype produced three findings of one shape: `COPY`/`MOVE`
bypassing the database (18), no way to keep a lock alive through a long upload
(08), and the directory model (below). In each, `dav-server` did something and
the database learned late or never.

The read-only slice prejudges nothing — its path parsing, `TenantScopeLayer`,
CORS handling and tests are shared by every route. The fork is:

- **Stay on A** and finish what the prototype did: `copy_move.rs` in the
  finalization layer, auth scoping, an upload cap, a `DavLockSystem` on
  `entry_locks`. Least work, since most of it exists at `webdav-prototype`.
- **Move to D** — a custom `DavFileSystem` over `FileService` — if the database
  needs to be *in the loop* rather than notified after: `get_quota` for
  free-space display, directory `DELETE` cleaning up entries, locks kept alive
  through an upload. `dav-server` stays; only the filesystem behind it changes.
- **B**, native axum handlers, only if `dav-server`'s maintenance or its
  `Depth: infinity` refusal becomes a real problem. Highest cost; nothing so far
  demands it.

`dav-server` is the only Rust WebDAV server crate. It is functional but slowly
maintained, with a low bus factor. It refuses `PROPFIND` with `Depth: infinity`
or no `Depth` header (`403 propfind-finite-depth`), unconfigurably, so listing a
subtree is one request per directory — this applies to A and D alike.

---

## Authentication

WebDAV inherits whatever auth HTTP provides, and each client chooses what it
implements. The grant exchange needs Ed25519, which no standard client can do,
and bearers expire hourly.

| Client | Basic | Bearer |
|---|---|---|
| macOS Finder, Windows Explorer, GNOME Files, KDE Dolphin | yes | no |
| Cyberduck | yes | yes (also OAuth2) |
| rclone | yes | yes, incl. `bearer_token_command` |

So file managers need **Basic**, with the public key as username and a
long-lived token as password — the same shape as Nextcloud's app passwords. The
server already resolves bearers by SHA-256 lookup; what is missing is issuance
with a longer TTL. The prototype minted these as ordinary grants with a
discarded `cnf` key and the grant's own expiry as the session expiry, gated by
an admin route that should not ship.

### 03 · Basic auth must be scoped to `/dav` · from code

Teaching `extract_bearer_token` the `Basic` scheme for every route caused a
regression: a 43-character Basic password silently disabled cookie fallback on
`/events-stream`. Accept `Basic` on `/dav` paths only — cleanest as a layer on
the dav router, not a path test in the global middleware.

### 01 · Capability scopes · verified

The prototype's first cut checked only that the session owned the drive, so a
token scoped to `/pub/someapp/` had the whole drive including `/priv/` — a
privilege escalation over the REST routes. `/dav` must call the same
`has_read_permission` / `has_write_permission` per path, with `COPY` and `MOVE`
authorizing their `Destination` separately and unknown verbs failing closed. The
drive root and the two storage roots need a read carve-out so a scoped token can
still list them to mount; they reveal only the shape every drive shares.

### 02 · The `/pub/` + `/priv/` write rule · verified

Finder writes `.DS_Store` at the mount root; GNOME writes `.Trash-$UID`. They
must get `403`, matching REST, which macOS may surface as an occasional error
dialog. Preferred over an allowlist, which would mean acknowledging writes the
server did not perform.

### 06 · Upload cap · verified

`DefaultBodyLimit` does not apply — the handler takes the raw request so it can
stream. `RequestBodyLimitLayer` at the REST routes' 100MB does; a 101MB `PUT`
then gets `413`.

### 20 · Status for over-quota writes · verified

The storage layer refuses them, but dav-server reports that as a bare `500`.
Checking `Content-Length` up front with the REST route's quota check returns
`507 Insufficient Storage`, which file managers show as a full disk. A chunked
`PUT` still gets `500`.

---

## Writes

### 18 · `COPY` and `MOVE` bypass the database, quota and events · verified

The finalization layer wraps `write` and `delete` but passes `copy` and `rename`
straight to the backend. Nothing in the REST API calls either, so this is latent
until WebDAV writes exist — and then it is the first thing they hit. On the
`file_system` backend:

- Renaming a file in a file manager made it unreachable over REST at both
  names — a stale entry pointing at nothing, and bytes with no entry.
- Copying had no quota limit: five copies of a 600 KB file put 4 MB on disk
  against a 1 MB cap while `used_bytes` stayed at 614 KB.

The prototype's `copy_move.rs` fixes it in the layer, following the write path's
ordering — lock the users, check collisions and quota, commit the backend, then
entries, events and usage in one transaction — and handles a whole-directory
`rename`, since dav-server renames a collection in one call. Fixing it in the
layer covers every OpenDAL caller, including the admin operator. This was the
deciding experiment between A and D, and it did not favour D: `FileService` has
no copy or rename either.

### The directory model · pre-existing

There are no directory entries; directories exist because files have paths
beneath them. The **admin** server's `/dav` already shows the seams: `MKCOL`
creates a directory in storage but no entry, directory `DELETE` removes storage
but orphans the entries beneath it, and `PROPFIND` lists from storage rather
than the database. For client writes this needs a decision — explicit directory
entries, or accept that empty folders are invisible outside WebDAV (item 13) —
and directory `DELETE` must clean up entries by prefix either way.

### 21 · Free space · from code

`dav-server-opendalfs` implements neither `get_quota` nor the property methods,
so Finder and GNOME Files show no usage for a mount. The route is a thin
`DavFileSystem` wrapper adding `get_quota` from `UserEntity.used_bytes` — a
first step toward D, and the natural home for a synthesized root listing if
`/dav/{key}/` should ever list `pub` alone.

---

## Locks

### 08 · Locks · verified

A read-only share has nothing to lock, so the endpoint advertises class 1 only.
Writes need class 2: macOS insists on the `LOCK` handshake before it mounts
writable. The prototype used `FakeLs`, which grants locks that lock nothing —
enough to mount, and a defensible first step if documented.

`/storage` has since gained a database-backed lock scheme (`entry_locks`,
#630). A `DavLockSystem` on the same table would make REST and WebDAV locks
mutually visible for free, since both key on `EntryPath`. Gaps: the table has
no subtree queries (dav-server checks and clears locks with `Depth: infinity`
on `DELETE` and `MOVE`), no `owner`/`principal` columns, and the trait cannot
signal a server error — every database failure becomes "lock failed".

What does not transfer is keep-alive. REST extends a lock for as long as an
upload streams; `DavLockSystem::check` runs once before the body is read, so a
WebDAV upload longer than `MAX_LOCK_TIMEOUT_SECS` (60s) outlives its own lock.
That needs a hook in the write path, which is one of the arguments for D.

---

## Separate tickets

None came from the endpoint itself; all outlive it.

### 19 · An interrupted overwrite destroyed the original · fixed on main (#637)

Found while testing the prototype's writes: the `fs` backend was built without
`atomic_write_dir`, so an upload that failed after it started had already
replaced the file it was overwriting, with the database still recording the
original's length and hash. Fixed on main by #637 — uploads stage in
`data/files-tmp` and rename into place on close, a broken stream aborts the
writer, and finalization runs to completion even if the client disconnects.
Recorded here because WebDAV writes will lean on exactly those guarantees.

### 05 · Any origin may be able to read a signed-in user's private files · pre-existing

`CorsLayer::very_permissive()` on `/storage` mirrors any origin *and* allows
credentials, while the session cookie is `SameSite=None` whenever the host is a
pkarr key or FQDN — that is, in production. Read together, any site appears able
to read a signed-in user's `/priv/`. From code, not exploited: *verify
urgently*. `/dav` already never allows credentials cross-origin.

### 10 · The homeserver will not start without the DHT · verified

`app_context.rs` calls `builder.no_relays()` whenever `dht_bootstrap_nodes` is
set at all, so `dht_bootstrap_nodes = []` — the obvious way to force relay-only
— leaves no DHT nodes and relays off. Relays do work when the key is absent. Do
not disable relays for an empty list, and consider whether a publish failure
should be fatal at boot.

### 22 · Test homeservers that ran the prototype hold inconsistent data · verified

Files copied or moved over the prototype's `/dav` before 18 was fixed are on
disk with no entry, or have entries pointing at moved files. Deleting the demo
users is the remedy.

---

## Deliberate non-goals

- **13 · `MKCOL` emits no event.** Directories are implied by key prefixes, so
  there is nothing to emit about. A decision, recorded so it is not an accident.
- **11 · Shorter path budget than REST.** The tenant key is normalised as part of
  the path against the 972-byte cap, so ~919 bytes remain. Validate the tenant
  segment separately if it ever matters.
- **A browser explorer and demo-user provisioning** were built for testing the
  prototype. Neither belongs in the homeserver.
