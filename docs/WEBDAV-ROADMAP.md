# WebDAV Productionisation Roadmap

An audit of the shortcuts taken while building the WebDAV endpoint ([WEBDAV.md](./WEBDAV.md)),
what each costs in production, and the decision taken on it.

The design record that preceded the work is
[WEBDAV-DESIGN.md](./WEBDAV-DESIGN.md); it explains why the endpoint is shaped the
way it is.

Compiled by reading the code and testing a deployed homeserver. Each item is tagged
**verified** (demonstrated against a running server), **from code** (traced but not
exercised), or **pre-existing** (predates this work).

## Contents

- [Done](#done)
- [Features](#features)
- [Separate tickets](#separate-tickets)
- [Not bugs](#deliberate-non-goals)

---

## Done

### 01 · Capability scopes are ignored · verified

The handler checked only that the session owned the drive, so a token scoped to
`/pub/someapp/` had read and write over the whole drive including `/priv/` — a
privilege escalation against the REST routes, reachable by switching endpoint.

**Decision: per-path enforcement.** `/dav` now calls the same
`has_read_permission` / `has_write_permission` as the REST routes, which enforce
capability scopes and the storage-root rule together. Each method maps to the
permission it needs; `COPY` and `MOVE` authorize their `Destination` separately from
their source; unknown verbs fail closed as writes.

The drive root and the `/pub/` and `/priv/` directories stay listable by their owner
whatever the token's scope. A client has to list them to mount anything, and they
reveal only the shape every drive shares. Without this carve-out, per-path
enforcement breaks mounting entirely — which is why the shortcut existed.

### 02 · The `/pub/` + `/priv/` write rule was not applied · verified

WebDAV accepted writes anywhere in the key's namespace; `.DS_Store` at a drive root
returned `201`.

**Decision: enforce strictly.** Now `403`, matching REST. Finder and GNOME junk
files are refused, which macOS may surface as an occasional error dialog. That is
preferred over a filename allowlist, which would mean reporting writes the server
did not perform.

### 03 · Basic auth was widened to every endpoint · from code

Teaching `extract_bearer_token` the `Basic` scheme for WebDAV's sake taught it to
`/storage`, `/session` and everything else at once. It had already caused one
regression: a `Basic` password of 43 characters silently disabled cookie fallback on
`/events-stream`.

**Decision: scope it to `/dav`.** The grant middleware accepts `Basic` only on
WebDAV paths, matched exactly so siblings like `/davos` do not inherit it.

### 15–17 · Demo scaffolding shipped unconditionally · verified

`/generate_demo_user` creates users bypassing signup-token policy and returns a
server-generated secret key; `/drive` served a web UI from every homeserver; PAT
minting had no policy around it.

**Decision: config flags, all defaulting safely.**

```toml
[drive]
webdav = true        # default
web_explorer = false # default; refuses to start without webdav

[admin]
demo_users = false   # default
```

All three are `#[serde(default)]`, so a `config.toml` written before they existed
keeps parsing — required fields would have broken every deployment on upgrade.

### 04 · Tenant isolation rested on a single function · verified

One shared `DavHandler` was pointed at the whole storage root, with the request
guard the only thing between a session and every other drive. The guard held, but
one future change to path normalisation would have turned a bug into a cross-tenant
breach.

**Decision: defence in depth.** `TenantScopeLayer` is an OpenDAL layer that refuses
any object key outside `{user_z32}/`, applied per request with the caller's key, so
confinement is enforced at the storage boundary as well as the HTTP one. Unlike
`WritePathLayer` it checks reads too — cross-tenant reads are the point. The
`DavHandler` is now built per request rather than shared, which is what makes the
scoping possible; the cost is a few allocations against a network round trip.

`opendal` 0.54 has no `SubdirLayer` and `OpendalFs` takes no root, so this is written
out by hand. Tests cover the case these checks usually get wrong: a key that merely
*starts with* the owner's, like `{owner}-evil/`.

### 06 · No upload size limit · verified

`DefaultBodyLimit` was no help — it is honoured by body extractors, and the handler
takes the raw request so it can stream. `RequestBodyLimitLayer` caps the body itself
at the same 100MB as the REST routes. A 101MB `PUT` now returns `413`.

### 07 · WebDAV traffic was invisible to metrics · verified

WebDAV resolves its own tenant from the URL rather than through `RequestTenant`, so
the existing recorder skipped it entirely. It now has its own, feeding the same
counter under a new `webdav` addressing mode, so the split between access paths
stays visible. Confirmed against a running server: `addressing_mode="webdav"` appears
alongside `path`.

### 09 · No rate limits configured for `/dav` · verified

A shipped default: 600 `PROPFIND`/minute per user. Mounted drives poll constantly, so
this is deliberately generous — it exists to stop a runaway client, not to shape
normal use.

---

## Features

### 12 · Public folders are not publicly readable · verified

The same file is `200` anonymously at `/storage/{key}/pub/README.txt` and `401` at
`/dav/{key}/pub/README.txt`. You cannot mount another key's public folder read-only
in a file manager — for a protocol whose shared surface is `/pub/pubky.app/`, that is
close to the whole pitch.

Needs read-only access for non-owners under `/pub/` only, `403` on every write verb
including `MOVE`/`COPY` destinations, and — the subtle part — a root listing that
does not reveal that `/priv/` exists.

### 08 · Locks are advisory only · verified

`FakeLs` returns well-formed lock tokens and accepts them back, but nothing is
locked, so two clients editing the same file silently overwrite one another having
both been told they hold an exclusive lock. macOS relies on the handshake to mount
writable, so removing it is not an option.

**Plan:** a `DavLockSystem` backed by the database with TTL expiry.

---

## Separate tickets

Neither came from this work and both outlive it.

### 05 · Any origin may be able to read a signed-in user's private files · pre-existing

`CorsLayer::very_permissive()` on `/storage` mirrors any origin *and* allows
credentials, while the session cookie is `SameSite=None` whenever the host is a pkarr
key or FQDN — that is, in production. Read together, any website appears able to read
a signed-in user's `/priv/` files.

Confirmed by reading the code, not by building an exploit, so treat as *verify
urgently* rather than proven. The likely fix is to stop allowing credentials
cross-origin, which is what `/dav` already does.

### 10 · The homeserver will not start without the DHT · verified

Startup aborts with `Key republisher error: DHT publish queried no nodes` when UDP to
the DHT is unavailable. A network condition outside the operator's control takes the
server down at boot rather than degrading.

**Cause found** while this was blocking local testing:
[`app_context.rs`](../pubky-homeserver/src/app_context.rs) calls `builder.no_relays()`
whenever `dht_bootstrap_nodes` is set *at all*, on the reasoning that custom bootstrap
nodes and mainnet relays should not be mixed. Setting `dht_bootstrap_nodes = []` to
force relay-only therefore does the opposite: it leaves a DHT with no nodes and
relays switched off.

Relays **do** work as a fallback — removing `dht_bootstrap_nodes` entirely and setting
only `dht_relay_nodes` publishes successfully with the DHT unreachable. So the fix is
narrow: do not disable relays for an empty bootstrap list, and consider whether a
publish failure should be fatal at boot or retried in the background.

---

## Deliberate non-goals

### 13 · `MKCOL` emits no event · verified

`PUT` and `DELETE` produce events; creating a collection does not, so an empty folder
made in a file manager is visible over WebDAV and invisible to everything else. This
is **correct**: directories are implied by key prefixes rather than stored, so there
is nothing to emit an event about. Recorded here so it is a decision rather than an
accident.

### 11 · Shorter path budget than REST · from code

The guard normalises `/{key}/{path}` as one string against the 972-byte cap, so the
52-character key eats into the user's allowance: ~919 bytes versus 972 over REST. A
deep path that works over REST can fail over WebDAV. Low priority; the fix is to
validate the tenant segment and the path separately.

### 14 · Spec conformance is reimplemented, not verified · from code

The demo seed's tests replicate the pubky-app-specs rules rather than validating with
the crate, so what is under test is one reading of the spec. Adding
`pubky-app-specs` as a dev-dependency and validating through `PubkyAppPost::try_from`
would fix it, if it is published.
