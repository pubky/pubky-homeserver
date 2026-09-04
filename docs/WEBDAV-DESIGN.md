# WebDAV Support in Pubky Homeserver

> **Design record, written before the work. Superseded as a description of the
> system.**
>
> Everything under *Current Implementation* below describes the homeserver as it
> was **before** WebDAV was added to the client server — it is kept for the
> reasoning, not as a statement of fact. The client server now has a full WebDAV
> endpoint.
>
> - What the endpoint does today, and how to use it: [WEBDAV.md](./WEBDAV.md)
> - What is still outstanding: [WEBDAV-ROADMAP.md](./WEBDAV-ROADMAP.md)
>
> **Outcome:** [Option A](#option-a-use-dav-server-on-the-client-server) — `dav-server`
> on the client server — with one departure. This document assumed per-user scoping
> would come from the storage layer, but `opendal` 0.54 has no `SubdirLayer` and
> `OpendalFs` takes no root, so isolation is enforced by an authorization guard on
> each request plus a hand-written `TenantScopeLayer` behind it. The auth problem
> raised under *Authentication Challenge* was solved by accepting HTTP Basic on
> `/dav` only, with the token as the password.

## Current Implementation

### Admin Server (port 4000)

The admin server provides a full WebDAV endpoint at `/dav/*` using the `dav-server` crate (v0.8) with `dav-server-opendalfs` (v0.6) bridging to OpenDAL storage backends.

**Setup** (`admin_server/app_state.rs`):
- `OpendalFs` wraps the `admin_operator` (OpenDAL operator without per-user write-path restrictions)
- `DavHandler` is configured with `FakeLs` (non-persistent locks), `/dav` prefix stripping, and autoindex
- All HTTP methods are routed to the handler via `any(dav_handler)`

**Supported operations**: GET, PUT, DELETE, PROPFIND (207 Multi-Status XML), MKCOL, COPY, MOVE, HEAD, LOCK/UNLOCK (fake — acknowledged but not enforced).

**Authentication**: HTTP Basic Auth (`admin:<password>` from `config.toml`). Validated in `dav_handler.rs` before delegating to `DavHandler`.

**Usage in practice**: The admin WebDAV endpoint is lightly used. It was added as a quick way for operators to view stored content and overwrite files if necessary. It is not battle-tested.

### Client Server (port 8000/8001)

The client server is REST-only with no WebDAV support:

| Method | Behavior |
|--------|----------|
| GET (file) | Stream file content with ETag/Last-Modified conditional support |
| GET (directory/) | Plain-text listing of `pubky://` URLs with cursor pagination |
| HEAD | Metadata headers only |
| PUT | Create/overwrite file (streaming, quota-checked) |
| DELETE | Remove a single file (not directories) |

**Missing**: PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK/UNLOCK, WebDAV-style OPTIONS.

Directory listings return plain-text `pubky://` URLs (one per line) rather than XML multistatus responses. There is no support for creating empty directories, copying, moving, locking resources, or deleting directories.

**Authentication**: Capability-based, using Ed25519-signed grants.

### Data Model

Entries are stored as flat records in PostgreSQL:

```
EntryEntity { user_id, path, content_hash, content_length, content_type, modified_at, created_at }
```

Directories are implicit — they exist because files have paths beneath them. There are no explicit directory entries. Storage is split into two roots: `/pub/` (world-readable) and `/priv/` (owner + authorized users only).

File content is stored via OpenDAL with pluggable backends (local filesystem, GCS, in-memory for tests).

## Requirements

### Motivation

The current API is WebDAV-compatible-ish — it uses some WebDAV conventions but is missing key methods. The goal is to either be explicitly WebDAV-compliant or have a good reason not to be. Specifically, applications want:

- **COPY**: Duplicate resources without re-uploading
- **Directory DELETE**: Remove directories and their contents
- **LOCK/UNLOCK**: Protect against concurrent writes from multiple sessions (e.g., a user logged into multiple apps that access the same data)

Beyond application needs, WebDAV compliance enables standard tooling and end-user access:

- **rclone backups**: rclone has a built-in WebDAV backend — it uses PROPFIND to enumerate files with metadata (size, modification time) for change detection, GET/PUT for transfers, and MKCOL/DELETE for directory management. Combined with PATs (see Authentication Challenge), users could run `rclone sync` for automated backups — rclone supports `--webdav-bearer-token` natively.
- **Drive mounting**: End users could mount homeserver storage via macOS Finder, Windows Explorer, or Cyberduck for direct file browsing and management.

Without PATs, both use cases would require building custom integrations or wrapping every operation through the Pubky SDK.

### What Works Out of the Box

The argument for compliance is that other people already implemented the client.
Nothing below needed code from us.

**Verified against a deployed homeserver:**

| Client | What was exercised |
|---|---|
| `curl` | OPTIONS, PROPFIND, GET, PUT, MKCOL, COPY, MOVE, DELETE, LOCK/UNLOCK |
| `rclone` | `tree`, `ls`, `copy`, `cat`, `purge` via its WebDAV backend |
| GNOME Files / Thunar (GVfs) | mount, browse, read, write, mkdir, rename, delete — and as a POSIX path under `/run/user/$UID/gvfs/` |
| Built-in `/drive` explorer | browse, preview, upload, delete |
| Filestash | connects and reads (proxies server-side, so CORS never applies) |

**macOS Finder** sits between verified and assumed. Everything it depends on is
confirmed on the wire, including through a TLS reverse proxy: `DAV: 1,2,3` on
OPTIONS, the `LOCK` → `PUT` with `If:` → `UNLOCK` write sequence, and its
housekeeping files being handled rather than erroring. The GUI itself has not
been driven, so a Finder-specific quirk would still be a surprise.

**Expected to work, untested:** KDE Dolphin (`webdavs://`), Cyberduck and
Mountain Duck, WinSCP, `davfs2`, Windows Explorer.

**Applications that treat WebDAV as a storage backend.** This is the more
interesting category for the pitch, because these turn a drive into an app's
backing store with no Pubky integration at all: Joplin (note sync), Obsidian
(via the Remotely Save plugin), Zotero (attachment sync), KeePassXC (open the
database directly off the drive), Duplicati (backup target), Documents by
Readdle (iOS), Solid Explorer (Android).

**Will not work:** `rsync` — not a WebDAV client, though it works fine against
an already-mounted drive; Time Machine, which needs SMB/AFP; and the
Nextcloud/ownCloud desktop clients, which speak Nextcloud's own API rather than
plain WebDAV.

Two caveats worth stating rather than discovering. Windows Explorer's built-in
WebDAV client is genuinely unreliable — a default ~50 MB file cap and
long-standing auth quirks — so Cyberduck is the better Windows recommendation.
And while locks remain advisory (`FakeLs`), anything assuming real locking for
concurrent edits, Office over WebDAV especially, can still clobber.

### Standard Client Compatibility

To ground the requirements, here's what two major WebDAV consumers actually use:

**Nextcloud** (as a reference WebDAV server/client):

| Method | Usage |
|--------|-------|
| PROPFIND | List folder contents and file metadata |
| GET | Download files (or folders as zip/tar archives) |
| PUT | Upload/overwrite files (with optional checksum, mtime headers) |
| MKCOL | Create folders |
| DELETE | Remove files or folders recursively |
| COPY | Duplicate resources (`Destination` header) |
| MOVE | Relocate resources (`Destination` header) |
| PROPPATCH | Modify properties (e.g., favorites) |
| REPORT | Filtered queries (e.g., list favorites) |
| LOCK/UNLOCK | Dummy endpoints only — not enforced |

**rclone** (WebDAV backend):

| Method | Usage |
|--------|-------|
| PROPFIND | Enumerate files with metadata (size, mtime, checksums) for sync/change detection |
| GET | Download file content |
| PUT | Upload file content (chunked upload support for Nextcloud) |
| MKCOL | Create directories |
| DELETE | Remove files and directories |
| COPY | Duplicate files/directories |
| MOVE | Rename/relocate files/directories |

Notably, rclone does **not** use LOCK — it relies on its own conflict detection. Nextcloud only provides fake LOCK support. This suggests that while LOCK is important for our multi-session app use case, standard tooling won't depend on it.

### Required Methods

- **PROPFIND**: Structured directory listings with file metadata (size, type, timestamps)
- **MKCOL**: Create collections/directories
- **COPY**: Copy resources
- **MOVE**: Move/rename resources (should be quota-neutral)
- **LOCK/UNLOCK**: Real lock enforcement (not fake), backed by persistent storage. Exclusive locks to protect against concurrent writes from multiple sessions.
- **Directory DELETE**: Remove a directory and its contents
- **Compatibility with Pubky's auth model**: Capability-based authorization

### Locking Requirements

**Scope: Exclusive locks only.** Shared (read) locks are not required. The primary use case for Paykit/noise is preventing concurrent writes. Exclusive locks are sufficient: one app locks, writes, unlocks; the other gets 423 Locked and retries. 

RFC 4918 requires servers to support exclusive locks. Shared locks are optional, and many WebDAV servers skip them. Standard clients work fine with exclusive-only.

**File and directory locks (RFC 4918 §7).** Locks apply to both files and directories.

**Timeouts (RFC 4918 §6.6).** Locks have a server-enforced timeout to handle writers that die or disconnect without unlocking. Clients specify a desired timeout with server defined cap. Clients must call LOCK refresh to extend the timeout if their operation takes longer.

### Constraints

- **Depth limit**: Directory depth can be artificially limited (e.g., 50 levels) if it simplifies implementation, particularly for `Depth: infinity` PROPFIND operations.

### Authentication Challenge

WebDAV (RFC 4918) does not specify authentication — it inherits whatever HTTP provides. HTTP defines Basic (RFC 7617), Digest (RFC 7616), and Bearer (RFC 6750, via OAuth2) as standard `Authorization` header schemes, but each client chooses which to implement. There is no single "correct" WebDAV auth mechanism, which is why different clients support different approaches.

The Pubky homeserver's grant exchange requires Ed25519 cryptography that no standard client supports, and bearer tokens expire hourly with refresh requiring Ed25519 signing. This means standard clients cannot authenticate without additional server-side support.

#### Server-side reference: how Nextcloud handles auth

Nextcloud accepts HTTP Basic Auth (`Authorization: Basic base64(user:pass)`) for WebDAV. Users generate **app passwords** — long-lived, per-device credentials separate from their login password — via Settings > Security. The server maps username + app-password to a user account and scoped permissions. Nextcloud also supports Bearer tokens via OpenID Connect, but Basic + app passwords is the standard path. This is directly analogous to what PATs would be for Pubky.

#### What standard WebDAV clients can send

| Client | Basic Auth | Bearer Token | Notes |
|--------|-----------|-------------|-------|
| macOS Finder | Yes | No | Basic only |
| Windows Explorer | Yes | No | Basic only |
| GNOME Files (Nautilus) | Yes | No | Connect via `davs://` URL |
| KDE Dolphin | Yes | No | Connect via `webdavs://` URL |
| Cyberduck | Yes | Yes | Also supports OAuth2 redirect flows |
| rclone | Yes (`user`/`pass`) | Yes (`bearer_token` or `bearer_token_command`) | Command variant can dynamically fetch tokens |

#### What we'd need to support them

- **Personal access tokens (PATs)**: Long-lived bearer tokens issued via the SDK or admin interface. The server already resolves bearers by SHA-256 hash lookup in Postgres — the infrastructure exists, only the issuance mechanism and longer TTL are missing. This is the most practical path, and directly analogous to Nextcloud's app passwords. rclone would use `bearer_token` config; Cyberduck could use Bearer auth.
- **Basic auth mapping** (optional, for Finder/Explorer compatibility): Accept the user's z32-encoded public key as the username and a PAT as the password (`Authorization: Basic base64(z32:pat)`). This is essentially PATs over a different HTTP header, needed because Finder and Explorer only speak Basic auth. The downside is that capability scoping is fixed at token issuance time.
- **`bearer_token_command` integration**: rclone could use a Pubky CLI command (e.g., `pubky auth token --homeserver <url>`) that performs the Ed25519 grant exchange and outputs a fresh bearer token. This avoids long-lived PATs entirely but requires the Pubky CLI to be installed alongside rclone.

Without one of these additions, a Pubky SDK wrapper is always required — clients cannot "just mount" the homeserver as a WebDAV drive.

## The `dav-server` Crate

`dav-server` (v0.8) is the **only** Rust WebDAV server library. Every Rust project that implements WebDAV (Dufs, OpenDAL's `oay`) uses it. No alternative crates exist on crates.io — `rustydav` and `hyperdav` are client-only libraries.

### Capabilities

- WebDAV Classes 1 and 2 (COPY, MOVE, LOCK/UNLOCK)
- Pluggable storage via `DavFileSystem` trait (see Appendix A)
- Pluggable lock backend via `DavLockSystem` trait (see Appendix B)
- Auth handled externally at the HTTP framework level
- `dav-server-opendalfs` bridges it to OpenDAL's 40+ storage backends

### Compatibility

`dav-server` v0.8 does **not** directly depend on hyper. It uses `http 1.4.0` and `http-body 1.0.1` for its request/response types. The project's axum (v0.8.9) depends on hyper 1.9.0. Both hyper 0.14.32 and 1.9.0 are present in the lockfile (some transitive dependencies still use 0.14), but `dav-server` itself is not the source of this split. There is no blocking compatibility issue.

### Risks

- **Maintenance is infrequent.** The repository (messense/dav-server-rs, originally by miquels) has long gaps between commits and slow issue/PR response. There is some activity from 2025–2026, but not a huge amount. The crate is functional but not actively evolved.
- **Niche dependency.** Low bus factor. If the maintainer steps away, the crate becomes unmaintained.
- **Lock implementation is your responsibility.** `FakeLs` does not enforce locks. A real `DavLockSystem` backed by Postgres would need to be built.

## WebDAV vs REST: Impact on the SDK

The SDK currently uses plain REST (GET/PUT/DELETE via `reqwest`) with no COPY, MOVE, or LOCK operations. If the server gains WebDAV methods, the SDK should adopt them — COPY, MOVE, and LOCK are atomic server-side operations that can't be replicated as multi-step REST calls without losing atomicity. 

The trade-off is adding XML generation/parsing to the SDK, but this only applies to PROPFIND responses; COPY, MOVE, and LOCK requests are simple HTTP methods with minimal XML.

## The Implicit Directory Problem

The current data model has no directory entries — directories exist only because files have paths beneath them. The admin server's existing WebDAV endpoint exposes the gaps in this model:

**How the admin server handles directories today:**
- **MKCOL** (`create_dir`): `WriteFinalizationLayer` performs a collision check against the DB, then delegates to OpenDAL which creates the directory in the storage backend (actual folder on filesystem, marker object on GCS). But **no `EntryEntity` is created in Postgres** — the directory exists only in storage.
- **Directory DELETE** (`remove_dir`): OpenDAL deletes the directory in storage, but **orphaned `EntryEntity` records for files under that directory remain in Postgres**. The delete layer only handles single-file deletion.
- **PROPFIND** (`read_dir`): Queries OpenDAL storage directly, not Postgres. This means it can find empty directories that MKCOL created in storage, but the DB doesn't know about them.

**This is already broken in the admin server** — directory operations create inconsistencies between the OpenDAL storage layer and the Postgres metadata layer. It's just not visible because the admin endpoint is lightly used.

**What needs to be resolved for client server WebDAV:**
- **MKCOL**: Either add explicit directory entries to the `entries` table (with a flag or null content_hash), or use the existing implicit model and accept that empty directories can't be represented in the DB.
- **Directory DELETE**: Must delete all `EntryEntity` records with matching path prefixes. The DB supports this (it's a prefix query on the `path` column), but it needs to be built — the current `WriteFinalizationLayer` doesn't do it.
- **COPY/MOVE of directories**: Recursive operations that need to update/duplicate all child `EntryEntity` records and their corresponding storage objects.
- **PROPFIND consistency**: Should PROPFIND query the DB (which has metadata like content_hash, timestamps) or OpenDAL (which knows about empty directories)? The answer depends on whether explicit directory entries are added to the DB.

## PATs as an Orthogonal Concern

PATs are only needed for standard WebDAV clients (Finder, rclone, Cyberduck) that cannot perform Ed25519 auth. The SDK and any Pubky-aware application would access the same WebDAV endpoints using the existing grant-based auth — COPY, MOVE, LOCK all work identically regardless of authentication method.

This means WebDAV methods can be shipped and used immediately without PATs. PATs are a separate workstream that unlocks standard client access when needed.

## Options

### Option A: Use `dav-server` on the Client Server

Integrate `dav-server` into the client server the same way it's used in the admin server (once fixed), but wrapped with Pubky's capability-based auth middleware.

**How it would work:**
- Mount a `DavHandler` on the client server (e.g., at `/storage/{pubkey}/` or alongside existing routes)
- Before each request, extract the Bearer token / cookie, resolve the `AuthSession`, check capabilities against the request method + path
- Construct a scoped OpenDAL operator for the authenticated user and pass the request to `DavHandler`
- Keep existing REST endpoints (`GET /dir/` returning `pubky://` URLs) alongside WebDAV methods — they use different HTTP methods so they don't conflict

**Pros:**
- COPY, MOVE, LOCK/UNLOCK protocol handling comes for free — this is the primary value
- `DavFileSystem` trait goes through OpenDAL operators, so `WriteFinalizationLayer` handles quota/events
- Autoindex and XML multistatus responses handled by the crate
- Significantly less code than a from-scratch implementation

**Cons:**
- Auth wrapping complexity: every request must be intercepted, authenticated, and scoped before reaching `DavHandler`. The multi-tenant model (each user has isolated storage) means you may need per-request operator construction or careful path rewriting
- `DavHandler` owns the full request lifecycle — harder to customize response formats, add custom headers, or integrate with Pubky-specific concerns (events, quotas) at fine granularity
- COPY/MOVE quota semantics need verification: does `WriteFinalizationLayer` fire correctly for the destination when `dav-server` internally performs a copy? If not, quota accounting breaks
- LOCK requires implementing `DavLockSystem` regardless (backed by Postgres)
- Coupling to a niche, infrequently-maintained crate for a client-facing API surface
- Implicit directory model may conflict with `dav-server`'s expectations — MKCOL creates explicit directories, but the current data model has none

**`DavFileSystem` fit** (see Appendix A): The existing `OpendalFs` implementation covers all 8 overridable methods needed for basic operations. This option reuses it directly, so no trait implementation work is needed beyond what already exists. However, the `OpendalFs` adapter does not implement property methods (`get_props`, `patch_props`) or `get_quota` — these would return "not implemented" to WebDAV clients.

### Option B: Build WebDAV Methods Natively in Axum

Implement PROPFIND, MKCOL, COPY, MOVE, LOCK/UNLOCK as axum route handlers using the existing `EntryRepository`, `FileService`, and OpenDAL stack directly.

**How it would work:**
- Add new axum handlers for each WebDAV method alongside the existing GET/PUT/DELETE
- PROPFIND queries `EntryRepository` and serializes XML multistatus responses
- COPY/MOVE use `FileService` operations with explicit quota accounting
- LOCK/UNLOCK backed by a new `locks` table in Postgres
- Each handler uses the existing auth middleware (`has_read_permission` / `has_write_permission`)

**Pros:**
- Full control over auth, path model, quota accounting, and event emission — no impedance mismatch
- Multi-tenant capability-based auth works naturally per-handler
- COPY/MOVE can implement correct quota semantics (COPY charges the destination user, MOVE is neutral) with transactional DB updates
- No new dependencies — uses existing axum + sqlx + OpenDAL stack
- Backward compatible — existing REST endpoints unchanged, WebDAV methods added alongside
- Can evolve independently without being constrained by an upstream crate's release cycle

**Cons:**
- Significant implementation effort, especially:
  - **PROPFIND**: XML multistatus (207) generation, `Depth: 0/1/infinity` handling, property marshalling, namespace handling
  - **LOCK/UNLOCK**: Token management, timeout, refresh, conflict detection, `If` header conditional logic, shared vs exclusive locks (RFC 4918 sections 6–8) — this is the hardest piece
  - **COPY/MOVE**: Recursive operations with partial-failure reporting (207 on errors), overwrite semantics, cross-directory atomicity
- Risk of spec non-compliance — WebDAV (RFC 4918) has many edge cases that are easy to get wrong
- Needs interop testing against real WebDAV clients (Finder, Windows Explorer, rclone, Cyberduck, cadaver)
- MKCOL requires a decision about the data model: add explicit directory entries to the DB, or use marker files?


### Option C: Hybrid — `dav-server` for Admin, Native for Client

Keep the admin server's `dav-server` integration as-is. Build only the needed WebDAV methods natively on the client server.

**How it would work:**
- Admin `/dav/*` endpoint unchanged
- Client server gets native axum handlers for PROPFIND, MKCOL, COPY, MOVE, LOCK/UNLOCK
- Two separate implementations, each optimized for its context

**Pros:**
- No disruption to working admin server
- Client server gets purpose-built handlers with correct auth and quota integration
- Can prioritize methods incrementally (PROPFIND first, then COPY/MOVE, then LOCK)

**Cons:**
- Two WebDAV implementations to maintain — divergent behavior is possible
- Full implementation effort on the client side (same as Option B)
- Admin server still depends on `dav-server` maintenance

**`DavFileSystem` fit**: Not applicable for the client server (native implementation). Admin server continues using existing `OpendalFs`.

### Option D: `dav-server` for Both, with Custom `DavFileSystem` and `DavLockSystem`

Use `dav-server` on both admin and client servers, but implement a custom `DavFileSystem` (instead of `OpendalFs`) that wraps `FileService` directly, giving full control over quota, events, and auth at the storage layer.

**How it would work:**
- Implement `DavFileSystem` trait backed by `FileService` + `EntryRepository` rather than raw OpenDAL
- Implement `DavLockSystem` trait backed by a Postgres `locks` table
- The custom filesystem handles quota accounting, event emission, and permission checks internally
- `DavHandler` handles protocol-level concerns (XML, multistatus, depth, conditional headers)

**Pros:**
- Protocol complexity (XML, PROPFIND, LOCK token negotiation) handled by `dav-server`
- Business logic (quota, events, permissions) handled by your code in the trait implementations
- Cleaner separation of concerns than Option A (wrapping the opaque handler)
- Single codebase for both admin and client (different `DavFileSystem` instances with different permission models)
- COPY/MOVE quota semantics are correct because your `DavFileSystem::copy`/`DavFileSystem::rename` implementations control the logic

**Cons:**
- Implementing `DavFileSystem` is non-trivial — the trait has 16 methods (3 required, 13 with defaults). The required methods (`open`, `read_dir`, `metadata`) plus the core mutation methods (`create_dir`, `remove_dir`, `remove_file`, `rename`, `copy`) need full implementations backed by `FileService` and `EntryRepository`. The `open` method must return a `Box<dyn DavFile>`, requiring a custom file adapter that bridges OpenDAL streams to `DavFile`'s read/write/seek interface.
- Still coupled to `dav-server` crate maintenance
- Must verify that `dav-server` calls the trait methods in the expected order for each WebDAV operation (e.g., does COPY call `copy()` or does it `open()` + `write()` the destination?)
- Lock system implementation effort is the same regardless
- Debugging issues requires understanding both your trait implementation and `dav-server`'s internal dispatch

**`DavFileSystem` fit** (see Appendix A): The existing `OpendalFs` implementation provides a good reference — it implements 8 of the 16 methods, leaving properties and quota as defaults. A custom implementation backed by `FileService` would need the same 8 methods but could additionally implement `get_quota` (data already available from `UserEntity.used_bytes`). The `open` method is the most complex — it must return a `DavFile` implementation that wraps OpenDAL's streaming read/write. The `OpendalFs` source shows how this is done via `OpendalFile` and can be adapted.

---

## Appendix A: `DavFileSystem` Trait

Full trait definition from `dav-server` v0.8.0:

```rust
pub trait DavFileSystem: Debug + Send + Sync + DynClone {
    // === REQUIRED (no defaults) ===

    fn open<'a>(
        &'a self, path: &'a DavPath, options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>>;

    fn read_dir<'a>(
        &'a self, path: &'a DavPath, meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>>;

    fn metadata<'a>(
        &'a self, path: &'a DavPath,
    ) -> FsFuture<'a, Box<dyn DavMetaData>>;

    // === OPTIONAL (defaults return NotImplemented) ===

    fn symlink_metadata(&self, path) -> FsFuture<Box<dyn DavMetaData>>;  // default: delegates to metadata()
    fn create_dir(&self, path) -> FsFuture<()>;
    fn remove_dir(&self, path) -> FsFuture<()>;
    fn remove_file(&self, path) -> FsFuture<()>;
    fn rename(&self, from, to) -> FsFuture<()>;
    fn copy(&self, from, to) -> FsFuture<()>;
    fn set_accessed(&self, path, time) -> FsFuture<()>;
    fn set_modified(&self, path, time) -> FsFuture<()>;
    fn have_props(&self, path) -> Pin<Box<dyn Future<Output = bool>>>;  // default: false
    fn patch_props(&self, path, patch) -> FsFuture<Vec<(StatusCode, DavProp)>>;
    fn get_props(&self, path, do_content) -> FsFuture<Vec<DavProp>>;
    fn get_prop(&self, path, prop) -> FsFuture<Vec<u8>>;
    fn get_quota(&self) -> FsFuture<(u64, Option<u64>)>;
}
```

**`OpendalFs` implements**: `open`, `read_dir`, `metadata`, `create_dir`, `remove_dir`, `remove_file`, `rename`, `copy` (8 of 16).

**`OpendalFs` leaves as defaults**: `symlink_metadata`, `set_accessed`, `set_modified`, `have_props`, `patch_props`, `get_props`, `get_prop`, `get_quota`.

## Appendix B: `DavLockSystem` Trait

Full trait definition from `dav-server` v0.8.0:

```rust
pub trait DavLockSystem: Debug + Send + Sync + DynClone {
    fn lock(
        &self, path: &DavPath, principal: Option<&str>, owner: Option<&Element>,
        timeout: Option<Duration>, shared: bool, deep: bool,
    ) -> LsFuture<Result<DavLock, DavLock>>;

    fn unlock(&self, path: &DavPath, token: &str) -> LsFuture<Result<(), ()>>;

    fn refresh(
        &self, path: &DavPath, token: &str, timeout: Option<Duration>,
    ) -> LsFuture<Result<DavLock, ()>>;

    fn check(
        &self, path: &DavPath, principal: Option<&str>, ignore_principal: bool,
        deep: bool, submitted_tokens: Vec<&str>,
    ) -> LsFuture<Result<(), DavLock>>;

    fn discover(&self, path: &DavPath) -> LsFuture<Vec<DavLock>>;

    fn delete(&self, path: &DavPath) -> LsFuture<Result<(), ()>>;
}
```

All 6 methods are required (no defaults). A Postgres-backed implementation would need a `locks` table storing path, token, owner, `expires_at` timestamp, and depth. Since only exclusive locks are required, the `shared` parameter on `lock()` can be rejected (return conflict). The `check()` method is called by `dav-server` before every mutating operation — it must query for active (non-expired) locks on the exact path and, for deep locks, on all ancestor paths. Expired locks are treated as non-existent (lazy cleanup).
