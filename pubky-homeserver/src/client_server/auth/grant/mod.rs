//! Grant-based authentication (current auth flow).
//!
//! This module adds per-app sessions using short-lived opaque bearers
//! bound to long-lived, revocable **Grants**.
//!
//! # Design principles
//!
//! - **Cold key model**: Ring (the user's key manager) signs only at Grant creation.
//!   The client app refreshes bearers autonomously using PoP proofs — no Ring needed.
//! - **Mirror-friendly**: a Grant has no `aud` claim. The same Grant can be exchanged
//!   at any homeserver in the user's pkarr record.
//! - **Bearer as opaque pointer**: capabilities and metadata live server-side, keyed
//!   by `SHA-256(bearer)`. A DB leak cannot yield usable bearers, and revocation is
//!   instant.
//! - **PoP binding**: prevents Grant replay by third parties and homeservers. With
//!   WebCrypto non-extractable keys, also prevents Grant theft via XSS.
//!
//! # Token types
//!
//! | Token | Signer | Lifetime | Purpose |
//! |-------|--------|----------|---------|
//! | **Grant** (`pubky-grant`) | User keypair | Long-lived | Delegates scoped capabilities to a client app |
//! | **PoP proof** (`pubky-pop`) | Client keypair | ±3 min | Proves possession of the key bound by Grant `cnf` |
//! | **Session bearer** | 32 random bytes (OsRng), SHA-256 hashed at rest | 1 hour | Opaque `Authorization: Bearer` token for API requests |
//!
//! The Grant and PoP tokens use EdDSA (Ed25519) in JWS Compact Serialization. The
//! session bearer carries no claims — it is 256 bits of CSPRNG output presented
//! verbatim by the client and hashed on the homeserver side for lookup.
//!
//! Each Grant carries a self-declared `client_id` (domain string, like OAuth public
//! clients) for session separation — the security boundary is capability scoping,
//! not `client_id`.
//!
//! # Flow
//!
//! ## 1. Session creation (`POST /auth/grant/session`, JSON body)
//!
//! The client sends a **Grant JWS** + **PoP JWS**. The homeserver verifies both
//! (signature, expiry, PoP audience/nonce/timestamp), stores the Grant idempotently,
//! generates a fresh opaque bearer, and inserts a session row holding only
//! `SHA-256(bearer)` (max 1 per Grant; oldest evicted).
//!
//! ## 2. Authenticating requests
//!
//! [`GrantAuthenticationMiddleware`](middleware::GrantAuthenticationMiddleware) extracts
//! the `Authorization: Bearer` value, hashes it, looks up the session by hash, and
//! checks the Grant is not revoked/expired. An unknown or oversized bearer is rejected
//! with 401.
//!
//! ## 3. Grant management (root capability required)
//!
//! - `GET /auth/grant/sessions` — list active Grants.
//! - `DELETE /auth/grant/session/{grant_id}` — revoke a Grant and delete all its sessions.
//!
//! ## 4. Replay protection
//!
//! - **Nonce**: each PoP nonce is tracked in `pop_nonces` (unique constraint, GC after 360 s).
//! - **Audience**: PoP `aud` must match this homeserver's public key.

pub(crate) mod bearer;
pub mod crypto;
mod error_mapping;
pub mod middleware;
pub mod persistence;
pub mod routes;
pub mod service;
pub mod service_error;
pub mod session;
