# Hierarchical encryption key vectors

[hierarchical-keys-v1.json](hierarchical-keys-v1.json) contains shared v1 test
vectors and a dummy identity secret. Never use these keys in production.

`identity_secret_hex` and `key_hex` are 32-byte lowercase hex values. Paths are
canonical and decoded: `/` yields the root seed, paths with a trailing slash
yield directory seeds, and other paths yield file keys. `/priv/` tests derivation, not storage
support.

Outputs were calculated independently with Python `hashlib` and `hmac`:

- Extract: `PRK = HMAC-SHA256(32 zero bytes, identity_secret)`.
- Root: `HMAC-SHA256(PRK, UTF8("pubky/hierarchical-keys/v1/root") || 0x01)`.
- Child: `HMAC-SHA256(parent, label || 0x00 || UTF8(segment) || 0x01)`.

Child labels are `pubky/hierarchical-keys/v1/directory` and
`pubky/hierarchical-keys/v1/file-content`. Segments exclude slashes. Each output
uses one HKDF expansion block; do not extract again for children.

Percent signs are literal. Unicode is not normalized: the NFC and NFD vectors
produce different keys. Derivation from a parent seed must match derivation
from the identity. Rust tests cover every vector; WASM tests cover file keys
from root and parent scopes.

These v1 labels, encodings, and outputs are permanent recovery inputs. Preserve
this fixture; derivation changes require a new version and fixture.
