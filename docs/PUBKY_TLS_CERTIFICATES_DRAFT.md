# Draft Pubky TLS support for raw keys and signed certificates

Allow the native SDK to connect to servers presenting either a raw public
key (RPK) or an X.509 certificate signed by the endpoint's Pubky key.
Negotiate the format in one handshake, without caller settings or fallback.
Start with SDK support; add homeserver certificate serving separately.

## How it works

1. Resolve the endpoint and its identity key through PKARR.
2. Advertise both formats in the TLS ClientHello:

   ```text
   server_certificate_type = [RawPublicKey, X509]
   ```

3. The server selects a format. An omitted extension means X.509.
4. Authenticate the server:
   - RPK: the raw key must match the PKARR endpoint key.
   - X.509: the certificate's signature must verify against that key.
     Its TLS key may be the same key or a separate key.
5. Verify the handshake signature using the presented TLS key before sending
   HTTP data.

Use the authenticated endpoint key, including PKARR delegation. This may
be different from the user's key. The negotiation follows [RFC 7250].

## Required changes

We currently use Rustls 0.23.45, Reqwest 0.13.5, and Pkarr 8.1.0.
Rustls 0.23 cannot advertise both formats through its existing verifier API.

**Rustls:** backport support for a list of accepted formats, validate the
server's selection, and pass the selected format into verification.
Keep that selection per connection and preserve existing verifier behavior.
Use upstream's 0.24 design as a reference while retaining 0.23 compatibility.

**SDK:** add a verifier for both formats, reusing Pkarr's RPK verification.
Initially accept one certificate with an Ed25519 key and Ed25519 signature.
Check validity dates, key usage, and critical extensions. Document the
certificate requirements.

Install this configuration through Reqwest's `tls_backend_preconfigured()`
while keeping Pkarr's DNS resolver. No Reqwest source changes or SDK request
API changes are expected. Start with TLS 1.3 and disable resumption until
its behavior is tested. Browser/WASM support remains unchanged.

## Dependency distribution

Apply the patched Rustls crate at the workspace root:

```toml
[patch.crates-io]
rustls = { path = "vendor/rustls" }
```

All dependencies must use that same Rustls package. SDK consumers also need
this override: Cargo patches do not propagate from libraries to applications.
An upstream release containing the backport would remove this requirement.

## Tests

Use one SDK client against RPK and certificate servers, including delegated
endpoints and certificates containing a separate TLS key. Confirm that each
successful connection uses one handshake.

Reject wrong keys, invalid certificate or handshake signatures, expired
certificates, and unoffered formats. Test concurrent connections, X.509 by
omission, and existing Rustls behavior. Cover handshake retries, certificate
compression, and resumption before enabling those paths.

Run the Rustls tests and repository formatting, Clippy, SDK tests, and
applicable WASM checks. Confirm ordinary ICANN HTTPS still works.

[RFC 7250]: https://www.rfc-editor.org/rfc/rfc7250.html
