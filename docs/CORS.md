# CORS

Browser apps call the homeserver from their own origin, so every response
they read needs CORS headers. Either the homeserver or your reverse proxy
can send them, but not both. If both add them, browsers receive the headers
twice and reject the response.

| Setup | `[drive] cors_enabled` | Reverse proxy |
| --- | --- | --- |
| Homeserver handles CORS (default) | `true` | Sends no CORS headers. |
| Reverse proxy handles CORS | `false` | Sends the headers described below. |

## What the homeserver sends

With `cors_enabled = true`, the homeserver allows browser apps on every
origin:

- It answers every `OPTIONS` request as a preflight. The request doesn't
  reach the API.
- It mirrors the request's `Origin`, method, and headers into
  `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and
  `Access-Control-Allow-Headers`.
- It sends `Access-Control-Allow-Credentials: true`. Browser apps on SDK 0.16
  and earlier include credentials on grant sign-in and public reads, and
  browsers reject those responses without this header.
- It exposes these response headers with `Access-Control-Expose-Headers`:

  | Header | Used for |
  | --- | --- |
  | `Retry-After` | The wait time on a `429 Too Many Requests` from the rate limiter. |
  | `Lock-Token` | The token of a granted WebDAV lock. The SDK sends it back to unlock. |
  | `Timeout` | How long a granted WebDAV lock lasts. |

  By default, a page can only read a few safelisted headers, such as
  `Content-Type`, from a cross-origin response. Without this list, the
  browser SDK can't read a granted lock and fails to lock files.

## Handle CORS in nginx

To let nginx handle CORS:

1. In the homeserver's `config.toml`, turn off the built-in CORS layer and
   restart the homeserver:

   ```toml
   [drive]
   cors_enabled = false
   ```

1. Add these `map` blocks to the `http` context, next to your `server` block:

   ```nginx
   # Credentials and exposed headers only apply to cross-origin requests.
   map $http_origin $cors_allow_credentials {
       ""      "";
       default "true";
   }

   map $http_origin $cors_expose_headers {
       ""      "";
       default "Retry-After, Lock-Token, Timeout";
   }
   ```

1. Add these lines to the `location` that proxies to the homeserver:

   ```nginx
   # nginx skips headers with an empty value, so requests without `Origin`
   # get no CORS headers. `always` adds them to error responses too.
   add_header Access-Control-Allow-Origin      $http_origin always;
   add_header Access-Control-Allow-Credentials $cors_allow_credentials always;
   add_header Access-Control-Expose-Headers    $cors_expose_headers always;
   # Only set on preflights, which carry these request headers.
   add_header Access-Control-Allow-Methods     $http_access_control_request_method always;
   add_header Access-Control-Allow-Headers     $http_access_control_request_headers always;
   add_header Vary "Origin, Access-Control-Request-Method, Access-Control-Request-Headers" always;

   # Like the homeserver, answer every OPTIONS request as a preflight
   # without passing it on.
   if ($request_method = OPTIONS) {
       return 204;
   }
   ```

   nginx only inherits `add_header` directives from the `server` or `http`
   context when the `location` has none of its own. If you set other headers
   at those levels, such as `Strict-Transport-Security`, repeat them in this
   `location`.

   The config mirrors the request's `Origin` instead of sending `*`, because
   browsers reject `Access-Control-Allow-Origin: *` together with
   credentials.

1. Check the config and reload nginx:

   ```sh
   sudo nginx -t
   sudo systemctl reload nginx
   ```

1. Check that a preflight returns each CORS header exactly once:

   ```sh
   curl -si -X OPTIONS https://homeserver.example.com/info \
     -H "Origin: https://app.example" \
     -H "Access-Control-Request-Method: PUT" \
     -H "Access-Control-Request-Headers: authorization"
   ```

   The response is `204 No Content` with one each of
   `Access-Control-Allow-Origin: https://app.example`,
   `Access-Control-Allow-Credentials: true`,
   `Access-Control-Allow-Methods: PUT`, and
   `Access-Control-Allow-Headers: authorization`. If a header appears twice,
   the homeserver still has `cors_enabled = true`.

1. Check that a normal request exposes the lock and rate-limit headers:

   ```sh
   curl -si https://homeserver.example.com/info -H "Origin: https://app.example"
   ```

   The response includes
   `Access-Control-Expose-Headers: Retry-After, Lock-Token, Timeout`.

## Simplify once credentials are gone

`Access-Control-Allow-Credentials` is only needed while browser apps send
credentials: apps that use the deprecated cookie session, and apps on SDK
0.16 and earlier. Browsers don't accept wildcards together with credentials,
which is why the headers above mirror the origin and name each exposed
header. Once those apps are gone, the homeserver will drop
`Allow-Credentials`. Your proxy can then send
`Access-Control-Allow-Origin: *` and `Access-Control-Expose-Headers: *`.
