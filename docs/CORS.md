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

1. Add the CORS headers to your nginx config. The `map` blocks go in the
   `http` context, next to your `server` block:

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

   server {
       listen 443 ssl;
       server_name homeserver.example.com;
       # ssl_certificate and ssl_certificate_key go here.

       location / {
           # nginx skips headers with an empty value, so requests without
           # `Origin` get no CORS headers. `always` adds them to error
           # responses too.
           add_header Access-Control-Allow-Origin      $http_origin always;
           add_header Access-Control-Allow-Credentials $cors_allow_credentials always;
           add_header Access-Control-Expose-Headers    $cors_expose_headers always;
           # Only set on preflights, which carry these request headers.
           add_header Access-Control-Allow-Methods     $http_access_control_request_method always;
           add_header Access-Control-Allow-Headers     $http_access_control_request_headers always;
           add_header Vary Origin always;

           # Answer preflights here, as the homeserver would.
           if ($request_method = OPTIONS) {
               return 204;
           }

           proxy_pass http://127.0.0.1:6286;
           proxy_set_header Host $host;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

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
