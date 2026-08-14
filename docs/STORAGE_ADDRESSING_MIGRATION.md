# Storage Addressing Migration

New SDKs will send storage requests to path-addressed routes. Older SDKs use
owner-relative routes:

```text
Legacy: GET /pub/example.txt + pubky-host
Path:   GET /storage/{user-z32}/pub/example.txt
```

The homeserver will keep legacy storage addressing, `pubky-host`, and cookie
authentication during the migration. Maintainers may remove them only after
the minimum migration period and an explicit review.

## Migration metric

The homeserver exports `storage_request_count_total`. Each request that reaches
a tenant storage route is counted once with these fixed labels:

| Label | Values | Meaning |
| --- | --- | --- |
| `addressing_mode` | `path`, `legacy` | Where the homeserver got the owner: `/storage/{user-z32}/...` or legacy request addressing. |
| `pubky_host_header` | `absent`, `matching`, `other` | The header was absent, matched the resolved owner, or held a different or invalid value. |
| `pubky_host_query` | `true`, `false` | The request included a `pubky-host` query parameter. |
| `auth_method` | `none`, `cookie`, `grant` | How the homeserver authenticated the request. `none` includes anonymous requests and unresolved credentials; `grant` means bearer/grant authentication. |

These labels produce at most 36 combinations. No label contains a cookie,
bearer token, public key, or storage path.

Use these PromQL queries:

```promql
# Path-addressed versus legacy requests over the last 30 days.
sum by (addressing_mode) (increase(storage_request_count_total[30d]))

# Remaining pubky-host header usage, split by addressing mode.
sum by (addressing_mode, pubky_host_header, pubky_host_query) (
  increase(storage_request_count_total{
    pubky_host_header!="absent"
  }[30d])
)

# Remaining pubky-host query-parameter usage.
sum by (addressing_mode) (
  increase(storage_request_count_total{pubky_host_query="true"}[30d])
)

# Cookie versus grant authentication on storage requests.
sum by (auth_method) (increase(storage_request_count_total[30d]))
```

## Collection requirements

Metrics are disabled by default. Counters reset when the homeserver restarts.
Operators contributing data to the migration review must:

1. Enable `[metrics]` and scrape `GET /metrics` with Prometheus or a compatible
   collector.
2. Keep the metrics listener isolated from the public network; it is
   unauthenticated.
3. Start collecting before the stable path-addressing SDK is published, and
   retain the time series for at least the full migration period.
4. Aggregate all instances of a multi-instance homeserver when comparing
   adoption.

## Migration clock

The one-year minimum starts on the release date of the first stable SDK that
uses `/storage/{user-z32}/{storage-path}` by default. A merge, prerelease, or
homeserver-only release does not start the clock.

| Milestone | SDK version | UTC date |
| --- | --- | --- |
| First stable path-addressing SDK release | Not released ([#527](https://github.com/pubky/pubky-homeserver/issues/527)) | Not started |
| Earliest legacy-removal review | Stable release version | Stable release date + one year |

Update this table as part of publishing that stable SDK release.

## Breaking-release review

After the earliest review date:

1. Collect path/legacy, `pubky-host`, and cookie/grant time-series from
   participating operators, including recent usage and known coverage gaps.
2. Record the evidence and maintainer decision in
   [#529](https://github.com/pubky/pubky-homeserver/issues/529). The elapsed year
   does not authorize removal automatically.
3. If removal is approved, ship it as a coordinated breaking homeserver and SDK
   release with upgrade requirements and release notes.
4. If removal is not approved, keep compatibility and record the next review
   date.
