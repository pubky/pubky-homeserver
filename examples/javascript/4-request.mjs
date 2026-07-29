#!/usr/bin/env node
// Raw request using the Pubky HTTP client (expects resolved https:// transport URLs).
import { Pubky } from "@synonymdev/pubky";
import { args, printHttpResponse } from "./_cli.mjs";

const usage = `
Usage:
  node 4-request.mjs <METHOD> <URL> [--testnet] [-H "Name: value"]... [-d DATA]

Examples:
  node 4-request.mjs GET https://_pubky.<user>/pub/my-cool-app/info.json --testnet
  node 4-request.mjs \\
    -H "Content-Type: application/json" \\
    -H "Accept: application/json" \\
    -d '{"msg":"hello"}' \\
    POST https://example.com/data.json
  node 4-request.mjs GET https://_pubky.operrr8wsbpr3ue9d4qj41ge1kcc6r7fdiy6o3ugjrrhi4y77rdo/pub/pubky.app/posts/0033X02JAN0SG
`;

const a = args(process.argv.slice(2), {
  usage,
  aliases: { H: "header", d: "data" },
  defaults: { header: [] },
});
const [method, url] = a._;
if (!method || !url) {
  console.error(usage.trim());
  process.exit(1);
}

const pubky = a.testnet ? Pubky.testnet() : new Pubky();

const headers = {};
for (const h of Array.isArray(a.header)
  ? a.header
  : [a.header].filter(Boolean)) {
  const idx = h.indexOf(":");
  if (idx === -1) continue;
  headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
}

const res = await pubky.client.fetch(url, {
  method,
  headers,
  body: a.data ?? undefined,
  credentials: "include",
});

const body = res.headers.get("content-type")?.includes("application/json")
  ? JSON.stringify(await res.json(), null, 2)
  : await res.text();

printHttpResponse(res, body);
