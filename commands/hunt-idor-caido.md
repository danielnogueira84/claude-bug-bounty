---
description: Hunt IDOR/BOLA across the Caido HTTP history using canary seeding + a 3-state differential (A→A / A→B / B→B) replayed server-side. Turns the flood of "200 on token-swap" into a short ranked list of PROVEN cross-object/cross-tenant reads. Not a status-code scanner. Usage: /hunt-idor-caido "2026-08-05 16:50" [--scope <name>] [--accounts A=<label>,B=<label>]
---

# /hunt-idor-caido

Hunt **IDOR / BOLA** across the **already-captured Caido HTTP history** — the sibling of `/hunt-caido` (which proves *injection*). This command proves **broken object-level authorization**: can identity **A** read/modify an object that belongs to identity **B**?

The hard part of IDOR is **interpretive** — a `200` on a token-swap replay is NOT a finding. It can be (1) the endpoint ignoring the ID and returning the *caller's own* data, (2) a global/public resource, or (3) a real cross-object leak. Status code can't tell them apart. This command removes the interpretation with **two mechanisms**:

1. **Canary seeding** — each test account is pre-seeded with unique greppable markers. A cross-tenant leak is then *deterministic*: account B's canary appearing in account A's response = proven.
2. **3-state differential** — for responses with no greppable canary (pure numeric/opaque data), compare `A→A` (control), `A→B` (attack), `B→B` (oracle).

This is a **methodology command driven through the Caido MCP** (`mcp__caido__*`), plus Chrome MCP for render/UI confirmation. It does **not** call `tools/hunt.py`.

> **Environment (standing authorization).** The operator works inside **orca.dev**. You MAY, without asking each time: (1) open the **Orca embedded browser** to visually validate anything on screen / in the DOM that server-side replay can't show (render of a leaked field, UI state of a flow) — routed through Caido per memory `orca-browser-caido-proxy`; (2) **use or create Google Chrome profiles** to isolate the A and B test sessions (one profile per account) per memory `chrome-profiles-multiaccount`. This covers driving the browser and managing profiles only — it does **not** waive scope or the destructive-action confirmation. See memory `feedback-orca-browser-authorization`.

## Usage

```
/hunt-idor-caido "2026-08-05 16:50"                              (all in-scope objects after cutoff)
/hunt-idor-caido "2026-08-05 16:50" --scope Mercury             (pin scope by name)
/hunt-idor-caido "2026-08-05 16:50" --accounts A=empresa-a,B=empresa-b
/hunt-idor-caido "2026-08-05 16:50" --tz -03                    (datetime offset; default America/Sao_Paulo)
```

Datetime is interpreted in the operator's local offset (default `-03`) unless `--tz` is given.

---

## Prerequisites — the account vault (≥3 identities), seeded with canaries

IDOR/BOLA needs several identities you control, at different privilege levels and tenants. **Load them from the account vault** (`tools/account_vault.py`) — the per-target store of logins, roles, groups, companies, canaries, and live sessions (with TTL + refresh recipe). The vault lives **outside git** in Claude's project memory dir (`~/.claude/projects/<slug>/memory/accounts/<target>.json`, `0600`) so credentials are never pushed.

**Standard role model (at least 3; extend per target):**

| Label | Role | Company | Tests |
|---|---|---|---|
| `A-admin` | full-access admin / Owner | Company A | baseline that legitimately sees all |
| `B-admin` | admin, **different company** | Company B | **cross-tenant** BOLA (A↔B) |
| `A-lowpriv` | restricted user | Company A | **vertical privesc / BFLA** (can lowpriv hit admin-only endpoints *in its own tenant*?) |
| `A-<role>` | any specific role | Company A | per-role authorization gaps |

So "attacker A / victim B" generalizes: pick the attacker/victim pair per test — `A-admin→B-admin` (cross-tenant), `A-lowpriv→A-admin` (vertical), `A-lowpriv→B-*` (cross-tenant + horizontal), etc.

```
python3 tools/account_vault.py list <target>              # see labels/roles/companies + session freshness
python3 tools/account_vault.py get  <target> A-admin --field session.bearer
python3 tools/account_vault.py stale <target> <label>     # exit 3 = session expired -> refresh it
```

**Session handling — always work with a fresh session.** Before replaying as any identity: `stale <target> <label>`; if STALE (or `no-session`), run that account's **refresh recipe** (`get <target> <label> --field refresh.how`) — hit the token endpoint, re-login with the stored user/password, or read it from the account's Chrome profile — then write it back with `set-session <target> <label> --bearer ... --cookie k=v --ttl N`. Never build a test on an expired session (produces false negatives).

**Seed canaries BEFORE testing (write access).** In every *writable* field that can surface in a response — name, company/org name, note/description, address, email local-part — write a unique improbable marker per account, and store it in the vault (`set-field <target> <label> canary ZZCAN-...`):

- `A-admin`: `ZZCAN-A-<rand>` · `B-admin`: `ZZCAN-B-<rand>` · `A-lowpriv`: `ZZCAN-Alow-<rand>`
- Email canary via H1 subaddressing: `myliberty+canB-7f3a@wearehackerone.com`

Prefix `ZZCAN-` + role + 6 hex, colliding with nothing in the app. Step 4 greps for them. Read-only fields fall back to the differential matrix.

> Why seed: it converts "is this data relevant / someone else's?" (a judgment call) into `grep ZZCAN-B` (a fact). This is the whole point of the command.

## Step 1 — Resolve scope (never test out-of-scope)

1. `mcp__caido__caido_list_scopes`. Pick the scope named by `--scope`, else infer / ask.
2. Note **allowlist AND denylist** (e.g. Tradeshift allows `*.tradeshift.com` but **denies** `go.` / `api.`; Mercury auth-test only on `pentest.mercury.com`). Confirm doubtful hosts with `mcp__caido__caido_is_in_scope`.

## Step 2 — Find the cutoff request-id (date → ID bisection)

Identical to `/hunt-caido` Step 2 — the HTTPQL date filter does **not** work, and request-ids are **sparse with large gaps**, so you bisect with **forged cursors + `caido_list_requests`**, never with loose `caido_get_request` on guessed ids:

```bash
TZ=America/Sao_Paulo date -j -f "%Y-%m-%d %H:%M:%S" "2026-08-05 16:50:00" +%s   # cutoff → unix
printf '{"id":"<ID>","order_value":null}' | base64                               # forge a cursor at <ID>
```
```
caido_list_requests(httpql:'req.host.cont:"<scope-token>"', after:<forged-cursor>, limit:3)
```
- **Empty + `hasMore:false`** ⇒ nothing at/after `<ID>` → max is below `<ID>`; bisect down.
- **Non-empty** ⇒ traffic above `<ID>`; read the returned ids' `createdAt` (via `caido_get_request` on **ids the list actually returned**, never guesses) to pick a side. Binary-search until you bracket first-id-with-`createdAt ≥ cutoff`.

Reuse that id's forged cursor as `after` for Step 3. ("not found" on a guessed id = a gap, **not** the end — same miss mode documented in `/hunt-caido`.)

## Step 3 — Select OBJECT-REFERENCING requests (filter the noise)

IDOR candidates are requests that **reference an object the server scopes by owner**. Paginate `caido_list_requests` to **`hasMore:false`** (20/page, loop the cursor) and **state the counts** ("window = N requests, M object-referencing candidates"). Then **keep only** requests with an object reference:

- **Path IDs**: `/account/{id}`, `/orders/{uuid}`, `/v4/apps/.../{companyId}/...`
- **Query refs**: `?id=`, `?companyId=`, `?userId=`, `?documentId=`, `?org=`
- **Body refs**: `targetCompanyId`, `ownerId`, `accountId` in a JSON/XML body (pull the body — the list shows only `id/method/url/status`, **never** judge a POST by its URL, same trap as `/hunt-caido`)

**Drop** (not IDOR candidates): `/me`-style self-scoped routes with no object ref, auth/token endpoints, static assets, OPTIONS, telemetry, and genuinely global/public resources (same response for everyone — you'll confirm "global" in Step 4, don't assume from the URL).

> Classify each candidate's **operation**: READ (GET) → information disclosure IDOR; WRITE (POST/PUT/PATCH/DELETE) → the higher-impact BOLA (modify/delete another tenant's object). Test both; a write-IDOR outranks a read-IDOR.

## Step 4 — Per candidate, run the 3-state differential (the core)

For each candidate you need **three identities-of-request**. **Always replay server-side with `mcp__caido__caido_send_request` using a FRESH token for each account** — a cross-origin browser `fetch` can return a spurious `405`. Pull fresh sessions (tokens expire fast; e.g. Tradeshift `/v4/accesstoken` → `.accessToken` already includes `Bearer `; Mercury uses cookie + `X-HackerOne-ID`).

Build the matrix by swapping **only the auth material** (Bearer / Cookie / tenant header), keeping method, path, body, resource-ID fixed to **B's object**:

| Test | Auth used | Resource ID in request | Role |
|---|---|---|---|
| **A→A** | A's session | **A's own** object | control — "what my own data looks like" |
| **A→B** | A's session | **B's** object | **the attack** |
| **B→B** | B's session | **B's** object | oracle — "what B's data looks like" |

**Decision (in priority order):**

1. **Canary hit** — `A→B` response body contains **`ZZCAN-B`** (or B's email canary) → **IDOR/BOLA CONFIRMED**, cross-tenant data leak proven. No interpretation needed. Record the exact field + snippet.
2. **No canary present in the response** (opaque/numeric data) → apply the matrix:
   - `A→B ≈ B→B` **and** `A→B ≠ A→A` → **IDOR** (A receives B's distinct data). Diff the bodies ignoring volatile fields (timestamps, request-ids, csrf tokens, trace-ids) — compare the *stable* fields.
   - `A→B ≈ A→A` → **FALSE POSITIVE** — the endpoint ignored the ID and returned A's own data. This is the #1 FP the raw token-swap worker flags as 200. Kill it.
   - `A→B` = `403` / `401` / empty / **redacted** (fields present but nulled/masked) → access control working → **kill the lead** (note: partial redaction that still leaks e.g. an email or internal id is a *partial* IDOR — keep it).
3. **WRITE candidates** — after `A→B` write returns success, **verify the mutation landed on B's object** by reading it back as `B→B` (did B's object actually change / get deleted?). A `200` on the write alone is not proof; the read-back is. For stored-XSS-via-IDOR, also render-check in Chrome.

4. **DELETE / consuming-op candidates — RE-PROVISION before replay.** A captured `DELETE` (or any one-shot/state-consuming op — redeem token, accept invite, mark-as-used, cancel, one-way status transition) **already consumed the object**. Replaying `A→B` on the original id hits a *gone* object and the `404`/no-op looks like access control — a **false negative** (the authz check often never runs; the object lookup fails before it). Idempotent deletes `200/204` whether or not anything was deleted. Instead:
   ```
   1. As B: create a FRESH object        → new id obj_B_new   (reuse the CREATE from history, or drive the UI once)
   2. As B: GET obj_B_new                → 200 (oracle: it exists)
   3. As A: DELETE/consume obj_B_new     (the cross-tenant attack)
   4. As B: GET obj_B_new again          → THE ORACLE, not the delete's own status:
         gone (404)                → BOLA CONFIRMED (A destroyed B's object)
         still there + A got 403   → authz held → kill
         still there + A got 200   → silent no-op / internally-scoped delete → not a bug (note it)
   ```
   The delete's own status code is unreliable (404-masking + idempotency) — **the read-back as B is the only proof.** Re-provision fresh state before *each* consuming replay.

> **MANDATORY — confirm each baseline is real before trusting a negative.** `A→A` and `B→B` must each return `200` + the expected object (not a login shell / error). A negative built on a broken baseline (wrong token, expired session, `404` login page) is invalid — e.g. Tradeshift `/v4/apps/...` needs Cookie **AND** Bearer or it returns a `404` shell with `TS_LOGGED_IN=false`.

> **Do NOT stop at same-object swaps.** Also test **2nd-order IDOR** (ID buried in a nested body field, base64/encoded ID, ID in a follow-up request of a flow) and **ID-prediction** (sequential ints → enumerate; UUIDs leaked elsewhere → reuse). The org-id-in-path being guarded (403) does **not** mean a bare resource-id is guarded — test the naked resource id too (see `mercury-idor-org-guard`).

## Step 5 — Rank and report (evidence in hand)

Output a **ranked list of CONFIRMED findings only**, most-impactful first (cross-tenant write > cross-tenant read > same-tenant cross-user > redaction-partial). For each:

- The request (method + path + which field held B's object id)
- The proof line: canary hit (`ZZCAN-B` in field X) **or** the matrix result (`A→B` body vs `A→A` vs `B→B`, with the distinguishing fields quoted) + status + trace/request-id
- Impact: what PII / capability crosses the boundary (roster, email, financial, ability to modify/delete)

Then:
- Log each confirmed finding to the lead board (`tools/lead_board.py`) and `touch` its status.
- Note any pollution created (canaries written, test objects) so it can be cleaned.
- Confirmed → `/validate` (7-Question Gate) → `/report`.

## Anti-patterns (do NOT do these)

1. **Treating a `200` on token-swap as a finding.** A 200 with no canary and `A→B ≈ A→A` is the endpoint handing you *your own* data — the single most common false positive. You MUST run `A→A` as a control; without it you cannot distinguish "returns their data" from "ignores the id and returns mine."

2. **Judging "is this data valuable" by eyeballing one response.** That's the interpretive trap this command exists to remove. Seed canaries and grep, or diff against the `B→B` oracle. "Looks like someone else's data" is not evidence; `ZZCAN-B` in the body is.

3. **Trusting a write `200` without read-back.** A successful-looking write to B's object proves nothing until you read B's object (as B) and confirm it actually mutated. APIs routinely `200` a write they silently drop.

4bis. **Reading a `404` on a replayed DELETE as "access control works."** The captured DELETE already consumed the object, so the replay hits nothing — the authz check never even ran. You MUST re-provision a fresh object as B first (Step 4 case 4). Declaring DELETE-IDOR "safe" from a replay against a gone object is a false negative, full stop.

4. **Building a negative on a broken baseline.** If `A→A` or `B→B` didn't return the real object, every verdict derived from it is void. Confirm both baselines first.

5. **Declaring an endpoint "self-scoped, not a candidate" from its URL.** Open the body; the object ref may be a nested `targetCompanyId`. Same URL-vs-body trap as `/hunt-caido`.

See memory `feedback-idor-canary-differential`, `mercury-idor-org-guard`, `tradeshift-finding-bola-account`, `chrome-profiles-multiaccount`.
