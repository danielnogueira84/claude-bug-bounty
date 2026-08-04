# Tradeshift — HackerOne Submission Form Spec (reusable)

Mapped live from `https://hackerone.com/tradeshift/reports/new?type=team&report_type=vulnerability`
(private program; logged-in). Use this to build every Tradeshift report in the exact shape the
form expects. Last mapped: 2026-08-03.

## Program notes (read before submitting)
- **"Update April 2026":** program re-opened. Policy stresses **submission quality requirements**
  and **CRUD handling rules**. *Reports that don't meet the bar are closed without review.*
- **Severity method is CVSS 3.0 (HackerOne)** — NOT 3.1. Build the vector in 3.0 terms.
- **Bounty tiers:** Low $50–100 (avg $100) · Medium $100–500 (avg $311) · High $500–1000 (avg $532) ·
  Critical $1000–5000 (avg $1167). Top range $500–$5000. Avg bounty ~$250.

## Required fields (in order)
1. **Asset** (required) — pick the attack surface from the dropdown:
   - `*.tradeshift.com` — **Critical / Eligible for bounty** ← use for `api-sandbox.tradeshift.com`,
     `sandbox.tradeshift.com`, and any other in-scope subdomain. (This is what the cert/media draft used.)
   - `sandbox.tradeshift.com` — Critical / Eligible
   - `getgo-sandbox.tradeshift.com` — Critical / Eligible
   - `int-www.babelway.net` — Critical / Eligible
   - Also listed but per program rules OUT despite wildcard: `api.tradeshift.com`, `go.tradeshift.com`.
     Do NOT select these for in-scope hosts; use `*.tradeshift.com`. (See [[tradeshift-target]].)
   - Others present: `way.tradeshift.com`, `www.babelway.net`, `https://portal.demo.ibxplatform.com/portal/`.
2. **Report Template** (optional) — saved templates; skip unless one is set up.
3. **Weakness** (required) — CWE dropdown. Common picks for this program:
   - `Insecure Direct Object Reference (IDOR) (CWE-639)` ← cross-tenant object access
   - `Improper Access Control - Generic (CWE-284)`
   - `Information Disclosure (CWE-200)` / `Privacy Violation (CWE-359)`
   - Full CWE + LLM/ASI taxonomy available (ASI01-ASI10, LLM01-LLM10 present).
4. **Severity** (optional but recommended) — CVSS 3.0 calculator (AV/AC/PR/UI/S/C/I/A). Or "Submit without severity".
5. **Proof of Concept** (the graded part):
   - **Title\*** — max 150 chars. Formula: *[vuln type] + impacted asset/endpoint + impact*.
   - **Description\*** — Markdown. "What is the vulnerability? In clear steps, how do you reproduce it?"
   - **Impact\*** — Markdown. "What security impact can an attacker achieve?"
   - Attachments (max 250MB/file) + optional demo recording.
6. **Create Draft** / **Submit Report** buttons. Editing after submission is NOT possible — review first.

## Body format the program expects (from a real accepted-style draft)
Use these Markdown sub-headers inside **Description**:

```
Summary:
<1–3 sentences: the vuln + why it's a boundary violation>

Steps To Reproduce:
Setup: <accounts/roles, e.g. two reporter-owned sandbox accounts>.
  Attacker: <company, UUID, role — note "free account">.
  Victim: <company, UUID; note PublicProfile:false / Restricted:true / DISCONNECTED>.
1. <log in / capture Bearer token>
2. <exact curl with method, full URL, headers>
   → <exact response: HTTP status + the leaked data>
3. <chain step / open in fresh incognito to prove no-auth>
Evidence the leak is NOT by-design:
  <show the same backend hides a sibling field (e.g. AddressLines:[]) for the disconnected
   requester → the visibility mechanism exists, just isn't applied to this endpoint>

Supporting Material/References:
<buckets, ACLs, missing X-Amz-Signature/expiry, screenshots list>
Suggested fix: <1–2 concrete sentences>
```

And inside **Impact**:
```
Summary:
<what any free-tier attacker walks away with, scale (every tenant), persistence, and the
 opted-out-victim angle (PublicProfile:false). Quantify.>
```

## Tone / bar tips for THIS program (they dedup hard — see [[tradeshift-finding-bola-account]])
- Cross-tenant access-control on the external API is heavily reported. Pre-empt dedup: cite the
  nearest known report and state the distinct primitive (e.g. bulk enumeration by accountId vs
  1-by-1 email lookup; permanent unauth S3 URL vs authenticated read).
- Always prove impact beyond "200 OK": show the leaked bytes / permanent URL opening with no session.
- Use the "sibling field is correctly hidden" trick to prove missing-check (not intended behavior).
- Two reporter-owned accounts, disconnected, one marked PublicProfile:false = the strongest setup.
```
```
