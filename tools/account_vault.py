#!/usr/bin/env python3
"""
Account Vault — per-target test-identity store for IDOR/BOLA & auth hunting.

WHY: IDOR/BOLA needs several identities you control, at different privilege
levels and tenants, and you must be able to RE-LOGIN / refresh a token / mint a
fresh cookie for any of them on demand. Scattering creds across memory notes
loses them and mixes prose with structured data. This vault keeps, per target,
each account's login + role + groups + company + identity ids + canary + the
LIVE session (bearer/cookies with a TTL) + a refresh recipe.

SECURITY — the vault lives OUTSIDE the git repo, in Claude's project memory dir,
so it is NEVER pushed to GitHub:
    ~/.claude/projects/<project-slug>/memory/accounts/<target>.json   (chmod 0600)
Override with  BBHUNT_ACCOUNTS_DIR=/some/dir .  This tool (code, no secrets)
lives in the repo; the JSON vaults it manages do not.

STANDARD ROLE MODEL (at least 3 accounts; extend freely):
    A-admin    full-access admin / Owner in Company A        (baseline "sees all")
    B-admin    admin in a DIFFERENT company B                (cross-tenant A<->B pair)
    A-lowpriv  very restricted user in Company A             (vertical privesc / BFLA)
    A-<role>   any other specific role in Company A          (per-role authz tests)

COMMANDS
  account_vault.py template <target>                 scaffold a vault with the 3 base roles
  account_vault.py list     <target>                 table: label/role/company + session freshness
  account_vault.py get      <target> <label> [--field a.b.c]   print account (or one field, e.g. session.bearer)
  account_vault.py set-session <target> <label> [--bearer STR] [--cookie k=v ...] [--header k=v ...] [--ttl N]
                                                     write a fresh session (obtained_at=now)
  account_vault.py stale    <target> [<label>]       list stale sessions; exit 3 if the named one is stale
  account_vault.py set-field <target> <label> <path> <value>   set any metadata (password, canary, chrome_profile, company.tenantId ...)
  account_vault.py upsert   <target> --label L [--role R] [--company NAME] [--username U] [--password P] [...]

Claude's loop: `get-session`/`stale` -> if stale, run the account's refresh recipe
(hit /accesstoken, re-login, or read from the Chrome profile) -> `set-session` to store it.
See command /hunt-idor-caido and skill web2-vuln-classes (IDOR).
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def accounts_dir():
    env = os.environ.get("BBHUNT_ACCOUNTS_DIR")
    if env:
        return os.path.expanduser(env)
    # Derive Claude's project memory dir from the repo path (slug = abs path, / -> -).
    slug = ROOT.replace("/", "-")
    return os.path.expanduser(f"~/.claude/projects/{slug}/memory/accounts")


def vault_path(target):
    return os.path.join(accounts_dir(), f"{target.lower()}.json")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(target):
    p = vault_path(target)
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def save(target, data):
    d = accounts_dir()
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    data["updated"] = now_iso()
    p = vault_path(target)
    with open(p, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return p


def find(data, label):
    for a in data.get("accounts", []):
        if a.get("label") == label:
            return a
    return None


def blank_account(label, role, company, access):
    return {
        "label": label,
        "role": role,
        "access": access,
        "company": {"name": company, "id": "", "tenantId": ""},
        "groups": [],
        "username": "",
        "password": "",
        "identity": {},            # actorId / userId / tenantId / whatever the API keys on
        "canary": "",              # the ZZCAN-... marker seeded into this account
        "chrome_profile": "",      # which Chrome profile logs this account in
        "session": {"bearer": "", "cookies": {}, "headers": {},
                    "obtained_at": "", "ttl_seconds": 300},
        "refresh": {"method": "", "how": "", "login_url": ""},
        "notes": "",
    }


def session_fresh(acc):
    s = acc.get("session", {})
    ts = s.get("obtained_at")
    ttl = int(s.get("ttl_seconds") or 0)
    if not ts or ttl <= 0:
        return None  # unknown
    try:
        got = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    age = (datetime.now(timezone.utc) - got).total_seconds()
    return age < (ttl - 10)  # 10s skew


def fresh_label(acc):
    f = session_fresh(acc)
    has = bool(acc.get("session", {}).get("bearer") or acc.get("session", {}).get("cookies"))
    if not has:
        return "no-session"
    if f is None:
        return "unknown-ttl"
    return "FRESH" if f else "STALE"


# ----------------------------------------------------------------------------- commands

def cmd_template(args):
    if load(args.target) and not args.force:
        print(f"vault already exists: {vault_path(args.target)} (use --force to overwrite)", file=sys.stderr)
        return 1
    data = {
        "target": args.target.lower(),
        "scope": args.scope or "",
        "accounts": [
            blank_account("A-admin", "Owner / full-access admin", "Company A", "full"),
            blank_account("B-admin", "admin (different company)", "Company B", "full"),
            blank_account("A-lowpriv", "restricted user", "Company A", "restricted"),
        ],
    }
    p = save(args.target, data)
    print(f"scaffolded {p}")
    print("Fill in username/password/company ids/canary/chrome_profile, then use set-session.")
    return 0


def cmd_list(args):
    data = load(args.target)
    if not data:
        print(f"no vault for '{args.target}' at {vault_path(args.target)} (run: template)", file=sys.stderr)
        return 1
    print(f"# vault: {vault_path(args.target)}  (scope: {data.get('scope','-')}, updated {data.get('updated','-')})")
    print(f"{'LABEL':<12} {'ROLE':<30} {'COMPANY':<16} {'CANARY':<16} {'PROFILE':<16} SESSION")
    for a in data.get("accounts", []):
        comp = (a.get("company") or {}).get("name", "")
        print(f"{a.get('label',''):<12} {a.get('role',''):<30} {comp:<16} "
              f"{a.get('canary',''):<16} {a.get('chrome_profile',''):<16} {fresh_label(a)}")
    return 0


def dig(obj, path):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def cmd_get(args):
    data = load(args.target)
    if not data:
        print(f"no vault for '{args.target}'", file=sys.stderr)
        return 1
    acc = find(data, args.label)
    if not acc:
        print(f"no account '{args.label}' in {args.target}", file=sys.stderr)
        return 1
    if args.field:
        val = dig(acc, args.field)
        if val is None:
            print(f"field '{args.field}' not set", file=sys.stderr)
            return 1
        print(val if isinstance(val, str) else json.dumps(val))
        return 0
    print(json.dumps(acc, indent=2))
    return 0


def cmd_set_session(args):
    data = load(args.target)
    if not data:
        print(f"no vault for '{args.target}'", file=sys.stderr)
        return 1
    acc = find(data, args.label)
    if not acc:
        print(f"no account '{args.label}'", file=sys.stderr)
        return 1
    s = acc.setdefault("session", {})
    if args.bearer is not None:
        s["bearer"] = args.bearer
    if args.cookie:
        s.setdefault("cookies", {})
        for kv in args.cookie:
            k, _, v = kv.partition("=")
            s["cookies"][k] = v
    if args.header:
        s.setdefault("headers", {})
        for kv in args.header:
            k, _, v = kv.partition("=")
            s["headers"][k] = v
    if args.ttl is not None:
        s["ttl_seconds"] = args.ttl
    s["obtained_at"] = now_iso()
    save(args.target, data)
    print(f"session updated for {args.label} @ {s['obtained_at']} (ttl {s.get('ttl_seconds')}s)")
    return 0


def cmd_stale(args):
    data = load(args.target)
    if not data:
        print(f"no vault for '{args.target}'", file=sys.stderr)
        return 1
    if args.label:
        acc = find(data, args.label)
        if not acc:
            print(f"no account '{args.label}'", file=sys.stderr)
            return 1
        state = fresh_label(acc)
        print(f"{args.label}: {state}")
        return 3 if state != "FRESH" else 0
    any_stale = False
    for a in data.get("accounts", []):
        state = fresh_label(a)
        if state != "FRESH":
            any_stale = True
            print(f"{a.get('label')}: {state}")
    if not any_stale:
        print("all sessions FRESH")
    return 0


def cmd_set_field(args):
    data = load(args.target)
    if not data:
        print(f"no vault for '{args.target}'", file=sys.stderr)
        return 1
    acc = find(data, args.label)
    if not acc:
        print(f"no account '{args.label}'", file=sys.stderr)
        return 1
    parts = args.path.split(".")
    cur = acc
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    # try to parse JSON (lists/numbers/bools), else keep string
    try:
        val = json.loads(args.value)
    except (json.JSONDecodeError, ValueError):
        val = args.value
    cur[parts[-1]] = val
    save(args.target, data)
    print(f"{args.label}.{args.path} = {val!r}")
    return 0


def cmd_upsert(args):
    data = load(args.target) or {"target": args.target.lower(), "scope": "", "accounts": []}
    acc = find(data, args.label)
    if not acc:
        acc = blank_account(args.label, args.role or "", args.company or "", args.access or "")
        data.setdefault("accounts", []).append(acc)
    for attr in ("role", "username", "password", "access", "canary", "chrome_profile"):
        v = getattr(args, attr)
        if v is not None:
            acc[attr] = v
    if args.company is not None:
        acc.setdefault("company", {})["name"] = args.company
    save(args.target, data)
    print(f"upserted {args.label} in {args.target}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Per-target test-identity vault (IDOR/BOLA).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("template"); t.add_argument("target"); t.add_argument("--scope"); t.add_argument("--force", action="store_true"); t.set_defaults(fn=cmd_template)
    l = sub.add_parser("list"); l.add_argument("target"); l.set_defaults(fn=cmd_list)
    g = sub.add_parser("get"); g.add_argument("target"); g.add_argument("label"); g.add_argument("--field"); g.set_defaults(fn=cmd_get)
    ss = sub.add_parser("set-session"); ss.add_argument("target"); ss.add_argument("label")
    ss.add_argument("--bearer"); ss.add_argument("--cookie", action="append"); ss.add_argument("--header", action="append"); ss.add_argument("--ttl", type=int); ss.set_defaults(fn=cmd_set_session)
    st = sub.add_parser("stale"); st.add_argument("target"); st.add_argument("label", nargs="?"); st.set_defaults(fn=cmd_stale)
    sf = sub.add_parser("set-field"); sf.add_argument("target"); sf.add_argument("label"); sf.add_argument("path"); sf.add_argument("value"); sf.set_defaults(fn=cmd_set_field)
    u = sub.add_parser("upsert"); u.add_argument("target"); u.add_argument("--label", required=True)
    for a in ("role", "company", "username", "password", "access", "canary", "chrome_profile"):
        u.add_argument(f"--{a}")
    u.set_defaults(fn=cmd_upsert)

    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
