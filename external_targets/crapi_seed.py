#!/usr/bin/env python3
"""
crapi_seed.py — RICH seeder for a LOCAL, AUTHORIZED crAPI.

Populates crAPI with everything ONYX's full arsenal needs to exercise the WHOLE
in-scope surface (not just vehicle-location BOLA). Per principal it provisions:
  * account (signup + login)      -> captures the JWT (for onyx_recon / conductor)
  * a vehicle (via MailHog)       -> captures VIN + uuid
  * several shop orders           -> order ids   (order-BOLA, mass-assign/refund)
  * a mechanic service request    -> report id   (mechanic-report BOLA)
  * a community post              -> post id      (EDE / feed leakage)
  * profile video id (dashboard)  -> video id     (video field-exposure / mass-assign)
  * coupon liveness check

Output:
  * <out>/seed.json   — accounts (with tokens), per-principal ids, coupon, principals
The three ONYX engines read this file; nothing needs to be copied by hand.

Reuses hunt_crapi's proven CrapiClient. Authorized, loopback-only testing.
"""
from __future__ import annotations
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
from hunt_crapi import CrapiClient

P_MECHLIST = "/workshop/api/mechanic/"
P_CONTACT  = "/workshop/api/merchant/contact_mechanic"
P_MECHRPT  = "/workshop/api/mechanic/mechanic_report"
P_DASH     = "/identity/api/v2/user/dashboard"
P_POSTS    = "/community/api/v2/community/posts"
P_VALCPN   = "/community/api/v2/coupon/validate-coupon"


def _first_int(text):
    for pat in (r"report_id=(\d+)", r'"report_id"\s*:\s*"?(\d+)', r'"id"\s*:\s*(\d+)'):
        m = re.search(pat, text or "")
        if m:
            return int(m.group(1))
    return None


def _collect(obj, keys):
    out, seen = [], set()
    keys = {k.lower() for k in keys}
    def walk(n):
        if isinstance(n, dict):
            for k, v in n.items():
                if k.lower() in keys and isinstance(v, (str, int)) and str(v) not in seen:
                    seen.add(str(v)); out.append(str(v))
                walk(v)
        elif isinstance(n, list):
            for x in n: walk(x)
    walk(obj); return out


def mechanic_code(cli, token):
    try:
        r = cli._req("GET", P_MECHLIST, token=token)
        codes = _collect(r.json(), {"mechanic_code", "mechaniccode"}) if r.status_code < 400 else []
    except Exception:
        codes = []
    for c in codes + ["TRAC_JHM", "TRAC_MECH2"]:
        if c: return c
    return "TRAC_JHM"


def file_report(cli, base, token, vin, code):
    body = {"mechanic_code": code, "problem_details": "ONYX seed: routine diagnostic",
            "vin": vin, "mechanic_api": base.rstrip("/") + "/workshop/api/mechanic/receive_report",
            "number_of_repeats": 1, "repeat_request_if_failed": False}
    try:
        r = cli._req("POST", P_CONTACT, token=token, json=body)
        return _first_int(r.text)
    except Exception:
        return None


def owned_report_ids(cli, token, hi=60):
    found = []
    for rid in range(1, hi + 1):
        try:
            r = cli._req("GET", f"{P_MECHRPT}?report_id={rid}", token=token)
            if r.status_code < 400:
                found.append(str(rid))
        except Exception:
            continue
    return found


def make_post(cli, token, pid):
    try:
        r = cli._req("POST", P_POSTS, token=token,
                     json={"title": f"ONYX {pid} note", "content": f"seed post by {pid}"})
        ids = _collect(r.json(), {"id", "post_id"}) if r.status_code < 400 else []
        return ids[0] if ids else None
    except Exception:
        return None


def coupon_live(cli, token, code):
    try:
        r = cli._req("POST", P_VALCPN, token=token, json={"coupon_code": code})
        return r.status_code < 400
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8888")
    ap.add_argument("--mailhog", default="http://localhost:8025")
    ap.add_argument("--principals", default="A,B,C", help="comma list, e.g. A,B,C")
    ap.add_argument("--domain", default="example.com")
    ap.add_argument("--password", default="Passw0rd!23")
    ap.add_argument("--orders-each", type=int, default=2)
    ap.add_argument("--coupon", default="TRAC075")
    ap.add_argument("--out", default="./crapi_out")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    verify = not (args.insecure or args.base_url.startswith("https"))
    cli = CrapiClient(args.base_url, verify=verify, timeout=25)
    pids = [p.strip() for p in args.principals.split(",") if p.strip()]

    seed = {"base_url": args.base_url, "principals": pids, "coupon": args.coupon,
            "accounts": {}, "ids": {}}

    for i, pid in enumerate(pids):
        email = f"onyx_seed_{pid.lower()}@{args.domain}"
        print(f"\n=== principal {pid} : {email} ===")
        cli.signup(f"ONYX {pid}", email, f"9{i:09d}", args.password)
        tok = cli.login(email, args.password)
        if not tok:
            sys.exit(f"[{pid}] login failed — is crAPI up at {args.base_url}?")
        seed["accounts"][pid] = {"email": email, "password": args.password, "token": tok, "vin": None}
        seed["ids"][pid] = {}
        print(f"[{pid}] login ok (token captured)")

        ok, detail = cli.claim_vehicle_via_mailhog(args.mailhog, tok, email)
        m = re.search(r"VIN\s+([A-Z0-9]{6,17})", detail or "")
        vin = m.group(1) if m else None
        seed["accounts"][pid]["vin"] = vin
        seed["ids"][pid]["vehicles"] = cli.vehicles(tok)
        print(f"[{pid}] vehicle: {'ok' if ok else 'no'} ({detail}) uuids={seed['ids'][pid]['vehicles'] or '-'}")

        prods = cli.products(tok); orders = []
        for k in range(args.orders_each):
            if not prods: break
            good, oid = cli.buy(tok, prods[k % len(prods)])
            if good and oid not in ("ok", None): orders.append(str(oid))
        seed["ids"][pid]["orders"] = orders or cli.orders(tok)
        print(f"[{pid}] orders={seed['ids'][pid]['orders'] or '-'}")

        rid = file_report(cli, args.base_url, tok, vin, mechanic_code(cli, tok)) if vin else None
        seed["ids"][pid]["reports"] = [str(rid)] if rid else []

        dash = cli._json(P_DASH, tok) if hasattr(cli, "_json") else None
        seed["ids"][pid]["videos"] = _collect(dash, {"video_id", "videoid"})
        post = make_post(cli, tok, pid)
        seed["ids"][pid]["posts"] = [post] if post else []
        print(f"[{pid}] report={rid or '(probe)'} videos={seed['ids'][pid]['videos'] or '-'} post={post or '-'}")

    # fallback: probe owned report ids where the contact response gave none
    for pid in pids:
        if not seed["ids"][pid]["reports"]:
            owned = owned_report_ids(cli, seed["accounts"][pid]["token"])
            if owned:
                seed["ids"][pid]["reports"] = [owned[0]]
                print(f"[{pid}] probed report id={owned[0]}")

    seed["coupon_live"] = coupon_live(cli, seed["accounts"][pids[0]]["token"], args.coupon)
    print(f"[*] coupon {args.coupon} live: {seed['coupon_live']}")

    with open(os.path.join(args.out, "seed.json"), "w", encoding="utf-8") as fh:
        json.dump(seed, fh, indent=2)
    # redact tokens in the console echo
    echo = json.loads(json.dumps(seed))
    for p in echo["accounts"]:
        echo["accounts"][p]["token"] = (echo["accounts"][p]["token"] or "")[:12] + "…"
    print("\n================ SEED COMPLETE ================")
    print(json.dumps(echo, indent=2))
    print(f"\nseed.json written to {os.path.join(args.out, 'seed.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
