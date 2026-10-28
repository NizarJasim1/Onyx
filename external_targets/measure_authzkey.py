#!/usr/bin/env python3
"""measure_authzkey.py — MEASURED proof for the AUTHZ-KEY DIFFERENTIAL (Layer 4-X part 2),
offline against a labeled capture. No network — this tests the discriminator in isolation.

"العائق هو التمييز لا التوليد." The differential compares an ALLOWED vs a DENIED request on
the SAME door and returns the minimal request-feature delta = the authorization key.

LABELED CAPTURE (on GET /api/export):
  * multiple DENIED  : header X-Internal absent            -> 403
  * multiple ALLOWED : header X-Internal: 1                 -> 200   (real key, consistent)
  * every request also carries a NOISE header X-Request-Id with a DIFFERENT value each time
    — a real capture always has these. The differential must REJECT it (varies within the
    allowed set) and keep only X-Internal.
  * decoy door /api/orders/{id}: allowed for owner, denied for non-owner, differ ONLY by
    id / auth token — must yield NO key (identity is the baseline axis).

ASSERTIONS:
  1. /api/export -> learns {header:x-internal: '1'} ONLY (noise X-Request-Id rejected).
  2. /api/orders/{id} -> NO key learned (identity-only delta).

PASS = real key learned, noise rejected, decoy produces no key.
Run:  python3 external_targets/measure_authzkey.py   (exit 0 = pass)
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import alt_paths_deep as DEEP

def _rec(method, path, status, principal, headers=None, query="", body=None):
    url = f"http://t{path}" + (f"?{query}" if query else "")
    hlist = [{"name": "Authorization", "value": f"Bearer tok{principal}"}]
    for k, v in (headers or {}).items():
        hlist.append({"name": k, "value": v})
    import sitemodel as SM
    from urllib.parse import urlparse, parse_qs
    return {"method": method, "path": path, "tmpl": SM.templatize_path(path),
            "status": status, "principal": principal, "url": url,
            "query": parse_qs(query), "req_headers": hlist, "req_body": body,
            "resp_body": {}, "key": f"{method} {SM.templatize_path(path)}"}

def main():
    records = [
        # --- /api/export: X-Internal is the real key; X-Request-Id is per-request noise ---
        _rec("GET", "/api/export", 403, "A", headers={"X-Request-Id": "r-1"}),
        _rec("GET", "/api/export", 403, "B", headers={"X-Request-Id": "r-2"}),
        _rec("GET", "/api/export", 200, "A", headers={"X-Internal": "1", "X-Request-Id": "r-3"}),
        _rec("GET", "/api/export", 200, "C", headers={"X-Internal": "1", "X-Request-Id": "r-4"}),
        # --- decoy door: allowed vs denied differ only by id/token (identity) ---
        _rec("GET", "/api/orders/2002", 200, "B"),
        _rec("GET", "/api/orders/2002", 200, "B"),
        _rec("GET", "/api/orders/2002", 403, "A"),
    ]
    keys = DEEP.authz_key_differential(records)
    print("  learned authz-keys:")
    for door, k in keys.items():
        print(f"    {door}: {k}")

    export = keys.get("GET /api/export", {})
    decoy = keys.get("GET /api/orders/{id}", {})
    got_real = export.get("header:x-internal") == "1"
    no_noise = "header:x-request-id" not in export
    no_decoy = not decoy
    print()
    print(f"  real key learned (X-Internal unlocks export) : {got_real}")
    print(f"  noise header rejected (X-Request-Id varies)  : {no_noise}")
    print(f"  decoy produces NO key (identity-only delta)  : {no_decoy}")
    if got_real and no_noise and no_decoy:
        print("\nMEASURE-AUTHZKEY: PASS — the differential isolates the server's real authorization "
              "key from an allowed/denied pair, and does not invent a key when the only difference "
              "is identity. Discriminator works; feeds pivot targeting.")
        return 0
    print("\nMEASURE-AUTHZKEY: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
