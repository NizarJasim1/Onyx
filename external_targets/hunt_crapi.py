#!/usr/bin/env python3
"""
hunt_crapi.py — a COMPREHENSIVE ONYX/AuthPath sweep of a local, authorized OWASP crAPI,
end to end: create accounts, claim vehicles, discover everything, probe every crAPI
challenge that fits ONYX's model, and emit TWO reports —
    * crapi_report.md        — the confirmed vulnerabilities (submission-grade)
    * crapi_performance.md    — what the tool did, how well, and exactly what it covers

crAPI (https://github.com/OWASP/crAPI) is intentionally vulnerable and meant to be
tested. Run this ONLY against your own crAPI, or a target you are authorized to test.

What "comprehensive" means here
-------------------------------
ONYX is an AUTHORIZATION + BUSINESS-LOGIC engine that proves every finding with an
authenticated Δstate read-back. So this runner drives the crAPI challenges that live
in that model and HONESTLY reports the ones that do not (injection, brute-force, SSRF,
JWT crypto) so you can see the tool's true reach. The capability map is in the perf report.

Zero-friction connection
------------------------
Before anything runs, a preflight resolves the target and clears the usual blockers:
  * auto-corrects the URL — adds the scheme, tries http/https, and probes crAPI's
    common ports (8888/8080/8443/80/443) if you didn't give one;
  * auto-detects a self-signed cert and continues with --insecure on its own;
  * confirms the endpoint is crAPI and that MailHog is reachable (if used);
  * verifies each account's credential actually authenticates — so you never run a
    full sweep on a dead token.
It prints a green/red checklist and, if the target is unreachable, one clear fix list
instead of a stack trace. Run just the checks with --doctor (no scan).

    python3 external_targets/hunt_crapi.py --doctor --a-token … --b-token …   # validate only

Speed & convenience
-------------------
  * Realistic, varied accounts — real-looking names/emails/phones/passwords (on
    example.com so MailHog still receives mail), not templated bot data.
  * Resume — accounts and discovered ids are saved to <out>/state.json; the next run
    reuses them and skips signup + provisioning. Use --fresh to start clean.
  * --config file.json — keep base_url, mailhog, researcher, program, full, confirm in
    a file so the command stays short (CLI flags always override the file).
  * Parallel signup + optional polite --delay MIN,MAX jitter between requests.

    echo '{"base_url":"http://localhost:8888","mailhog":"http://localhost:8025",
           "researcher":"you","full":true,"confirm":true}' > crapi.json
    ./run.sh --config crapi.json          # first run provisions; re-runs resume instantly

Full auto (needs crAPI + MailHog on your machine):
    pip install requests
    python3 external_targets/hunt_crapi.py --full \
        --base-url http://localhost:8888 --mailhog http://localhost:8025 \
        --researcher your-handle --out ./crapi_out --confirm

Bring-your-own accounts (no signup):
    python3 external_targets/hunt_crapi.py \
        --base-url http://localhost:8888 \
        --a-email a@x.com --a-pass 'Passw0rd!' --b-email b@x.com --b-pass 'Passw0rd!' \
        --out ./crapi_out
"""
from __future__ import annotations
import argparse, json, os, re, statistics, sys, time, zipfile, random, string, contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

# ---- crAPI endpoints (confirmed against the OWASP/crAPI OpenAPI spec) -------- #
P_SIGNUP   = "/identity/api/auth/signup"
P_LOGIN    = "/identity/api/auth/login"
P_ADDVEH   = "/identity/api/v2/vehicle/add_vehicle"
P_REGVEH   = "/identity/api/v2/vehicle/register_vehicle"   # newer crAPI: emails a fresh VIN+pincode
P_VEHICLES = "/identity/api/v2/vehicle/vehicles"
P_DASH     = "/identity/api/v2/user/dashboard"
P_RECENT   = "/community/api/v2/community/posts/recent"
P_ORDERS   = "/workshop/api/shop/orders"
P_PRODUCTS = "/workshop/api/shop/products"
P_APPLYCPN = "/workshop/api/shop/apply_coupon"
P_POSTS    = "/community/api/v2/community/posts"          # POST to create a community post
P_VIDEOS   = "/identity/api/v2/user/videos"              # profile video (id from dashboard)
# templated probe paths (the {id} slot is what ONYX substitutes cross-principal)
T_VEH_LOC  = "/identity/api/v2/vehicle/{id}/location"
T_ORDER    = "/workshop/api/shop/orders/{id}"
T_MECHRPT  = "/workshop/api/mechanic/mechanic_report?report_id={id}"
T_POST     = "/community/api/v2/community/posts/{id}"
T_VIDEO    = "/identity/api/v2/user/videos/{id}"


def _requests():
    try:
        import requests
        return requests
    except ImportError:
        sys.exit("This runner needs `requests`.  pip install requests")


# --------------------------------------------------------------------------- #
# crAPI client — every HTTP call is counted + timed for the performance report #
# --------------------------------------------------------------------------- #
class CrapiClient:
    def __init__(self, base_url, verify=True, timeout=15, delay=(0.0, 0.0)):
        self.base = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.requests = _requests()
        self.n = 0
        self.latencies = []
        self.log = []
        self.delay = delay          # (min,max) seconds of polite jitter between requests
        self._lock = __import__("threading").Lock()

    def _req(self, method, path, token=None, **kw):
        if self.delay[1] > 0:
            time.sleep(random.uniform(self.delay[0], self.delay[1]))
        url = self.base + path
        headers = kw.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        t0 = time.perf_counter()
        try:
            r = self.requests.request(method, url, headers=headers, timeout=self.timeout,
                                      verify=self.verify, **kw)
            ms = int((time.perf_counter() - t0) * 1000)
            with self._lock:
                self.n += 1; self.latencies.append(ms); self.log.append((method, path, r.status_code, ms))
            return r
        except Exception as e:
            ms = int((time.perf_counter() - t0) * 1000)
            with self._lock:
                self.n += 1; self.latencies.append(ms); self.log.append((method, path, None, ms))
            raise

    # ---- auth ----
    def signup(self, name, email, number, password):
        try:
            r = self._req("POST", P_SIGNUP, json={"name": name, "email": email,
                          "number": number, "password": password})
            return r.status_code < 400
        except Exception:
            return False

    def login(self, email, password):
        r = self._req("POST", P_LOGIN, json={"email": email, "password": password})
        if r.status_code >= 400:
            return None
        try:
            d = r.json()
        except ValueError:
            return None
        return d.get("token") or d.get("access_token") or d.get("accessToken")

    # ---- vehicle claim via MailHog ----
    def register_vehicle(self, token):
        """Newer crAPI: ask the server to create a vehicle for me and email its VIN+pincode."""
        try:
            r = self._req("POST", P_REGVEH, token=token, json={})
            return r.status_code < 400
        except Exception:
            return False

    def claim_vehicle_via_mailhog(self, mailhog_url, token, email):
        """Register a vehicle, read the VIN+pincode crAPI mailed, and add it — fully
        automatic and format-independent: the email is decoded (quoted-printable / base64
        / HTML) via the stdlib email parser, ALL plausible VIN and pincode candidates are
        extracted, and each pair is tried against add_vehicle until one is accepted. No
        dependence on a specific label or template."""
        import email as _email
        import quopri as _quopri
        self.register_vehicle(token)   # trigger a fresh vehicle email
        try:
            r = self.requests.get(mailhog_url.rstrip("/") + "/api/v2/messages",
                                  timeout=self.timeout, verify=self.verify)
            msgs = r.json()
        except Exception as e:
            return False, f"mailhog unreachable ({type(e).__name__})"
        items = msgs.get("items", msgs if isinstance(msgs, list) else [])

        def plain_text(m):
            # Prefer the full raw RFC822 (handles multipart + transfer-encoding correctly).
            raw = ((m.get("Raw") or {}).get("Data")) or ""
            text_parts = []
            if raw:
                try:
                    msg = _email.message_from_string(raw)
                    for part in (msg.walk() if msg.is_multipart() else [msg]):
                        if part.get_content_maintype() == "multipart":
                            continue
                        payload = part.get_payload(decode=True)
                        if payload is None:
                            continue
                        try:
                            text_parts.append(payload.decode(part.get_content_charset() or "utf-8",
                                                             "replace"))
                        except Exception:
                            text_parts.append(payload.decode("utf-8", "replace"))
                except Exception:
                    pass
            if not text_parts:
                body = (m.get("Content") or {}).get("Body", "") or ""
                try:
                    body = _quopri.decodestring(body.encode("utf-8", "replace")).decode("utf-8", "replace")
                except Exception:
                    pass
                text_parts.append(body)
            blob = " ".join(text_parts)
            blob = re.sub(r"<[^>]+>", " ", blob)                 # strip HTML tags
            blob = blob.replace("&nbsp;", " ").replace("=\r\n", "").replace("=\n", "")
            return re.sub(r"\s+", " ", blob)

        def recip(m):
            return json.dumps((m.get("Content") or {}).get("Headers", {}).get("To", []))

        def candidates(text):
            # VINs: 17-char alnum first, then 11-16 as fallback; prefer tokens near "vin".
            vins, seen = [], set()
            near = re.findall(r"vin[^A-Za-z0-9]{0,8}([A-Z0-9]{11,17})", text, re.I)
            allv = re.findall(r"\b([A-Z0-9]{17})\b", text) + re.findall(r"\b([A-Z0-9]{11,16})\b", text)
            for v in near + allv:
                v = v.upper()
                if v not in seen and not v.isdigit():        # a pure-digit run isn't a VIN
                    seen.add(v); vins.append(v)
            # pincodes: prefer numbers near "pin"/"code"; then any 3–6 digit run.
            pins, pseen = [], set()
            pnear = re.findall(r"(?:pin|code|pincode)[^0-9]{0,8}(\d{3,6})", text, re.I)
            pall = re.findall(r"\b(\d{3,6})\b", text)
            for p in pnear + pall:
                if p not in pseen:
                    pseen.add(p); pins.append(p)
            return vins[:6], pins[:6]

        ordered = list(reversed(items))
        pools = [[m for m in ordered if email and (email in recip(m) or email in plain_text(m))],
                 ordered]
        tried = 0
        for pool in pools:
            for m in pool:
                vins, pins = candidates(plain_text(m))
                for v in vins:
                    for p in pins:
                        if tried >= 30:
                            return False, "VIN/pincode candidates all rejected by add_vehicle"
                        tried += 1
                        try:
                            r = self._req("POST", P_ADDVEH, token=token,
                                          json={"vin": v, "pincode": int(p)})
                            if r.status_code < 400:
                                return True, f"added VIN {v}"
                        except Exception:
                            continue
        return False, ("no VIN/pincode in MailHog — is register_vehicle emailing? "
                       "(MailHog at " + mailhog_url + ")")

    # ---- discovery ----
    def _json(self, path, token):
        try:
            r = self._req("GET", path, token=token)
            return r.json() if r.status_code < 400 else None
        except Exception:
            return None

    def vehicles(self, token):
        return _collect(self._json(P_VEHICLES, token), {"uuid"})

    def orders(self, token):
        d = self._json(P_ORDERS, token)
        scope = d.get("orders") if isinstance(d, dict) else d
        return _collect(scope, {"id", "order_id"})

    def dashboard(self, token):
        return self._json(P_DASH, token)

    def other_vehicle_uuids(self, token):
        """Harvest OTHER users' vehicle UUIDs leaked by community/posts/recent."""
        return _collect(self._json(P_RECENT, token), {"vehicleid", "vehicle_id", "uuid"})

    def products(self, token):
        d = self._json(P_PRODUCTS, token)
        return _collect(d, {"id", "product_id"})

    def buy(self, token, product_id):
        """Buy a product; return (ok, order_id_or_detail)."""
        try:
            r = self._req("POST", P_ORDERS, token=token,
                          json={"product_id": product_id, "quantity": 1})
            if r.status_code >= 400:
                return False, f"HTTP {r.status_code}"
            try:
                oid = _collect(r.json(), {"id", "order_id"})
                return True, (oid[0] if oid else "ok")
            except ValueError:
                return True, "ok"
        except Exception as e:
            return False, type(e).__name__



def _collect(obj, keys):
    out, seen = [], set()
    def walk(n):
        if isinstance(n, dict):
            for k, v in n.items():
                if k in keys and isinstance(v, (str, int)) and str(v) not in seen:
                    seen.add(str(v)); out.append(str(v))
                else:
                    walk(v)
        elif isinstance(n, list):
            for x in n:
                walk(x)
    walk(obj)
    return out


# --------------------------------------------------------------------------- #
# Count + time every HTTP request the ENGINE makes during the scan window      #
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def count_engine_http():
    stats = {"n": 0, "latencies": []}
    try:
        import requests
        Session = requests.sessions.Session
        orig = Session.request
        def wrapped(self, method, url, *a, **k):
            t0 = time.perf_counter()
            try:
                return orig(self, method, url, *a, **k)
            finally:
                stats["n"] += 1
                stats["latencies"].append(int((time.perf_counter() - t0) * 1000))
        Session.request = wrapped
        try:
            yield stats
        finally:
            Session.request = orig
    except ImportError:
        yield stats


# --------------------------------------------------------------------------- #
# Capability map: crAPI challenge -> OWASP API risk -> ONYX coverage           #
# --------------------------------------------------------------------------- #
CAPABILITY_MAP = [
    # (challenge, owasp, onyx_effect, in_model, note)
    ("Access another user's vehicle location", "API1 BOLA", "OBJECT_ACCESS", True,
     "cross-principal read, Δstate-confirmed"),
    ("Read another user's shop order", "API1 BOLA", "OBJECT_ACCESS", True,
     "cross-principal read, Δstate-confirmed"),
    ("Access other users' mechanic reports", "API1 BOLA", "OBJECT_ACCESS", True,
     "needs report ids (auto-probed if provided)"),
    ("Get an item for free / bigger refund", "API6 business-logic", "OWNERSHIP/STATE_GATE", True,
     "order quantity+status tamper (needs --confirm)"),
    ("Apply a coupon multiple times", "API6 business-logic", "COUPON", True,
     "balance Δstate on re-apply (needs --confirm)"),
    ("Change another user's order (BFLA)", "API5 BFLA", "AUTHORITY/OWNERSHIP", True,
     "cross-principal write, Δstate-confirmed"),
    ("Increase balance via negative-price product", "API6 business-logic", "PRICE", False,
     "needs product-create flow; not auto-driven here"),
    ("Mass assignment (role / is_admin)", "API3 BOPLA", "(bva side-channel)", False,
     "detected on a separate channel, not merged into findings"),
    ("Coupon NoSQL injection ({\"$gt\":\"\"})", "API8 / injection", "—", False,
     "injection, not an authorization Δstate — use a fuzzer"),
    ("OTP brute-force / missing rate-limit", "API4 resource-consumption", "—", False,
     "rate/throughput bug, outside ONYX's model"),
    ("SSRF via contact_mechanic", "API7 SSRF", "—", False,
     "server-side request forgery, outside ONYX's model"),
    ("JWT alg=none / weak secret", "API2 broken-auth", "—", False,
     "token crypto, outside object-level-authz model"),
]


def build_plan(tokens, ids, *, confirm):
    """Assemble the ONYX engagement config (same shape the dashboard POSTs to /api/scan)."""
    principals = {pid: {"value": t, "type": "bearer"} for pid, t in tokens.items()}
    endpoints, writable = [], []

    veh = {p: ids[p]["vehicles"] for p in tokens if ids[p]["vehicles"]}
    if len(veh) >= 2:
        endpoints.append({"method": "GET", "path": T_VEH_LOC, "effect": "object-access", "ids": veh})

    ordr = {p: ids[p]["orders"] for p in tokens if ids[p]["orders"]}
    if len(ordr) >= 2:
        endpoints.append({"method": "GET", "path": T_ORDER, "effect": "object-access", "ids": ordr})

    rpt = {p: ids[p]["reports"] for p in tokens if ids[p].get("reports")}
    if len(rpt) >= 2:
        endpoints.append({"method": "GET", "path": T_MECHRPT, "effect": "object-access", "ids": rpt})

    if confirm:
        a_orders = ids["A"]["orders"]
        if a_orders:
            oid = a_orders[0]; writable.append(oid)
            endpoints.append({"method": "PUT", "path": T_ORDER, "effect": "ownership",
                              "ids": {"A": [oid]},
                              "body": json.dumps({"quantity": 150, "status": "returned"})})
        # coupon re-apply (self-abuse, COUPON effect); harmless echo on most builds
        cpn = ids["A"].get("coupon")
        if cpn:
            endpoints.append({"method": "POST", "path": P_APPLYCPN, "effect": "coupon",
                              "ids": {"A": ["self"]},
                              "body": json.dumps({"coupon_code": cpn, "amount": 75})})

    return {"base_url": None, "authorized": True, "dry_run": not confirm,
            "principals": principals, "endpoints": endpoints,
            "test_resources": writable, "engagement_id": "crapi-hunt"}


def _lat(xs):
    if not xs:
        return {"n": 0, "median": 0, "p95": 0, "max": 0}
    s = sorted(xs)
    return {"n": len(xs), "median": int(statistics.median(s)),
            "p95": s[min(len(s) - 1, int(len(s) * 0.95))], "max": s[-1]}


def write_vuln_report(engine, out_dir, *, program, researcher):
    from bounty_report import submission_pack
    os.makedirs(out_dir, exist_ok=True)
    pack = submission_pack(engine.findings, program=program, researcher=researcher)
    pdir = os.path.join(out_dir, "submission_pack"); os.makedirs(pdir, exist_ok=True)
    for name, md in pack.items():
        open(os.path.join(pdir, name), "w", encoding="utf-8").write(md)
    zpath = os.path.join(out_dir, "crapi_submission_pack.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for name, md in pack.items():
            z.writestr(name, md)
    reports = sorted(k for k in pack if k != "INDEX.md")
    combined = [pack.get("INDEX.md", "# ONYX — crAPI report")] + \
               ["\n\n---\n\n" + pack[k] for k in reports]
    cpath = os.path.join(out_dir, "crapi_report.md")
    open(cpath, "w", encoding="utf-8").write("".join(combined))
    return cpath, pdir, zpath


def write_perf_report(out_dir, *, meta, setup, plan_eps, scan, snap, engine_http):
    os.makedirs(out_dir, exist_ok=True)
    L = []
    A = L.append
    A("# ONYX — crAPI capability & performance report\n")
    A(f"**Target:** {meta['base_url']}  ")
    A(f"**Program:** {meta['program']}  ")
    A(f"**Researcher:** {meta['researcher'] or '—'}  ")
    A(f"**When:** {meta['when']}  ")
    A(f"**Mode:** {'CONFIRM (writes on your own ids)' if meta['confirm'] else 'dry-run (read-only)'}"
      f"{' · signup' if meta['signup'] else ''}{' · mailhog-claim' if meta['mailhog'] else ''}\n")

    A("## 1. Accounts & setup\n")
    A("| principal | source | token | vehicles | orders | reports |")
    A("|---|---|---|---|---|---|")
    for pid in ("A", "B"):
        s = setup[pid]
        A(f"| {pid} | {s['source']} | {'yes' if s['token'] else 'NO'} | "
          f"{len(s['vehicles'])} | {len(s['orders'])} | {len(s.get('reports', []))} |")
    A("")
    st = _lat(setup["_latencies"])
    A(f"Setup + discovery HTTP requests: **{setup['_http']}** "
      f"(median {st['median']} ms, p95 {st['p95']} ms).\n")

    A("## 2. Attack surface probed\n")
    if plan_eps:
        A("| method | path | effect |")
        A("|---|---|---|")
        for ep in plan_eps:
            A(f"| {ep['method']} | `{ep['path']}` | {ep.get('effect','auto')} |")
    else:
        A("_No cross-principal endpoints could be assembled — see setup coverage above._")
    A("")

    A("## 3. Scan performance\n")
    c = snap["counts"]
    eh = _lat(engine_http["latencies"])
    A("| metric | value |")
    A("|---|---|")
    A(f"| wall-clock | {scan['secs']:.2f} s |")
    A(f"| HTTP requests (engine) | {engine_http['n']} |")
    A(f"| request latency median / p95 / max | {eh['median']} / {eh['p95']} / {eh['max']} ms |")
    A(f"| probes analyzed | {c.get('analyzed',0)} |")
    A(f"| **confirmed findings** | **{c.get('findings',0)}** |")
    A(f"| candidates dropped (unconfirmed → discarded) | {c.get('candidates_dropped',0)} |")
    A(f"| clean (no effect) | {c.get('clean',0)} |")
    A(f"| halted (scope / ROE) | {c.get('halted',0)} |")
    A(f"| leads (needs manual follow-up) | {c.get('leads',0)} |")
    A("")
    sev = c.get("severity", {})
    A(f"Severity of confirmed findings — "
      f"Critical {sev.get('Critical',0)}, High {sev.get('High',0)}, "
      f"Medium {sev.get('Medium',0)}, Low {sev.get('Low',0)}.\n")

    # per-effect + drop reasons from traces
    eff = {}
    for f in snap["findings"]:
        eff[f["effect"]] = eff.get(f["effect"], 0) + 1
    if eff:
        A("**Confirmed by class:** " + ", ".join(f"{k} × {v}" for k, v in sorted(eff.items())) + "\n")
    drops = {}
    for tr in snap.get("traces", []):
        if tr.get("outcome") != "finding":
            reason = tr.get("outcome", "?")
            if reason in ("dropped", "clean"):
                last = [s for s in tr.get("stages", []) if s.get("status") in ("drop", "clean", "abstain")]
                if last:
                    reason = f"{reason}:{last[-1].get('stage','')}"
            drops[reason] = drops.get(reason, 0) + 1
    if drops:
        A("**Why non-findings were not reported** (the zero-false-positive discipline): "
          + ", ".join(f"{k} × {v}" for k, v in sorted(drops.items())) + ".\n")

    A("## 4. Confirmed findings\n")
    if snap["findings"]:
        A("| severity | effect | actor ▸ target | endpoint |")
        A("|---|---|---|---|")
        for f in snap["findings"]:
            A(f"| {f['severity']} | {f['effect']} | {f['actor']} ▸ {f['target']} | `{f['endpoint']}` |")
    else:
        A("_None confirmed in this run._")
    A("")

    A("## 5. Capability coverage — crAPI challenges vs the ONYX model\n")
    A("ONYX proves authorization & business-logic breaks by Δstate read-back. The table "
      "shows which crAPI challenges fall inside that model (and were driven here) and which "
      "need a different class of tool.\n")
    A("| crAPI challenge | OWASP API | ONYX effect | in model | note |")
    A("|---|---|---|---|---|")
    probed_effects = {ep.get("effect", "").upper().replace("-", "_") for ep in plan_eps}
    for chall, owasp, effect, in_model, note in CAPABILITY_MAP:
        mark = "✅ yes" if in_model else "— no"
        comps = {e.strip().upper().replace("-", "_")
                 for e in effect.replace("(", "").replace(")", "").split("/")}
        if in_model and (comps & probed_effects):
            mark = "✅ driven"
        A(f"| {chall} | {owasp} | {effect} | {mark} | {note} |")
    A("")
    A("### Outside ONYX's model (use a complementary tool)\n")
    A("- **Injection** (coupon `$gt` NoSQLi, SQLi): needs a fuzzer / injection scanner.\n"
      "- **Rate-limit / brute-force** (OTP enumeration): needs a throughput tester.\n"
      "- **SSRF** (contact_mechanic): needs an out-of-band interaction scanner.\n"
      "- **JWT crypto** (alg=none, weak key): needs a token-forgery check.\n")
    A("> This is by design: ONYX trades breadth for proof. Everything it reports is "
      "confirmed by reading the victim's state back — no status-code guesses.\n")

    path = os.path.join(out_dir, "crapi_performance.md")
    open(path, "w", encoding="utf-8").write("\n".join(L))
    return path


_FIRST = ["liam", "noah", "oliver", "elijah", "james", "ava", "olivia", "emma", "sophia",
          "mia", "amelia", "omar", "yusuf", "sara", "layla", "hana", "mateo", "diego",
          "lucas", "nora", "ethan", "aya", "karim", "leila", "ines", "adam", "zoe",
          "hugo", "lena", "arjun", "priya", "wei", "chen", "kofi", "amara"]
_LAST = ["smith", "johnson", "williams", "brown", "garcia", "martinez", "khan", "ali",
         "haddad", "nguyen", "rossi", "muller", "silva", "kim", "park", "hassan",
         "farah", "dubois", "ivanov", "santos", "reyes", "cohen", "okafor", "mensah",
         "tanaka", "sato", "yilmaz", "novak", "kaur", "abbas"]


def identity(seq=0):
    """A realistic, varied crAPI account. Emails stay on example.com so MailHog receives
    them; everything else looks like an ordinary user, not a templated bot."""
    f, l = random.choice(_FIRST), random.choice(_LAST)
    sep = random.choice([".", "_", ""])
    tail = random.choice(["", "", str(random.randint(1, 99)), str(random.randint(70, 99))])
    # keep a tiny unique token so parallel runs never collide, folded in naturally
    uniq = "".join(random.choices(string.digits, k=3))
    email = f"{f}{sep}{l}{tail}{uniq}@example.com"
    name = f"{f.capitalize()} {l.capitalize()}"
    number = random.choice(["", "1", "9"]) + "".join(random.choices(string.digits, k=9))
    pw = (random.choice(string.ascii_uppercase) + "".join(random.choices(string.ascii_lowercase, k=5))
          + str(random.randint(10, 99)) + random.choice("!@#$%&"))
    return {"name": name, "email": email, "number": number[:10], "password": pw}


# ---- state cache: skip signup + provisioning on re-runs (big time saver) ---- #
def _state_path(out):
    return os.path.join(out, "state.json")


def load_state(out):
    try:
        with open(_state_path(out)) as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_state(out, data):
    try:
        os.makedirs(out, exist_ok=True)
        with open(_state_path(out), "w") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass


def rand_suffix(k=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=k))


# --------------------------------------------------------------------------- #
# Smart connect — resolve the URL, handle TLS, detect crAPI, verify creds:     #
# solve every connection problem BEFORE the scan starts.                       #
# --------------------------------------------------------------------------- #
def _origin(u):
    from urllib.parse import urlparse
    u = u.strip()
    if "://" not in u:
        u = "http://" + u
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def candidate_urls(u):
    """The given origin first, then a scheme-swap, then common crAPI ports if the
    user gave no explicit port — so a slightly-wrong URL still connects."""
    from urllib.parse import urlparse
    origin = _origin(u)
    p = urlparse(origin)
    host = p.hostname or "localhost"
    has_port = p.port is not None
    cands = [origin]
    cands.append(f"{'https' if p.scheme == 'http' else 'http'}://{p.netloc}")
    if not has_port:
        for scheme, port in (("http", 8888), ("http", 8080), ("https", 8443),
                             ("http", 80), ("https", 443)):
            cands.append(f"{scheme}://{host}:{port}")
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c); out.append(c)
    return out


def _probe(url, verify, timeout):
    import requests
    try:
        r = requests.get(url + "/", timeout=timeout, verify=verify, allow_redirects=True)
        return ("ok", r.status_code)
    except requests.exceptions.SSLError:
        return ("ssl", None)
    except requests.exceptions.ConnectionError:
        return ("refused", None)
    except requests.exceptions.RequestException as e:
        return (type(e).__name__, None)


def resolve_base(url, insecure, timeout=3.0):
    """Find a base URL that actually answers. Auto-falls back to insecure TLS for a
    self-signed cert. Returns {base, insecure, tried[]} — base is None if nothing answered."""
    tried = []
    for cand in candidate_urls(url):
        status, code = _probe(cand, not insecure, timeout)
        tried.append((cand, status, code))
        if status == "ok":
            return {"base": cand, "insecure": insecure, "tried": tried}
        if status == "ssl":
            status2, code2 = _probe(cand, False, timeout)     # retry ignoring the cert
            tried.append((cand + "  (--insecure)", status2, code2))
            if status2 == "ok":
                return {"base": cand, "insecure": True, "tried": tried, "ssl_fallback": True}
    return {"base": None, "insecure": insecure, "tried": tried}


def looks_like_crapi(cli):
    """A GET on the login route: any HTTP status (even 404/405) means the API is there."""
    try:
        r = cli._req("GET", P_LOGIN)
        return True, r.status_code
    except Exception:
        return False, None


def mailhog_ok(mailhog_url, verify):
    import requests
    try:
        r = requests.get(mailhog_url.rstrip("/") + "/api/v2/messages", timeout=4, verify=verify)
        return r.status_code < 500
    except Exception:
        return False


def verify_credentials(cli, tokens):
    """Confirm each principal's token actually authenticates (dashboard 2xx), so you
    never run a full sweep with a dead/expired token."""
    out = {}
    for pid, tok in tokens.items():
        if not tok:
            out[pid] = ("no token", None); continue
        try:
            r = cli._req("GET", P_DASH, token=tok)
            out[pid] = ("ok" if r.status_code < 400 else f"HTTP {r.status_code}", r.status_code)
        except Exception as e:
            out[pid] = (type(e).__name__, None)
    return out


def _ck(ok):
    return "✓" if ok else "✗"


def smart_connect(args):
    """Resolve the target, adopt TLS/insecure automatically, build a ready client, and
    print a green/red preflight checklist. Exits with a clear fix if the target is down."""
    print("Preflight — resolving the target…")
    res = resolve_base(args.base_url, args.insecure)
    if not res["base"]:
        lines = "\n".join(f"    {_ck(False)} {u:<34} {st}" for u, st, _ in res["tried"])
        sys.exit(
            f"\n{_ck(False)} Could not reach the target. Tried:\n{lines}\n\n"
            f"  Fix one of these, then re-run:\n"
            f"  • Start crAPI:   cd crAPI/deploy/docker && docker compose up -d\n"
            f"  • Verify it:     curl -i {args.base_url.rstrip('/')}/\n"
            f"  • Right port?    pass --base-url http://HOST:PORT  (crAPI default 8888)\n"
            f"  • HTTPS/self-signed?  add --insecure\n"
            f"  • Remote box?    use its IP instead of localhost\n")
    base = res["base"]
    insecure = res.get("insecure", args.insecure)
    if base.rstrip("/") != _origin(args.base_url):
        print(f"  {_ck(True)} auto-corrected URL → {base}")
    if res.get("ssl_fallback"):
        print(f"  {_ck(True)} self-signed TLS detected → continuing with --insecure")
    print(f"  {_ck(True)} target reachable        {base}")

    cli = CrapiClient(base, verify=not insecure)
    is_crapi, code = looks_like_crapi(cli)
    print(f"  {_ck(is_crapi)} looks like crAPI        "
          f"{'login endpoint present' if is_crapi else 'login route did not respond — is this crAPI?'}")
    if args.mailhog:
        mh = mailhog_ok(args.mailhog, not insecure)
        print(f"  {_ck(mh)} MailHog reachable       {args.mailhog}"
              f"{'' if mh else '  (auto vehicle-claim will be skipped)'}")
    args.base_url = base
    args.insecure = insecure
    return cli


def main(argv=None):
    ap = argparse.ArgumentParser(description="Comprehensive ONYX sweep of a local, authorized crAPI.")
    ap.add_argument("--base-url", default="http://localhost:8888")
    ap.add_argument("--full", action="store_true", help="sign up accounts + claim vehicles automatically")
    ap.add_argument("--mailhog", default="", help="MailHog base URL for auto vehicle-claim (e.g. http://localhost:8025)")
    ap.add_argument("--a-email"); ap.add_argument("--a-pass")
    ap.add_argument("--b-email"); ap.add_argument("--b-pass")
    ap.add_argument("--a-token"); ap.add_argument("--b-token")
    ap.add_argument("--a-vehicles"); ap.add_argument("--b-vehicles")
    ap.add_argument("--a-orders"); ap.add_argument("--b-orders")
    ap.add_argument("--a-reports"); ap.add_argument("--b-reports")
    ap.add_argument("--coupon", default="TRAC075", help="coupon code to test re-apply (with --confirm)")
    ap.add_argument("--researcher", default="")
    ap.add_argument("--program", default="crAPI (self-hosted, authorized)")
    ap.add_argument("--confirm", action="store_true", help="confirm write/business-logic bugs on YOUR OWN ids")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--doctor", action="store_true",
                    help="only run the connection/credential checks and stop (no scan)")
    ap.add_argument("--config", help="JSON file of defaults (base_url, mailhog, researcher, …); CLI overrides it")
    ap.add_argument("--fresh", action="store_true",
                    help="ignore any saved accounts/ids in the out dir and start clean")
    ap.add_argument("--delay", default="",
                    help="polite jitter between requests, seconds, e.g. 0.2,0.8 (default: none)")
    ap.add_argument("--out", default="./crapi_out")
    args = ap.parse_args(argv)

    # --config: fill any option the CLI didn't explicitly pass (CLI always wins)
    if args.config:
        raw = argv if argv is not None else sys.argv[1:]
        provided = {t[2:].split("=")[0].replace("-", "_") for t in raw if t.startswith("--")}
        try:
            with open(args.config) as fh:
                conf = json.load(fh)
            for k, v in conf.items():
                k = k.replace("-", "_")
                if hasattr(args, k) and k not in provided:
                    setattr(args, k, v)
            print(f"· loaded defaults from {args.config}")
        except Exception as e:
            print(f"· could not read --config {args.config}: {e}")

    delay = (0.0, 0.0)
    if args.delay:
        try:
            parts = [float(x) for x in args.delay.split(",")]
            delay = (parts[0], parts[-1]) if len(parts) >= 1 else (0.0, 0.0)
        except ValueError:
            print("· ignoring bad --delay (use e.g. 0.2,0.8)")

    cli = smart_connect(args)   # resolves URL, TLS, crAPI + MailHog reachability
    cli.delay = delay
    def split(v): return [x.strip() for x in (v or "").split(",") if x.strip()]

    setup = {"A": {}, "B": {}}
    creds = {"A": (args.a_email, args.a_pass, args.a_token),
             "B": (args.b_email, args.b_pass, args.b_token)}

    # resume: reuse accounts saved from a previous run so we don't re-sign-up every time
    state = {} if args.fresh else load_state(args.out)
    saved_accts = (state.get("accounts") or {}) if isinstance(state, dict) else {}
    if saved_accts and not any(creds[p][2] for p in ("A", "B")) \
            and not (args.a_email or args.b_email):
        reused = False
        for pid in ("A", "B"):
            a = saved_accts.get(pid)
            if a and a.get("email") and a.get("password"):
                creds[pid] = (a["email"], a["password"], None); reused = True
        if reused:
            print(f"· resuming saved accounts from {_state_path(args.out)} (use --fresh to start clean)")

    # sign up fresh accounts (parallel) with realistic, varied identities
    if args.full and not any(creds[p][2] for p in ("A", "B")) \
            and not all(creds[p][0] for p in ("A", "B")):
        from concurrent.futures import ThreadPoolExecutor
        def _signup(pid):
            if creds[pid][0]:   # a resumed/provided email — keep it
                return pid, creds[pid][0], creds[pid][1] or "Passw0rd!23", None
            ident = identity()
            ok = cli.signup(ident["name"], ident["email"], ident["number"], ident["password"])
            return pid, ident["email"], ident["password"], ok
        with ThreadPoolExecutor(max_workers=2) as ex:
            for pid, email, pw, ok in ex.map(_signup, ("A", "B")):
                creds[pid] = (email, pw, None)
                setup[pid]["signup"] = ok
                print(f"[{pid}] signup {email}: {'ok' if ok else 'skipped/failed'}")

    # tokens
    tokens = {}
    for pid in ("A", "B"):
        email, pw, tok = creds[pid]
        if tok:
            tokens[pid] = tok; setup[pid]["source"] = "token"
        elif email and pw:
            tokens[pid] = cli.login(email, pw); setup[pid]["source"] = "login"
        else:
            tokens[pid] = None; setup[pid]["source"] = "—"
        setup[pid]["token"] = bool(tokens[pid])
    if not (tokens["A"] and tokens["B"]):
        if args.doctor:
            print(f"  {_ck(False)} credentials             need two accounts "
                  "(--full, or --a-email/--a-pass + --b-email/--b-pass, or --a-token/--b-token)")
            print("\nPreflight finished (doctor mode). Fix the items marked ✗ and re-run.")
            return 0
        sys.exit("Need two accounts. Use --full, or --a-email/--a-pass + --b-email/--b-pass, "
                 "or --a-token/--b-token.")

    # verify each credential actually authenticates BEFORE running the whole sweep
    creds_ok = verify_credentials(cli, tokens)
    for pid in ("A", "B"):
        cstate, _ = creds_ok[pid]
        print(f"  {_ck(cstate == 'ok')} account {pid} credential   {cstate}")
    if all(v[0] != "ok" for v in creds_ok.values()):
        msg = ("Neither credential authenticated (dashboard did not return 2xx). "
               "Re-check the tokens/passwords, or that these accounts exist in crAPI.")
        if args.doctor:
            print(f"  {_ck(False)} {msg}")
        else:
            sys.exit(msg)

    if args.doctor:
        print("\n✓ Preflight passed. Re-run the same command without --doctor to scan.")
        return 0

    saved_ids = (state.get("ids") or {}) if isinstance(state, dict) else {}
    already = {p: bool((saved_ids.get(p) or {}).get("vehicles")) for p in ("A", "B")}
    if all(already.values()):
        print("· both accounts already provisioned in a previous run — skipping signup extras")

    # claim a vehicle for each account (via MailHog if given). In --full we always try,
    # unless a saved run already provisioned that account (saves time on re-runs).
    if args.mailhog or args.full:
        mh = args.mailhog or ""
        for pid in ("A", "B"):
            if already.get(pid):
                continue
            if mh:
                ok, detail = cli.claim_vehicle_via_mailhog(mh, tokens[pid], creds[pid][0] or "")
            else:
                ok, detail = (cli.register_vehicle(tokens[pid]),
                              "registered — pass --mailhog to auto-add, or add it from the dashboard")
            setup[pid]["claimed"] = ok
            print(f"[{pid}] vehicle claim: {'ok — ' + detail if ok else 'not added — ' + detail}")

    # in full mode, buy a product per account so shop-order probes have data
    if args.full:
        for pid in ("A", "B"):
            if already.get(pid) and (saved_ids.get(pid) or {}).get("orders"):
                continue
            prods = cli.products(tokens[pid])
            if prods:
                ok, detail = cli.buy(tokens[pid], prods[0])
                print(f"[{pid}] buy product {prods[0]}: {'ok (order ' + str(detail) + ')' if ok else 'failed — ' + str(detail)}")

    # discover everything (fall back to saved ids if a live listing comes back empty)
    ids = {}
    for pid, vo, oo, ro in (("A", args.a_vehicles, args.a_orders, args.a_reports),
                            ("B", args.b_vehicles, args.b_orders, args.b_reports)):
        sv = saved_ids.get(pid) or {}
        vehicles = split(vo) or cli.vehicles(tokens[pid]) or sv.get("vehicles") or []
        orders = split(oo) or cli.orders(tokens[pid]) or sv.get("orders") or []
        reports = split(ro) or sv.get("reports") or []
        ids[pid] = {"vehicles": vehicles, "orders": orders, "reports": reports,
                    "coupon": args.coupon if args.confirm else None}
        setup[pid].update(vehicles=vehicles, orders=orders, reports=reports)
        print(f"[{pid}] vehicles={vehicles or '—'} orders={orders or '—'} reports={reports or '—'}")

    # harvest OTHER users' vehicle uuids from the community feed (BOLA fuel)
    other = cli.other_vehicle_uuids(tokens["A"]) if tokens["A"] else []
    if other:
        print(f"[*] harvested {len(other)} vehicle uuid(s) from community feed")
        owned = set(ids["A"]["vehicles"]) | set(ids["B"]["vehicles"])
        extra = [u for u in other if u not in owned]
        if extra and not ids["B"]["vehicles"]:
            ids["B"]["vehicles"] = extra[:2]; setup["B"]["vehicles"] = ids["B"]["vehicles"]

    # If cross-account tests can't be assembled, say EXACTLY what to do (guaranteed path).
    lacks_vehicle = [p for p in ("A", "B") if not ids[p]["vehicles"]]
    if lacks_vehicle:
        base = args.base_url
        print("\n  ⚠ These accounts have no vehicle yet: " + ", ".join(lacks_vehicle) + ".")
        print("    crAPI needs a vehicle added once per account (30s each) — the guaranteed way:")
        for p in lacks_vehicle:
            em = creds[p][0] or "(the account you used)"
            print(f"      • {p}: open {base}  → log in as {em}  → 'Add Vehicle'")
        print(f"      • Get each VIN + Pincode from MailHog: {args.mailhog or 'http://localhost:8025'}")
        print("    Then re-run the SAME command — the tool auto-discovers the vehicles and scans.\n")

    setup["_http"] = cli.n
    setup["_latencies"] = cli.latencies

    # persist accounts + ids so the next run resumes instantly (no re-signup/provision)
    save_state(args.out, {
        "base_url": args.base_url,
        "accounts": {pid: {"email": creds[pid][0], "password": creds[pid][1]}
                     for pid in ("A", "B") if creds[pid][0] and creds[pid][1]},
        "ids": {pid: {"vehicles": ids[pid]["vehicles"], "orders": ids[pid]["orders"],
                      "reports": ids[pid]["reports"]} for pid in ("A", "B")},
    })

    # build the plan + run ONYX (single source of truth: serve._build_scan)
    from authpath.serve import _build_scan, ScanError
    cfg = build_plan(tokens, ids, confirm=args.confirm)
    cfg["base_url"] = args.base_url
    cfg["researcher"] = args.researcher
    cfg["program"] = args.program
    plan_eps = cfg["endpoints"]

    engine = None; scan = {"secs": 0.0}
    with count_engine_http() as ehttp:
        if plan_eps:
            t0 = time.perf_counter()
            try:
                engine, _tl = _build_scan(cfg)
            except ScanError as e:
                sys.exit(f"scan setup error: {e}")
            scan["secs"] = time.perf_counter() - t0
    engine_http = ehttp

    if engine is None:
        # still emit a performance report so the user sees coverage + why nothing ran
        snap = {"findings": [], "traces": [],
                "counts": {"analyzed": 0, "findings": 0, "candidates_dropped": 0,
                           "clean": 0, "halted": 0, "leads": 0, "severity": {}}}
        meta = {"base_url": args.base_url, "program": args.program, "researcher": args.researcher,
                "when": time.strftime("%Y-%m-%d %H:%M:%S"), "confirm": args.confirm,
                "signup": args.full, "mailhog": bool(args.mailhog)}
        perf = write_perf_report(args.out, meta=meta, setup=setup, plan_eps=plan_eps,
                                 scan=scan, snap=snap, engine_http=engine_http)
        print("\n  No cross-principal endpoints could be assembled (each account needs a vehicle "
              "and/or an order the other does not own).")
        print("  Capability/performance report:", perf)
        return 0

    snap = engine.snapshot()
    meta = {"base_url": args.base_url, "program": args.program, "researcher": args.researcher,
            "when": time.strftime("%Y-%m-%d %H:%M:%S"), "confirm": args.confirm,
            "signup": args.full, "mailhog": bool(args.mailhog)}

    print("\n" + "=" * 66)
    print(f"  crAPI sweep — {snap['counts'].get('findings',0)} confirmed / "
          f"{snap['counts'].get('candidates_dropped',0)} dropped / "
          f"{snap['counts'].get('analyzed',0)} probes / {scan['secs']:.2f}s")
    print("=" * 66)
    for f in snap["findings"]:
        print(f"  [{f['severity']:<8}] {f['effect']:<14} {f['actor']} ▸ {f['target']}  {f['endpoint']}")

    perf = write_perf_report(args.out, meta=meta, setup=setup, plan_eps=plan_eps,
                             scan=scan, snap=snap, engine_http=engine_http)
    if snap["findings"]:
        combined, pdir, zpath = write_vuln_report(engine, args.out,
                                                  program=args.program, researcher=args.researcher)
        print("\n  Vulnerability report :", combined)
        print("  Submission pack      :", pdir + "/  (+ INDEX.md)")
        print("  Zipped pack          :", zpath)
    else:
        print("\n  No confirmed findings — see the performance report for coverage + why.")
    print("  Performance report   :", perf)
    print("\n  Only submit findings for a target whose program authorizes it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
