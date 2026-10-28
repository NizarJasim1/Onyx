#!/usr/bin/env python3
"""
onyx_recon.py — a GENERAL, authorized "use the whole app + hunt" engine.

Point ONYX at any target you are AUTHORIZED to test. It ingests the app's surface
(OpenAPI/Swagger spec, or a HAR capture), exercises it as two+ accounts to harvest
object ids with provenance, infers each endpoint's effect, builds a cross-principal
plan, and hunts authorization + business-logic bugs — every finding proven by ONYX's
Δstate read-back.

Guardrails (this is authorized-testing tooling):
  * --authorized is REQUIRED. No run without affirming you may test these hosts.
  * Scope-Guard: only hosts on --scope (or the base host) are ever contacted; off-scope
    URLs found in the spec/HAR are dropped.
  * Honest attribution: an identifiable User-Agent carries your handle. No disguising,
    no defeating anti-automation / WAF controls.
  * Polite: optional --delay jitter; mutating probes stay dry-run unless --confirm.
  * Proof, not guesses: findings come from ONYX Δstate, not 200-vs-403.

Examples
  # from an OpenAPI spec, two bearer tokens:
  python3 external_targets/onyx_recon.py --authorized \
      --openapi http://localhost:8080/openapi.json \
      --base-url http://localhost:8080 \
      --principal A:eyJA... --principal B:eyJB... \
      --researcher you --out ./recon_out

  # from a HAR you captured in a proxy:
  python3 external_targets/onyx_recon.py --authorized --har ./capture.har \
      --base-url https://api.target.com --principal A:tokA --principal B:tokB --out ./out

  # confirm write/business-logic bugs on ids you own:
  python3 external_targets/onyx_recon.py --authorized [...] --confirm
"""
from __future__ import annotations
import argparse, json, os, re, sys, time, statistics, random
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)


# --------------------------------------------------------------------------- #
# effect inference — the "intelligent" part: what law does this endpoint bear? #
# --------------------------------------------------------------------------- #
EFFECT_SIGNALS = [
    ("PAYMENT",  ("amount_paid", "amountpaid", "pay", "payment", "checkout", "charge",
                  "refund", "wallet", "balance", "settle")),
    ("PRICE",    ("price", "total", "cost", "discount", "cart", "amount_due", "subtotal")),
    ("COUPON",   ("coupon", "promo", "voucher", "redeem")),
    ("OWNERSHIP",("role", "is_admin", "isadmin", "admin", "owner", "grant", "privilege")),
    ("STATE_GATE",("status", "state", "approve", "publish", "cancel", "confirm", "fulfil",
                   "fulfill", "activate", "verify")),
]
AUTHORITY_PATHS = ("/admin", "/internal", "/mechanic", "/manage", "/backoffice")


def guess_effect(method, path, params, body):
    m = (method or "GET").upper()
    p = (path or "").lower()
    blob = p + " " + " ".join(params or []) + " " + json.dumps(body or {}).lower()
    if m == "GET":
        # a read with an id slot is the classic object-access / IDOR probe
        return "object-access" if "{id}" in path else "auto"
    if any(seg in p for seg in AUTHORITY_PATHS):
        return "authority"
    for effect, needles in EFFECT_SIGNALS:
        if any(n in blob for n in needles):
            return effect.lower().replace("_", "-")
    return "ownership" if m in ("PUT", "PATCH", "POST") else "auto"


def tamper_body(body, effect):
    """Turn a benign example body into a probe payload for the guessed effect."""
    b = dict(body or {})
    e = (effect or "").upper().replace("-", "_")
    if e == "PAYMENT":
        for k in list(b):
            if any(s in k.lower() for s in ("amount_paid", "amountpaid", "paid", "pay")):
                b[k] = 1
    elif e == "PRICE":
        for k in list(b):
            if any(s in k.lower() for s in ("price", "total", "cost", "subtotal")):
                b[k] = 1
    elif e == "OWNERSHIP":
        b.setdefault("role", "admin"); b.setdefault("is_admin", True)
    elif e == "STATE_GATE":
        for k in list(b):
            if "status" in k.lower() or "state" in k.lower():
                b[k] = "approved"
    return b


# --------------------------------------------------------------------------- #
# scope-guarded, honestly-attributed HTTP client                              #
# --------------------------------------------------------------------------- #
class Client:
    def __init__(self, scope_hosts, researcher="", verify=True, delay=(0.0, 0.0), timeout=15):
        import requests
        self.requests = requests
        self.scope = set(scope_hosts)
        self.ua = f"ONYX-Recon/1.0 (authorized-testing){'; ' + researcher if researcher else ''}"
        self.verify = verify
        self.delay = delay
        self.timeout = timeout
        self.n = 0
        self.latencies = []

    def in_scope(self, url):
        h = urlparse(url if "://" in url else "http://" + url).hostname or ""
        return h in self.scope

    def req(self, method, url, token=None, **kw):
        if not self.in_scope(url):
            raise PermissionError(f"off-scope host blocked by Scope-Guard: {url}")
        if self.delay[1] > 0:
            time.sleep(random.uniform(*self.delay))
        headers = kw.pop("headers", {})
        headers["User-Agent"] = self.ua
        if token:
            headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
        t0 = time.perf_counter()
        r = self.requests.request(method, url, headers=headers, timeout=self.timeout,
                                  verify=self.verify, **kw)
        self.n += 1
        self.latencies.append(int((time.perf_counter() - t0) * 1000))
        return r


# --------------------------------------------------------------------------- #
# ingestion: OpenAPI + HAR -> normalized endpoints                            #
# --------------------------------------------------------------------------- #
def _load_doc(src, client=None):
    """Load a spec/HAR from a URL (in scope) or a local file. JSON, or YAML if available."""
    if re.match(r"^https?://", src):
        if not client:
            raise SystemExit("a URL source needs a client (scope)")
        text = client.req("GET", src).text
    else:
        with open(src, encoding="utf-8") as fh:
            text = fh.read()
    try:
        return json.loads(text)
    except ValueError:
        try:
            import yaml  # optional
            return yaml.safe_load(text)
        except Exception:
            raise SystemExit(f"could not parse {src} as JSON (install pyyaml for YAML specs)")


def _example_from_schema(schema, depth=0):
    if not isinstance(schema, dict) or depth > 4:
        return {}
    if "example" in schema:
        return schema["example"]
    t = schema.get("type")
    if t == "object" or "properties" in schema:
        return {k: _example_from_schema(v, depth + 1)
                for k, v in (schema.get("properties") or {}).items()}
    if t == "array":
        return []
    return {"string": "", "integer": 0, "number": 0, "boolean": False}.get(t, "")


def ingest_openapi(doc):
    """paths -> [{method, path, params, other_params, query_id, body}].
    The LAST path param becomes ONYX's {id} slot; a query parameter named like an id
    (id / *_id / *Id) is captured as `query_id` so resources addressed by query string
    (e.g. crAPI's /mechanic_report?report_id={id}) are probed too."""
    out = []
    paths = doc.get("paths") or {}
    for raw_path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        path_params = re.findall(r"\{([^}]+)\}", raw_path)
        path = raw_path
        other_params = []
        if path_params:
            last = path_params[-1]
            path = raw_path.replace("{" + last + "}", "{id}")
            other_params = path_params[:-1]
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            op = op if isinstance(op, dict) else {}
            # query parameter that names an object id (operation- or path-level)
            params_meta = list(op.get("parameters") or []) + list(ops.get("parameters") or [])
            query_id = None
            for pm in params_meta:
                if isinstance(pm, dict) and pm.get("in") == "query":
                    nm = str(pm.get("name", ""))
                    lo = nm.lower()
                    if lo == "id" or lo.endswith("_id") or lo.endswith("id"):
                        query_id = nm; break
            body = {}
            rb = op.get("requestBody")
            if rb:
                content = (rb.get("content") or {}).get("application/json") or {}
                body = content.get("example") or _example_from_schema(content.get("schema") or {})
                if not isinstance(body, dict):
                    body = {}
            out.append({"method": method.upper(), "path": path,
                        "params": path_params, "other_params": other_params,
                        "query_id": query_id, "body": body,
                        "multi_param": len(other_params) > 0})
    return out


def ingest_har(doc):
    """HAR entries -> endpoints; templatize the last numeric/uuid path segment."""
    out, seen = [], set()
    entries = ((doc.get("log") or {}).get("entries")) or []
    for e in entries:
        req = e.get("request") or {}
        method = (req.get("method") or "GET").upper()
        url = req.get("url") or ""
        pr = urlparse(url)
        segs = pr.path.split("/")
        idx = None
        for i in range(len(segs) - 1, -1, -1):
            if re.fullmatch(r"\d+", segs[i]) or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{8,}", segs[i], re.I):
                idx = i; break
        if idx is not None:
            segs[idx] = "{id}"
        path = "/".join(segs) or "/"
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        body = {}
        pd = (req.get("postData") or {}).get("text")
        if pd:
            try:
                body = json.loads(pd)
                if not isinstance(body, dict):
                    body = {}
            except ValueError:
                body = {}
        out.append({"method": method, "path": path,
                    "params": ["id"] if idx is not None else [],
                    "body": body, "multi_param": False})
    return out


# --------------------------------------------------------------------------- #
# Discrimination gate — transplants ONYX's own rigor into the recon layer so    #
# the engine never receives polluted inputs. Three filters:                     #
#   1) identity   — a value is an OBJECT id, not a JWT / message / email        #
#   2) endpoint   — a path is a resource read/write, not auth / account / action#
#   3) ownership  — an id confers ownership only from an owner-scoped collection #
#                   (per-principal id sets must be DISJOINT; shared feeds don't) #
# --------------------------------------------------------------------------- #
_JWT_RE = re.compile(r"^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{8,}$")
_INT_RE = re.compile(r"^[0-9]{1,19}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
# Endpoints that must NEVER be probed. The first group MIRRORS the engine's own
# revocation heuristic (authpath/temporal.py _REVOCATION_PATTERNS): probing any of
# these injects a revocation event into the ledger, after which every later read is
# (correctly, per the engine) flagged TEMPORAL_DRIFT — the exact false-positive cascade
# seen on real crAPI. This exclusion is therefore principled, not a guess: it keeps the
# recon layer from poisoning the very ledger the engine reasons over. The second group
# is non-object surface (auth/account/action) that is never a BOLA target.
_EXCLUDE_RE = re.compile(
    r"/(change[-_]?password|reset[-_]?password|forgot[-_]?password|forget[-_]?password|"
    r"logout|signout|sign[-_]?out|sessions?/(?:end|destroy)|revoke|deauthorize|disable[-_]?token|"  # revocation-shaped
    r"login|signin|sign[-_]?in|signup|sign[-_]?up|register|auth|token|refresh|jwt|session|"          # session/auth
    r"otp|verify|verification|resend|activate|change[-_]?email|change[-_]?phone|change[-_]?number|password|"  # account
    r"contact[-_]?mechanic|contact|subscribe|unsubscribe|upload|search|health|status|metrics)"       # actions/infra
    r"(/|$|\?)", re.I)


def _looks_like_id(v):
    """A genuine object identifier: short, opaque, re-fetchable — never a JWT,
    a sentence, an email, or a status message."""
    if isinstance(v, bool) or v is None:
        return False
    s = str(v).strip()
    if not s or len(s) > 64:
        return False
    if any(c in s for c in " \t\n\r@"):        # sentences / emails are not ids
        return False
    if _JWT_RE.match(s):                        # JWTs are credentials, not object ids
        return False
    return bool(_INT_RE.match(s) or _UUID_RE.match(s) or _TOKEN_RE.match(s))


def _is_probeable(path):
    """True only for resource endpoints; auth/account/action/revocation paths are never BOLA."""
    return not _EXCLUDE_RE.search(path or "")


ID_KEYS = ("id", "uuid", "guid")


def _collect_ids(obj, extra_keys=()):
    keys = set(ID_KEYS) | set(k.lower() for k in extra_keys)
    out, seen = [], set()

    def walk(n):
        if isinstance(n, dict):
            for k, v in n.items():
                lk = k.lower()
                if (lk in keys or lk.endswith("_id") or lk.endswith("id")) and _looks_like_id(v):
                    s = str(v)
                    if s not in seen:
                        seen.add(s); out.append(s)
                else:
                    walk(v)
        elif isinstance(n, list):
            for x in n:
                walk(x)
    walk(obj)
    return out


def _next_url(data):
    """A conservative pagination cursor: an explicit absolute `next`-style URL. We never
    guess page params (that risks fetching unrelated data); only a declared next link is
    followed, and only if the client's Scope-Guard allows the host."""
    if isinstance(data, dict):
        for k in ("next", "next_page", "nextPage", "nextPageToken", "next_url", "nextUrl"):
            v = data.get(k)
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                return v
        # some APIs nest pagination under "meta"/"pagination"
        for holder in ("meta", "pagination", "paging"):
            m = data.get(holder)
            if isinstance(m, dict):
                v = m.get("next") or m.get("next_url")
                if isinstance(v, str) and v.startswith(("http://", "https://")):
                    return v
    return None


def harvest(client, base_url, endpoints, principals):
    """Read each owner-scoped collection as every principal and establish OWNERSHIP with
    provenance. Returns (owned[resource][pid], pool[pid], report) where report explains
    what was classified shared vs owner-scoped — the discrimination that kills the
    'shared-feed id assigned to everyone' false positive.

    An id confers ownership ONLY from a collection whose per-principal id sets are
    disjoint (each account sees different ids = owner-scoped). A collection every account
    sees identically (a public/community feed) confers NO ownership and is skipped."""
    base = base_url.rstrip("/")
    collections = [e for e in endpoints if e["method"] == "GET" and "{id}" not in e["path"]
                   and not e.get("multi_param") and not e.get("query_id")
                   and _is_probeable(e["path"])]
    per = {}   # resource -> pid -> set(ids)
    for e in collections:
        for pid, tok in principals.items():
            url = base + e["path"]
            pages = 0
            while url and pages < 5:
                try:
                    r = client.req("GET", url, token=tok)
                    if r.status_code >= 400:
                        break
                    data = r.json()
                except Exception:
                    break
                per.setdefault(e["path"], {}).setdefault(pid, set()).update(_collect_ids(data))
                # follow an explicit, IN-SCOPE `next` link only (pagination). Extra ids are
                # still subject to per-id ownership + the engine's Δstate — FP-safe.
                nxt = _next_url(data)
                if not nxt or not client.in_scope(nxt):
                    break
                url = nxt
                pages += 1

    owned, pool = {}, {pid: [] for pid in principals}
    report = {"owner_scoped": [], "shared": []}
    # Per-ID ownership (not per-collection): an id is owned by P iff EXACTLY ONE
    # principal ever saw it. A single shared value (an enum, a category, a public
    # feed id) is dropped on its own — it no longer poisons the whole collection,
    # which previously discarded real owned ids (a false negative) or admitted the
    # shared id (a false positive). This is the disjointness test done right.
    id_owners = {}
    for res, pmap in per.items():
        for pid, s in pmap.items():
            for i in s:
                id_owners.setdefault(i, set()).add(pid)
    for res, pmap in per.items():
        contributed, shared_here = False, False
        for pid, s in pmap.items():
            for i in s:
                if id_owners[i] == {pid}:                 # exactly one owner
                    owned.setdefault(res, {}).setdefault(pid, [])
                    if i not in owned[res][pid]:
                        owned[res][pid].append(i)
                    if i not in pool[pid]:
                        pool[pid].append(i)
                    contributed = True
                else:
                    shared_here = True
        if contributed:
            report["owner_scoped"].append(res)
        elif shared_here:
            report["shared"].append(res)
    return owned, pool, report


def _resource_of(path):
    # /api/orders/{id} -> /api/orders  ; /api/orders/{id}/items -> /api/orders/{id}/items (skip)
    return path.rsplit("/{id}", 1)[0] if path.endswith("/{id}") else None


# --------------------------------------------------------------------------- #
# plan: turn surface + owned ids into an ONYX engagement config                #
# --------------------------------------------------------------------------- #
def build_plan(endpoints, owned, pool, principals, confirm, max_ids=4, max_probes=80):
    eps = []
    pids = list(principals.keys())

    def ids_for(path):
        """ids each principal can supply for this {id} slot: link to a sibling collection
        if we can, otherwise fall back to everything that principal owns."""
        res = _resource_of(path)
        linked = owned.get(res) if res else None
        out = {}
        for pid in pids:
            vals = (linked.get(pid) if linked else None) or pool.get(pid) or []
            if vals:
                out[pid] = vals[:max_ids]
        return out

    for e in endpoints:
        if len(eps) >= max_probes:
            break
        if e.get("multi_param") or not _is_probeable(e["path"]):
            continue
        method, path = e["method"], e["path"]
        qid = e.get("query_id")
        has_slot = ("{id}" in path) or bool(qid)
        effect = guess_effect(method, path, e.get("params", []), e.get("body"))

        def _probe(effect_name, ids, body=None):
            p = {"method": method, "path": path, "effect": effect_name, "ids": ids}
            if qid:
                p["query_id"] = qid
            if body is not None:
                p["body"] = body
            return p

        # object reads with an id slot -> cross-principal BOLA (path OR query addressed)
        if method == "GET" and has_slot:
            ids = ids_for(path)
            if len(ids) >= 2:
                eps.append(_probe("object-access", ids))
            continue

        # cross-account WRITE (BFLA): does one account's write reach ANOTHER account's
        # object? Routed as object-access so the VERIFIED three-way leak audit confirms
        # it — the write's response must reproduce the victim's private fields (a real
        # cross-account disclosure), never a bare 200. DELETE is skipped (destructive).
        if method in ("PUT", "PATCH") and has_slot and confirm:
            ids = ids_for(path)
            if len(ids) >= 2:
                body = json.dumps(e["body"]) if e.get("body") else None
                eps.append(_probe("object-access", ids, body))
                continue

        # self-abuse business-logic (payment/price/coupon/state) -> tampered body
        if method in ("POST", "PUT", "PATCH") and confirm and e.get("body"):
            body = tamper_body(e["body"], effect)
            actor = pids[0]
            aid = (ids_for(path).get(actor, [])[:1] or ["self"]) if has_slot else ["self"]
            eps.append(_probe(effect, {actor: aid}, json.dumps(body)))
    # NOTE: nested multi-param paths (/a/{x}/b/{id}) are intentionally NOT probed. The
    # engine selects the object id from a multi-id path in a way that makes the parent
    # ambiguous, so a naive fill neither confirms (no true positive) nor risks a false
    # positive — it only wastes probes. Doing it properly needs engine-side provenance
    # for nested ids; deferred rather than shipped as dead weight.
    return eps


# --------------------------------------------------------------------------- #
# reports                                                                      #
# --------------------------------------------------------------------------- #
def _lat(xs):
    if not xs:
        return (0, 0, 0)
    s = sorted(xs)
    return (int(statistics.median(s)), s[min(len(s) - 1, int(len(s) * 0.95))], s[-1])


def _flatten(body, prefix="", out=None):
    """Flatten a JSON body to {dotted_key: scalar}. Only substantive scalars are kept:
    non-empty strings/numbers that could carry private state (booleans, tiny tokens and
    empties are ignored so they can never masquerade as a 'leak')."""
    out = {} if out is None else out
    if isinstance(body, dict):
        for k, v in body.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(body, list):
        for i, v in enumerate(body[:20]):
            _flatten(v, f"{prefix}[{i}]", out)
    else:
        if isinstance(body, bool) or body is None:
            return out
        s = str(body)
        if len(s) >= 3 and s.strip():          # substantive scalar only
            out[prefix] = s
    return out


def _read_fields(client, url, token, k=1):
    """Return (ok, list_of_flattened_reads). ok=all reads were 2xx with a JSON body."""
    reads = []
    for _ in range(max(1, k)):
        try:
            r = client.req("GET", url, token=token)
        except Exception:
            return False, reads
        if not (200 <= r.status_code < 300):
            return False, reads
        try:
            reads.append(_flatten(r.json()))
        except Exception:
            reads.append({})
    return True, reads


def reconfirm(client, base_url, principals, pool, finding, ep_meta, k=2):
    """Independent Adversarial Re-Confirmation. Returns (keep, reason).

    A second, engine-independent Δstate check that a real cross-account read must
    survive. It DROPS a finding only on POSITIVE evidence that it is a false positive
    (public resource, server-ignores-the-id, or non-reproducible) — otherwise it KEEPS
    it, so no genuine finding is ever lost. Adds an anonymous baseline the engine's
    two-principal audit lacks. Non-GET (write) findings are passed through (the engine's
    three-way write audit already governs them; the recon layer never fabricates)."""
    ep_raw = str(finding.get("endpoint", ""))
    parts = ep_raw.split(" ", 1)
    if len(parts) == 2 and parts[0] in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        fmethod, fpath = parts[0], parts[1]
    else:
        fmethod, fpath = "GET", ep_raw
    meta = ep_meta.get(fpath)
    if fmethod != "GET" or not meta:
        return True, "non-read finding (engine-governed)"
    X = str(finding.get("target", ""))
    A = str(finding.get("actor", ""))
    if A not in principals or not X:
        return True, "insufficient context to re-confirm"
    base = base_url.rstrip("/")

    def url_for(oid):
        if meta.get("query_id"):
            from urllib.parse import urlencode
            return base + meta["path"] + "?" + urlencode({meta["query_id"]: oid})
        return base + meta["path"].replace("{id}", str(oid))

    tgt_url = url_for(X)
    # (1) reproducibility — the attacker's access must succeed K times with substantive data
    ok, a_reads = _read_fields(client, tgt_url, principals[A], k=k)
    if not ok or not a_reads or not any(a_reads):
        return False, "not reproducible (attacker read failed on re-check)"
    stable = {f: v for f, v in a_reads[0].items() if all(r.get(f) == v for r in a_reads)}
    substantive = {f: v for f, v in stable.items() if f.split(".")[-1] != "id" and v != X}
    if not substantive:
        return False, "no stable substantive field on re-read"
    # (2) public-resource baseline — if an ANONYMOUS client reproduces any of it, it's public
    ok_anon, anon = _read_fields(client, tgt_url, None, k=1)
    if ok_anon and anon and any(anon[0].get(f) == v for f, v in substantive.items()):
        return False, "public: anonymous client reproduces the data"
    # (3) server-ignores-the-id — if the attacker gets IDENTICAL data for its OWN id, the
    #     endpoint isn't object-scoped (returns the caller's own thing regardless)
    own = [i for i in (pool.get(A) or []) if str(i) != X]
    if own:
        ok_own, o_reads = _read_fields(client, url_for(own[0]), principals[A], k=1)
        if ok_own and o_reads and o_reads[0]:
            own_sub = {f: o_reads[0].get(f) for f in substantive}
            if own_sub == substantive:
                return False, "server ignores the id (returns the caller's own object)"
    return True, "independently re-confirmed (reproducible, non-public, object-scoped)"


def _ep_meta(plan_eps):
    """endpoint template -> {method, path, query_id} for re-confirmation."""
    out = {}
    for e in plan_eps:
        key = e["path"] if not e.get("query_id") else e["path"]
        out[e["path"]] = {"method": e["method"], "path": e["path"], "query_id": e.get("query_id")}
    return out


def write_reports(engine_kept, kept, out, *, meta, surface, owned, hreport, gate,
                  plan_eps, recon_http, scan_secs, counts):
    os.makedirs(out, exist_ok=True)
    # vulnerability report — ONLY the gate-accepted findings (zero-FP)
    from bounty_report import submission_pack
    import zipfile
    pack = submission_pack(engine_kept, program=meta["program"], researcher=meta["researcher"])
    pdir = os.path.join(out, "submission_pack"); os.makedirs(pdir, exist_ok=True)
    for name, md in pack.items():
        open(os.path.join(pdir, name), "w", encoding="utf-8").write(md)
    with zipfile.ZipFile(os.path.join(out, "submission_pack.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        for name, md in pack.items():
            z.writestr(name, md)
    reports = sorted(k for k in pack if k != "INDEX.md")
    open(os.path.join(out, "recon_report.md"), "w", encoding="utf-8").write(
        (pack.get("INDEX.md", "# ONYX Recon report")) + "".join("\n\n---\n\n" + pack[k] for k in reports))

    med, p95, mx = _lat(recon_http["latencies"])
    L = ["# ONYX Recon — capability, coverage & performance\n",
         f"**Target:** {meta['base_url']}  ", f"**Scope:** {', '.join(meta['scope'])}  ",
         f"**Source:** {meta['source']}  ", f"**Researcher:** {meta['researcher'] or '—'}  ",
         f"**When:** {meta['when']}  ",
         f"**Mode:** {'CONFIRM' if meta['confirm'] else 'dry-run'}\n",
         "## Surface discovered\n",
         f"- endpoints ingested: **{len(surface)}**",
         f"- owner-scoped collections (confer ownership): **{len(owned)}**"
         + (f"  — {', '.join(r.split('/')[-1] or r for r in owned)}" if owned else ""),
         f"- shared/public collections (skipped, confer no ownership): **{len(hreport['shared'])}**"
         + (f"  — {', '.join(r.split('/')[-1] or r for r in hreport['shared'])}" if hreport['shared'] else ""),
         f"- cross-principal probes planned: **{len(plan_eps)}**",
         f"- recon HTTP requests: {recon_http['n']} (median {med} ms, p95 {p95} ms)\n",
         "## Discrimination gate (the zero-false-positive guarantee)\n",
         "The recon layer runs ONYX's own rigor before *and* after the engine: only genuine "
         "object ids, only resource endpoints (auth/account/action excluded), ownership only "
         "from owner-scoped collections, and only real authorization/business-logic effects.\n",
         "| stage | value |", "|---|---|",
         f"| raw engine candidates | {gate['raw']} |",
         f"| **accepted (reported)** | **{gate['kept']}** |",
         f"| suppressed as noise | {gate['suppressed']} |"]
    for why, n in sorted(gate["reasons"].items()):
        L.append(f"| — {why} | {n} |")
    L += ["\n## Scan result\n", "| metric | value |", "|---|---|",
          f"| probes analyzed | {counts.get('analyzed',0)} |",
          f"| **confirmed findings (accepted)** | **{gate['kept']}** |",
          f"| candidates dropped by engine | {counts.get('candidates_dropped',0)} |",
          f"| candidates suppressed by gate | {gate['suppressed']} |",
          f"| halted (scope/ROE) | {counts.get('halted',0)} |",
          f"| wall-clock | {scan_secs:.2f}s |\n",
          "## Confirmed findings\n"]
    if kept:
        L += ["| severity | effect | actor ▸ target | endpoint |", "|---|---|---|---|"]
        L += [f"| {f['severity']} | {f['effect']} | {f['actor']} ▸ {f['target']} | `{f['endpoint']}` |"
              for f in kept]
    else:
        L.append("_None confirmed after the discrimination gate — the engine produced no genuine "
                 "cross-account authorization break on the owner-scoped surface (raw candidates, if "
                 "any, were auth/dynamic-data artifacts and were suppressed)._")
    L += ["\n## OWASP API coverage (this engine's model)\n",
          "| class | covered | note |", "|---|---|---|",
          "| API1 BOLA / IDOR | ✅ | cross-principal object reads, Δstate-confirmed |",
          "| API3 property-level (mass-assign) | ✅ | tampered body on writes (--confirm) |",
          "| API5 BFLA | ✅ | function-scope endpoints (/admin,/internal…) |",
          "| API6 business-logic (payment/price/coupon/state) | ✅ | effect-tagged writes |",
          "| API8 injection, API4 rate-limit, API7 SSRF, API2 JWT-crypto | — | out of model; use a fuzzer/DAST |\n",
          "> Every ✅ finding is proven by reading the victim's state back — no 200-vs-403 guesses, "
          "and no auth-endpoint / shared-feed / dynamic-data artifacts."]
    open(os.path.join(out, "recon_performance.md"), "w", encoding="utf-8").write("\n".join(L))
    return os.path.join(out, "recon_report.md"), os.path.join(out, "recon_performance.md")


# --------------------------------------------------------------------------- #
# main                                                                         #
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(description="General authorized recon + ONYX hunt.")
    ap.add_argument("--authorized", action="store_true",
                    help="REQUIRED: you affirm you may test these hosts and all ids are in scope")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--openapi", help="OpenAPI/Swagger spec URL or file")
    ap.add_argument("--har", help="HAR capture file")
    ap.add_argument("--scope", help="comma-separated allowed hosts (default: the base host)")
    ap.add_argument("--principal", action="append", default=[],
                    help="PID:TOKEN (repeatable); or PID:email:password together with --login-url")
    ap.add_argument("--login-url",
                    help="login endpoint (URL or path) that takes {email,password} and returns a token; "
                         "lets you pass --principal PID:email:password instead of a raw token")
    ap.add_argument("--state",
                    help="path to a provisioner state.json (from hunt_crapi); auto-loads its two "
                         "accounts and logs them in, so you never type emails/passwords")
    ap.add_argument("--researcher", default="")
    ap.add_argument("--program", default="authorized engagement")
    ap.add_argument("--confirm", action="store_true", help="confirm write/business-logic bugs on ids you own")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--delay", default="", help="polite jitter seconds, e.g. 0.2,0.8")
    ap.add_argument("--out", default="./recon_out")
    args = ap.parse_args(argv)

    if not args.authorized:
        sys.exit("Refusing to run: pass --authorized to affirm you may test these hosts "
                 "and that every id is in scope and owned by your accounts.")
    if not (args.openapi or args.har):
        sys.exit("Give a surface source: --openapi <url|file> or --har <file>.")

    base_host = urlparse(args.base_url).hostname or ""
    scope = [h.strip() for h in (args.scope.split(",") if args.scope else [base_host]) if h.strip()]
    delay = (0.0, 0.0)
    if args.delay:
        try:
            xs = [float(x) for x in args.delay.split(",")]; delay = (xs[0], xs[-1])
        except ValueError:
            pass

    client = Client(scope, researcher=args.researcher, verify=not args.insecure, delay=delay)
    print(f"Scope-Guard: {', '.join(scope)}   ·   UA: {client.ua}")

    # principals: raw tokens, or email:password logged in via --login-url
    # --state: pull the provisioned accounts (from hunt_crapi) so no creds are typed
    if args.state:
        try:
            with open(args.state) as fh:
                accts = (json.load(fh).get("accounts") or {})
        except Exception as e:
            sys.exit(f"could not read --state {args.state}: {e}")
        if not args.login_url:
            sys.exit("--state needs --login-url so the loaded accounts can be logged in.")
        loaded = 0
        for pid in ("A", "B"):
            a = accts.get(pid) or {}
            if a.get("email") and a.get("password"):
                args.principal.append(f"{pid}:{a['email']}:{a['password']}"); loaded += 1
        if loaded < 2:
            sys.exit(f"--state {args.state} did not contain two usable accounts "
                     f"(run the provisioner first: ./run.sh --full --confirm --mailhog …).")
        print(f"· loaded {loaded} provisioned accounts from {args.state}")

    principals = {}
    for spec in args.principal:
        if ":" not in spec:
            sys.exit(f"bad --principal {spec!r}; use PID:TOKEN  (or PID:email:password with --login-url)")
        pid, val = spec.split(":", 1)
        pid = pid.strip(); val = val.strip()
        if args.login_url:
            if ":" not in val:
                sys.exit(f"--login-url set, so --principal must be PID:email:password (got {spec!r})")
            email, pw = val.split(":", 1)
            try:
                r = client.req("POST", args.login_url if "://" in args.login_url
                               else args.base_url.rstrip("/") + args.login_url,
                               json={"email": email.strip(), "password": pw.strip()})
                tok = None
                if r.status_code < 400:
                    d = r.json()
                    tok = d.get("token") or d.get("access_token") or d.get("accessToken") or d.get("jwt")
                if not tok:
                    sys.exit(f"login failed for principal {pid} ({email}): HTTP {r.status_code}")
                principals[pid] = tok
                print(f"· logged in {pid} ({email})")
            except SystemExit:
                raise
            except Exception as e:
                sys.exit(f"login error for {pid}: {type(e).__name__}: {e}")
        else:
            principals[pid] = val
    if len(principals) < 2:
        sys.exit("Cross-account testing needs at least two --principal (PID:TOKEN, "
                 "or PID:email:password with --login-url).")

    # ingest
    try:
        if args.openapi:
            doc = _load_doc(args.openapi, client); surface = ingest_openapi(doc); source = f"OpenAPI {args.openapi}"
        else:
            doc = _load_doc(args.har, client); surface = ingest_har(doc); source = f"HAR {args.har}"
    except PermissionError as e:
        sys.exit(f"Scope-Guard: {e}\n  Add the host to --scope only if you are authorized to test it.")
    except Exception as e:
        sys.exit(f"could not load the source: {e}")
    print(f"· ingested {len(surface)} endpoints from {source}")

    # harvest owned ids per principal (ownership requires disjoint per-principal sets)
    owned, pool, hreport = harvest(client, args.base_url, surface, principals)
    for res, pmap in owned.items():
        print(f"· owner-scoped {res.split('/')[-1] or res}: " + ", ".join(f"{pid}={v}" for pid, v in pmap.items()))
    if hreport["shared"]:
        print(f"· shared/public (no ownership, skipped): " +
              ", ".join(r.split('/')[-1] or r for r in hreport["shared"]))
    print("· owned id pool per principal: " + ", ".join(f"{pid}={len(v)}" for pid, v in pool.items()))

    # plan (auth/account/action endpoints already excluded by the gate)
    plan_eps = build_plan(surface, owned, pool, principals, args.confirm)
    if not plan_eps:
        print("\nNo cross-principal probes could be built. Ensure ≥2 principals own listable "
              "objects via an OWNER-SCOPED collection (each account must see different ids).")
    # seed provenance only from owner-scoped, probeable collections
    owner_scoped = set(hreport["owner_scoped"])
    collection_seeds = [(pid, "GET", e["path"])
                        for e in surface if e["method"] == "GET" and e["path"] in owner_scoped
                        for pid in principals]
    cfg = {
        "base_url": args.base_url, "authorized": True, "dry_run": not args.confirm,
        "researcher": args.researcher, "program": args.program,
        "principals": {pid: {"value": tok, "type": "bearer"} for pid, tok in principals.items()},
        "endpoints": plan_eps,
        "seeds": collection_seeds,
        "test_resources": sorted({i for e in plan_eps for v in e["ids"].values() for i in v}),
        "engagement_id": "recon",
    }

    from authpath.serve import _build_scan, ScanError
    t0 = time.perf_counter()
    try:
        engine, _tl = _build_scan(cfg)
    except ScanError as e:
        sys.exit(f"scan setup error: {e}")
    scan_secs = time.perf_counter() - t0

    snap = engine.snapshot()

    # ---- structural + BEHAVIORAL output guard (defense in depth) ----
    # We do NOT second-guess the engine's confirmed EFFECT by name — that would drop
    # genuine classes (e.g. TEMPORAL_DRIFT = stale-auth). Inputs are already clean
    # (no revocation-poisoning probes, no JWT/message ids, per-id ownership), so we
    # trust the engine's Δstate verdict and only guard structurally. The BEHAVIORAL
    # requirement — the finding's target must be an id we actually HARVESTED from a
    # real owner-scoped collection (not a value merely shaped like an id) — is a pure
    # tightening: it can only remove noise, never add it. It is FP-safe by construction.
    owned_union = {str(i) for v in pool.values() for i in v}
    probed_ids = {str(i) for e in plan_eps for v in e.get("ids", {}).values() for i in v}
    grounded = owned_union | probed_ids     # every id that came from a real resource / probe

    def _accept(fd):
        tgt = str(fd.get("target", ""))
        return (_is_probeable(str(fd.get("endpoint", ""))) and _looks_like_id(fd.get("target", ""))
                and (tgt in grounded))
    raw = snap["findings"]
    gate_kept = [fd for fd in raw if _accept(fd)]
    suppressed = [fd for fd in raw if not _accept(fd)]

    # ---- Independent Adversarial Re-Confirmation (IARC): a second, engine-independent
    #      Δstate check every read finding must survive. Drops ONLY on positive evidence
    #      of a false positive (public / server-ignores-id / non-reproducible); otherwise
    #      keeps — so power is never reduced, only precision raised. ----
    ep_meta = _ep_meta(plan_eps)
    kept, iarc_dropped = [], {}
    for fd in gate_kept:
        ok, why = reconfirm(client, args.base_url, principals, pool, fd, ep_meta)
        if ok:
            kept.append(fd)
        else:
            iarc_dropped[why] = iarc_dropped.get(why, 0) + 1

    kept_fids = {fd["fid"] for fd in kept}
    engine_kept = [f for f in engine.findings if getattr(f, "fid", None) in kept_fids]
    gate = {"raw": len(raw), "kept": len(kept),
            "suppressed": len(suppressed) + (len(gate_kept) - len(kept)), "reasons": {}}
    for fd in suppressed:
        why = ("auth/revocation endpoint" if not _is_probeable(str(fd.get("endpoint", "")))
               else "non-object-id target" if not _looks_like_id(fd.get("target", ""))
               else "target not a harvested owned id")
        gate["reasons"][why] = gate["reasons"].get(why, 0) + 1
    for why, n in iarc_dropped.items():
        gate["reasons"]["IARC: " + why] = n

    print("\n" + "=" * 60)
    print(f"  recon hunt — {len(kept)} confirmed (gate + independent re-confirmation) / "
          f"{len(raw)} raw / {snap['counts'].get('analyzed',0)} probes / {scan_secs:.2f}s")
    print("=" * 60)
    for f in kept:
        print(f"  [{f['severity']:<8}] {f['effect']:<14} {f['actor']} ▸ {f['target']}  {f['endpoint']}")
    total_supp = gate["suppressed"]
    if total_supp:
        print(f"  ({total_supp} candidate(s) suppressed: "
              + ", ".join(f"{k} ×{v}" for k, v in gate['reasons'].items()) + ")")

    meta = {"base_url": args.base_url, "scope": scope, "source": source,
            "researcher": args.researcher, "program": args.program,
            "when": time.strftime("%Y-%m-%d %H:%M:%S"), "confirm": args.confirm}
    rep, perf = write_reports(engine_kept, kept, args.out, meta=meta, surface=surface, owned=owned,
                              hreport=hreport, gate=gate,
                              plan_eps=plan_eps, recon_http={"n": client.n, "latencies": client.latencies},
                              scan_secs=scan_secs, counts=snap["counts"])
    print(f"\n  Vulnerability report : {rep}")
    print(f"  Coverage/performance : {perf}")
    print("\n  Only test targets whose program authorizes it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
