"""
HAR → ONYX spec converter (improvement #1).

The single biggest practical barrier to using ONYX on a real target was the
hour of hand-authoring a spec.json.  This module removes it: capture traffic in
Burp / browser DevTools / mitmproxy, export HAR, and convert.

The hard problem here is NOT parsing — it is PRINCIPAL ATTRIBUTION: a capture
mixes requests from several logged-in sessions.  We attribute each request to a
principal by its *credential fingerprint* (Authorization bearer subject, or the
session cookie), so two requests carrying the same identity collapse to one
principal automatically.

Design decisions:
  * We do NOT try to label seed-vs-probe. Every request is emitted as an
    observation/probe; the engine decides what is laundered. That is the whole
    point of ONYX — we never pre-judge.
  * Out-of-scope hosts (CDNs, analytics, third parties) are filtered, mirroring
    the Scope-Guard's allow-list philosophy (fail-safe to exclusion).
  * GraphQL bodies are preserved verbatim (the adapter handles them downstream).
  * SECURITY: real credentials are needed to REPLAY, so principal headers keep
    them — but the exported spec's PoC-facing fields use `$TOKEN_<pid>`
    placeholders. Never commit a spec with live tokens.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qs


# SENTINEL S1: per-exchange analysis failures on a real capture are collected here
# (path, error) so the run reports HONEST coverage rather than dying or hiding gaps.
_ANALYZE_ERRORS: list = []


# --------------------------------------------------------------------------- #
# Credential fingerprinting → principal identity                              #
# --------------------------------------------------------------------------- #
def _header(headers: list[dict], name: str) -> str | None:
    for h in headers or []:
        if h.get("name", "").lower() == name.lower():
            return h.get("value")
    return None


# OBSTACLE-1: header taxonomy. SECRET = identity-bearing (redacted); DROP =
# transport-managed (must NOT be replayed verbatim); everything else is the
# coherent browser PROFILE that we preserve so replayed requests look real.
_SECRET_HEADERS = ("authorization", "cookie", "x-csrf-token", "x-xsrf-token",
                   "x-api-key", "x-auth-token", "x-access-token", "x-session-token")
_DROP_HEADERS = ("host", "content-length", "connection", "transfer-encoding",
                 "content-encoding", "accept-encoding", "keep-alive", "te",
                 "upgrade", "proxy-authorization", ":authority", ":method",
                 ":path", ":scheme")

# Per-REQUEST contextual headers: their correct value depends on the specific
# request (navigation context, referring page). They must travel with the request
# being replayed, NEVER be frozen into a principal-level profile (attack #4).
_CONTEXTUAL_HEADERS = ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
                       "sec-fetch-user", "referer", "origin")

def _is_secret_header(name: str) -> bool:
    n = name.lower()
    if n in _SECRET_HEADERS:
        return True
    return any(k in n for k in ("token", "secret", "apikey", "api-key", "session", "csrf", "auth"))

def _profile_from_headers(headers: list[dict]) -> dict:
    """STABLE, non-secret browser headers (UA / Accept / sec-ch-ua ...) that are
    identical across a principal's requests. Insertion order = capture order
    (true on-wire ordering is the transport layer's job — obstacle 6)."""
    out = {}
    for hh in headers or []:
        name = hh.get("name", "")
        if not name or name.startswith(":"):
            continue
        ln = name.lower()
        if ln in _DROP_HEADERS or _is_secret_header(name) or ln in _CONTEXTUAL_HEADERS:
            continue
        out[name] = hh.get("value", "")
    return out

def _contextual_from_headers(headers: list[dict]) -> dict:
    """Per-request contextual headers, carried with the specific request so a
    replay never reuses a stale Referer / Sec-Fetch from another request (#4)."""
    out = {}
    for hh in headers or []:
        name = hh.get("name", "")
        if name and name.lower() in _CONTEXTUAL_HEADERS:
            out[name] = hh.get("value", "")
    return out

def _redact_cookie(cookie: str, pid: str) -> str:
    """Per-cookie redaction (attack #3): keep coherence cookies (analytics, locale)
    and cookie SHAPE verbatim; redact only the values of identity/CSRF cookies, so
    the replayed Cookie header stays structurally real and functional cookies (csrf)
    are visibly required rather than silently dropped."""
    if not cookie:
        return cookie
    secret_names = ("session", "sess", "sid", "auth", "token", "jwt", "csrf",
                    "xsrf", "_session", "connect.sid", "remember", "access")
    parts = []
    for seg in cookie.split(";"):
        seg = seg.strip()
        if not seg or "=" not in seg:
            parts.append(seg); continue
        k, _, v = seg.partition("=")
        kl = k.strip().lower()
        if any(sn in kl for sn in secret_names):
            parts.append(f"{k}=$COOKIE_{pid}_{k.strip()}")
        else:
            parts.append(seg)                 # coherence cookie: keep verbatim
    return "; ".join(parts)


def _principal_fingerprint(headers: list[dict]) -> tuple[str, dict]:
    """Return (fingerprint, identity_meta). The fingerprint groups requests that
    share an identity. Prefer JWT subject (stable + meaningful); fall back to the
    raw bearer/cookie value."""
    auth = _header(headers, "authorization")
    if auth:
        from .provenance import inspect_jwt
        jwt = inspect_jwt(auth)
        if jwt and jwt.identity_claims:
            sub = (jwt.identity_claims.get("sub")
                   or next(iter(jwt.identity_claims.values())))
            meta = {"via": "jwt", "claims": jwt.identity_claims,
                    "alg": jwt.alg, "none_alg": jwt.none_alg,
                    "empty_sig": jwt.empty_signature}
            return f"jwt:{sub}", meta
        # opaque bearer — fingerprint by a short stable suffix
        return f"bearer:{auth[-12:]}", {"via": "bearer"}
    cookie = _header(headers, "cookie")
    if cookie:
        # use the session-ish cookie value as fingerprint
        return f"cookie:{cookie[:40]}", {"via": "cookie"}
    return "anon", {"via": "anonymous"}


@dataclass
class ImportResult:
    base_url: str
    principals: dict           # pid -> {role, headers, identity}
    requests: list             # [{principal, method, path, query, body, host}]
    pairs: list                # auto-detected high-value cross-principal object pairs
    skipped_hosts: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def parse_har(har: dict, in_scope_hosts: list[str] | None = None) -> ImportResult:
    """Convert a parsed HAR document into an ImportResult.

    in_scope_hosts: when given, only requests to these hosts are kept. When
    omitted, the most frequent host in the capture is assumed in-scope (and the
    rest reported under skipped_hosts for the operator to review)."""
    entries = (har.get("log") or {}).get("entries") or []
    host_counts: dict[str, int] = {}
    parsed: list[dict] = []

    for e in entries:
        req = e.get("request") or {}
        url = req.get("url") or ""
        method = (req.get("method") or "GET").upper()
        u = urlparse(url)
        host = u.netloc.split("@")[-1]
        host_counts[host] = host_counts.get(host, 0) + 1
        headers = req.get("headers") or []
        fp, meta = _principal_fingerprint(headers)
        _prof = _profile_from_headers(headers)
        _ctx = _contextual_from_headers(headers)
        body = _extract_body(req)
        parsed.append({
            "host": host, "method": method, "path": u.path or "/",
            "query": {k: (v if len(v) > 1 else (v[0] if v else ""))
                      for k, v in parse_qs(u.query, keep_blank_values=True).items()},
            "body": body, "fp": fp, "meta": meta,
            "auth": _header(headers, "authorization"),
            "cookie": _header(headers, "cookie"),
            "profile": _prof,
            "ctx": _ctx,
            "resp_status": (e.get("response") or {}).get("status", 0),
        })

    # scope decision
    if not in_scope_hosts:
        in_scope_hosts = [max(host_counts, key=host_counts.get)] if host_counts else []
    scope_set = set(in_scope_hosts)
    skipped = {h: c for h, c in host_counts.items() if h not in scope_set}
    kept = [p for p in parsed if p["host"] in scope_set]

    # assign stable principal ids by first-seen order of fingerprint
    fp_to_pid: dict[str, str] = {}
    principals: dict[str, dict] = {}
    next_letter = ord("A")
    for p in kept:
        fp = p["fp"]
        if fp not in fp_to_pid:
            if fp == "anon":
                pid = "anon"
            else:
                pid = chr(next_letter); next_letter += 1
            fp_to_pid[fp] = pid
            principals[pid] = {
                "role": "user" if pid != "anon" else "anonymous",
                "headers": _auth_headers(p),
                "identity": p["meta"],
                "profile": p.get("profile", {}),   # OBSTACLE-1: coherent browser headers
                "anonymous": pid == "anon",
            }
        p["principal"] = fp_to_pid[fp]

    requests = [{
        "principal": p["principal"], "method": p["method"], "path": p["path"],
        "query": p["query"], "body": p["body"], "host": p["host"],
        "ctx": p.get("ctx", {}),
    } for p in kept]

    pairs = _detect_object_pairs(kept, fp_to_pid)
    base = f"https://{in_scope_hosts[0]}" if in_scope_hosts else ""

    notes = []
    none_alg = [pid for pid, m in principals.items() if m["identity"].get("none_alg")]
    if none_alg:
        notes.append(f"JWT alg=none detected for principals {none_alg} — "
                     f"possible signature-bypass; verify server enforcement.")
    return ImportResult(base, principals, requests, pairs, skipped, notes)


def _auth_headers(p: dict) -> dict:
    h = {}
    if p.get("auth"):
        h["Authorization"] = p["auth"]
    if p.get("cookie"):
        h["Cookie"] = p["cookie"]
    return h


def _extract_body(req: dict) -> Any:
    pd = req.get("postData") or {}
    text = pd.get("text")
    if not text:
        return None
    mime = (pd.get("mimeType") or "").lower()
    if "json" in mime or text.strip().startswith(("{", "[")):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return text


def _object_ids_of(p: dict) -> set[str]:
    """Reuse the engine's own carrier extraction so HAR-side pairing matches
    what the engine will later compute (path/query/headers/JWT/GraphQL vars)."""
    from .models import HTTPRequest
    r = HTTPRequest(p["method"], p["path"], host=p["host"],
                    headers=_auth_headers(p), query=p.get("query") or {},
                    body=p.get("body"))
    try:
        return set(r.object_ids())
    except Exception:
        return set()


def _detect_object_pairs(kept: list[dict], fp_to_pid: dict) -> list[dict]:
    """Auto-detect high-value probes (improvement #1, rÿ#4): the same object-id
    touched by more than one principal is a prime IDOR/BFLA candidate. We
    surface these so the operator knows where the engine will focus."""
    by_obj: dict[str, set[str]] = {}
    sample: dict[str, dict] = {}
    for p in kept:
        pid = p["principal"]
        for oid in _object_ids_of(p):
            by_obj.setdefault(oid, set()).add(pid)
            sample.setdefault(f"{oid}|{pid}", p)
    pairs = []
    for oid, pids in by_obj.items():
        if len(pids) > 1:
            pairs.append({"object_id": oid, "principals": sorted(pids),
                          "note": "same object touched by multiple principals — "
                                  "prime cross-principal access candidate"})
    return pairs


# --------------------------------------------------------------------------- #
# Spec emission                                                                #
# --------------------------------------------------------------------------- #
def to_spec(result: ImportResult, redact: bool = True) -> dict:
    """Emit an ONYX spec.json. When redact=True (default), live credentials in
    principal headers are replaced by `$TOKEN_<pid>` placeholders so the file is
    safe to share/commit. Replace them with real values (or env vars) at run."""
    principals = {}
    for pid, meta in result.principals.items():
        headers = dict(meta["headers"])
        if redact:
            if "Authorization" in headers:
                headers["Authorization"] = f"Bearer $TOKEN_{pid}"
            if "Cookie" in headers:
                headers["Cookie"] = _redact_cookie(headers["Cookie"], pid)
        principals[pid] = {"role": meta["role"], "headers": headers,
                           "profile_headers": meta.get("profile", {}),
                           **({"anonymous": True} if meta.get("anonymous") else {})}
    # every captured request becomes a probe; the engine decides laundering.
    probe = [{"principal": r["principal"], "method": r["method"], "path": r["path"],
              **({"query": r["query"]} if r["query"] else {}),
              **({"body": r["body"]} if r["body"] is not None else {}),
              **({"headers": r["ctx"]} if r.get("ctx") else {})}
             for r in result.requests]
    spec = {
        "base_url": result.base_url,
        "scope": {"dry_run": True, "automation_permitted": False,
                  "_comment": "set automation_permitted=true ONLY if the program "
                              "rules allow automated testing; set dry_run=false to act"},
        "principals": principals,
        "seed": [],
        "probe": probe,
        "_auto_detected_pairs": result.pairs,
        "_notes": result.notes,
    }
    return spec


# --------------------------------------------------------------------------- #
# Offline analysis bridge: HAR -> Exchanges -> a fully-driven engine          #
# --------------------------------------------------------------------------- #

def _extract_response_body(entry: dict):
    resp = entry.get("response") or {}
    content = resp.get("content") or {}
    text = content.get("text")
    if not text:
        return None
    if (content.get("encoding") or "").lower() == "base64":
        import base64
        try:
            text = base64.b64decode(text).decode("utf-8", "replace")
        except Exception:
            return None
    mime = (content.get("mimeType") or "").lower()
    if "json" in mime or text.strip()[:1] in ("{", "["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return text


def parse_har_exchanges(har: dict, in_scope_hosts: list[str] | None = None):
    """Build (principals, [Exchange]) from a HAR capture, PRESERVING the captured
    response bodies — the substrate for fully-offline analysis. Principal
    attribution mirrors parse_har exactly (credential-fingerprint, first-seen pid)
    so ids are stable and consistent."""
    from .models import Exchange, HTTPRequest, HTTPResponse, Principal

    entries = (har.get("log") or {}).get("entries") or []
    rows, host_counts = [], {}
    for e in entries:
        req = e.get("request") or {}
        u = urlparse(req.get("url") or "")
        host = u.netloc.split("@")[-1]
        host_counts[host] = host_counts.get(host, 0) + 1
        rows.append((e, req, u, host))
    if not in_scope_hosts:
        in_scope_hosts = [max(host_counts, key=host_counts.get)] if host_counts else []
    scope = set(in_scope_hosts)

    fp_to_pid: dict[str, str] = {}
    principals: dict[str, Principal] = {}
    nxt = ord("A")
    exchanges = []
    for e, req, u, host in rows:
        if host not in scope:
            continue
        headers = req.get("headers") or []
        fp, _meta = _principal_fingerprint(headers)
        _prof = _profile_from_headers(headers)
        if fp not in fp_to_pid:
            pid = "anon" if fp == "anon" else chr(nxt)
            if fp != "anon":
                nxt += 1
            fp_to_pid[fp] = pid
            auth = {}
            a, c = _header(headers, "authorization"), _header(headers, "cookie")
            if a:
                auth["Authorization"] = a
            if c:
                auth["Cookie"] = c
            principals[pid] = Principal(
                pid, f"{'anonymous' if pid == 'anon' else 'user'} (from capture)",
                auth=auth, is_anonymous=(pid == "anon"),
                profile_headers=_prof)
        pid = fp_to_pid[fp]
        _ctx = _contextual_from_headers(headers)
        hreq = HTTPRequest(
            (req.get("method") or "GET").upper(), u.path or "/",
            query={k: (v if len(v) > 1 else (v[0] if v else ""))
                   for k, v in parse_qs(u.query, keep_blank_values=True).items()},
            headers={**principals[pid].auth, **_ctx},   # auth + per-request context
            body=_extract_body(req), host=host)
        resp = e.get("response") or {}
        hresp = HTTPResponse(resp.get("status", 0) or 0, _extract_response_body(e))
        exchanges.append(Exchange(hreq, hresp, principals[pid]))
    return principals, exchanges


def ingest_har(har: dict, scope, in_scope_hosts: list[str] | None = None,
               provisional: bool = True):
    """Analyse a HAR capture FULLY OFFLINE — HONESTLY.

    EPISTEMIC FIX (defects #1/#3): a passive capture cannot DISTINGUISH "B owns 42"
    from "B did an IDOR on 42" — the observation is identical. Therefore offline
    mode is forbidden from emitting an object-access FINDING. It builds the
    measured self-envelope for ranking context, then emits a ranked
    CROSS_PRINCIPAL_OBJECT lead for every object touched by >=2 distinct
    credentials (a measured FACT, not an inference), after suppressing the cases
    that are provably benign by a LANGUAGE-FREE structural test (defect #4):
      * public: every observed principal (incl. anon) receives the object, OR
      * shared: the object's own body lists members and the actor id is among them.
    Confirmation (a real owner read-back) only exists live (the scan path), so a
    finding is structurally impossible here — which is exactly correct (RL5)."""
    from .engine import AuthPathEngine
    from .transport import ReplayTarget
    from .intrinsic import Lead, Confidence

    principals, exchanges = parse_har_exchanges(har, in_scope_hosts)
    target = ReplayTarget(exchanges)
    engine = AuthPathEngine(target, principals, scope, contract=None)
    engine.provisional_leads = provisional
    engine.offline = True                       # HARD GATE: no object-access findings

    # pass 1 — grammars (structural leads still work, they are reference-free)
    for ex in exchanges:
        engine.ingest_grammar(ex)
    # pass 2 — the reference-free / structural lead pipeline (no object-access finding)
    for ex in exchanges:
        # SENTINEL S1: isolate per-exchange analysis on real captures — a single
        # malformed exchange records a visible diagnostic and is skipped, never
        # aborts the whole capture.
        try:
            engine.analyze(ex)
        except Exception as exc:               # noqa: BLE001
            engine._pass_errors += 1
            _ANALYZE_ERRORS.append((getattr(ex.request, "path", "?"),
                                    f"{type(exc).__name__}: {str(exc)[:160]}"))

    # pass 3 — the relational object lead: object id -> {pid: (sample_ex, body)}
    obj_to: dict[str, dict] = {}
    for ex in exchanges:
        if not (200 <= ex.response.status < 300):
            continue
        try:
            oids = ex.request.object_ids()
        except Exception:
            oids = []
        for oid in oids:
            obj_to.setdefault(str(oid), {}).setdefault(ex.principal.pid, (ex, ex.response.body))

    emitted = set()
    for oid, per_pid in obj_to.items():
        if len(per_pid) < 2:
            continue                            # one credential => no cross-principal fact
        if _benign_object(oid, per_pid, principals):
            continue                            # public / member-shared => suppress (neutral)
        pids = sorted(per_pid)
        key = ("xprin", oid, tuple(pids))
        if key in emitted:
            continue
        emitted.add(key)
        any_ex = per_pid[pids[0]][0]
        engine.leads.append(("offline", Lead(
            kind="CROSS_PRINCIPAL_OBJECT", family=any_ex.request.endpoint_key(),
            principal=pids[0], paths=[f"{any_ex.request.path}#{oid}"],
            weight=8 + len(pids),
            confidence=Confidence.STRONG_LEAD, confirmable=True,
            rationale=(f"object id '{oid}' on {any_ex.request.endpoint_key()} was "
                       f"returned (2xx) to {len(pids)} DISTINCT credentials {pids} and "
                       f"is not provably public or member-shared — a measured "
                       f"cross-principal access fact. Whether it is an IDOR or "
                       f"legitimate co-ownership cannot be decided from a passive "
                       f"capture; confirm with an owner read-back."),
            suggested_probe=(f"as each of {pids}, re-read {any_ex.request.path} and, as a "
                             f"third principal that should NOT hold {oid}, attempt the "
                             f"same read; a 2xx with the owner's substantive fields is a "
                             f"confirmed BOLA (run `authpath scan`)."),
            evidence={"object_id": oid, "principals": pids})))
    return engine


def _benign_object(oid: str, per_pid: dict, principals) -> bool:
    """Language-free suppression of provably-legitimate cross-principal access.
    Reads only structural facts + value-equality of the actor's OWN id against a
    membership list the object itself publishes. No dictionary, no English."""
    pids = set(per_pid)
    # (a) PUBLIC: only an ANONYMOUS (unauthenticated) read proves the object is not
    #     behind per-principal ownership. The old "every known principal accessed
    #     it" clause was UNSOUND: in a 2-principal capture (victim + attacker) that
    #     condition IS the IDOR signature, not publicness. Removed (defect-in-fix).
    if "anon" in pids:
        return True
    # (b) MEMBER-SHARED: the object body lists members/owners and EVERY accessing
    #     principal's identity appears in that list. We match the principal's own
    #     credential identity (sub/cookie) values, deterministically.
    member_lists = []
    for pid, (_ex, body) in per_pid.items():
        for ml in _collect_member_values(body):
            member_lists.append((pid, set(map(str, ml))))
    if member_lists:
        # build the set of identity tokens each principal is known by
        def idents(pid):
            p = principals.get(pid)
            toks = {pid}
            if p is not None:
                for v in (p.auth or {}).values():
                    toks.add(str(v))
                    if isinstance(v, str) and "." in v:
                        from .provenance import inspect_jwt
                        j = inspect_jwt(v)
                        if j:
                            toks |= {str(x) for x in j.identity_claims.values()}
            return toks
        all_members = set().union(*[m for _, m in member_lists]) if member_lists else set()
        if all_members and all(idents(pid) & all_members for pid in pids):
            return True
    return False


def _collect_member_values(body):
    """Yield every list-of-scalars that plausibly enumerates membership/ownership,
    selected STRUCTURALLY (a list of scalar ids) — not by field name."""
    out = []
    def walk(n):
        if isinstance(n, dict):
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            scal = [x for x in n if isinstance(x, (str, int))]
            if scal and len(scal) == len(n):
                out.append(scal)
            for v in n:
                walk(v)
    walk(body if isinstance(body, (dict, list)) else {})
    return out
