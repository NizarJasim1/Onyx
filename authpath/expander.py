"""
Surface expander (deficiency #2 — spec-consumer, not surface-discoverer).
================================================================================
ONYX tested only the documented/observed surface, capping it at the operator's recon.
The commodity fix — blind dictionary fuzzing — is the wrong move for THIS tool: it is
noise (trips the defensive adversary, #6), it risks scope violations (#9), and it bolts a
probabilistic "does this exist?" guessing layer onto a deterministic zero-FP engine.

The root move: don't FUZZ, HARVEST. Every endpoint ONYX adds is grounded in a reference
the TARGET ITSELF emitted — a link in a body, a path in its own JavaScript, a version
sibling of a real path. That keeps discovery deterministic (RL1), quiet (no wordlist),
and FP-safe: discovery only FEEDS the detection pipeline, and the confirmer still requires
a proven Δstate, so a discovered endpoint that is not actually vulnerable yields no
finding. Discovery therefore cannot add a false positive.

Every candidate is TIER-TAGGED by provenance so a reviewer sees exactly why ONYX believes
an endpoint exists:  observed < spec < referenced < lineage < js.

Declared boundary: an endpoint the target references NOWHERE and ships in no spec/JS is
findable only by blind fuzzing — out of scope on purpose (noise + non-determinism), not by
laziness. ONYX discovers the referenced+derivable fraction, which is where a mature
target's own disclosures already leak most of its real surface.
"""
from __future__ import annotations
from dataclasses import dataclass
import re

_URL = re.compile(r"""https?://[^\s"'<>]+|(?<![\w])/(?:api|v\d|graphql|internal|admin|rest)[^\s"'<>]*""", re.I)
_JS_PATH = re.compile(r"""["'`](/(?:api|v\d|internal|admin|rest|graphql)/[A-Za-z0-9_\-/{}.:]+)["'`]""", re.I)
_VERSION = re.compile(r"/v(\d+)(/|$)")
_ID_KEY = re.compile(r"^([a-z0-9_]+?)_(id|uuid|key|ref|guid)$", re.I)


@dataclass
class Candidate:
    path: str
    method: str = "GET"
    tier: str = "referenced"          # observed|spec|referenced|lineage|js
    why: str = ""

    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


def _norm_path(u: str) -> str:
    """Reduce a URL/path to a path, stripping scheme+host and the query string."""
    u = u.strip().strip('.,;')
    if u.startswith("http"):
        m = re.match(r"https?://[^/]+(/.*)", u)
        u = m.group(1) if m else ""
    return u.split("?")[0].split("#")[0] if u.startswith("/") else ""


def harvest_references(body, tier: str = "referenced") -> list:
    """Endpoints the server DISCLOSED in a response: absolute/relative URLs, HATEOAS _links,
    and nested id-bearing fields (foo_id -> a probable /foo/{id} resource). Grounded, not
    guessed."""
    out, seen = [], set()

    def add(path, why):
        p = _norm_path(path)
        if p and p not in seen:
            seen.add(p); out.append(Candidate(path=p, tier=tier, why=why))

    def walk(node, keypath=""):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("href", "url", "link", "self", "next", "related") and isinstance(v, str):
                    add(v, f"link field '{k}'")
                if k == "_links" and isinstance(v, dict):
                    for _, lv in v.items():
                        href = lv.get("href") if isinstance(lv, dict) else lv
                        if isinstance(href, str):
                            add(href, "HATEOAS _links")
                m = _ID_KEY.match(k) if isinstance(k, str) else None
                if m and isinstance(v, (str, int)):
                    res = m.group(1)
                    add(f"/{res}s/{v}", f"nested ref '{k}'")     # foo_id -> /foos/{v}
                walk(v, f"{keypath}.{k}")
        elif isinstance(node, list):
            for it in node:
                walk(it, keypath)
        elif isinstance(node, str):
            for u in _URL.findall(node):
                add(u, "url in body")
    walk(body)
    return out


def derive_lineage(path: str) -> list:
    """Deterministic version-downgrade siblings of a REAL observed path: /api/v2/x ->
    /api/v1/x, /api/v0/x, /api/internal/x, /api/legacy/x. Version downgrade is a classic
    IDOR/BFLA vector (an old version often skips a new auth check)."""
    out = []
    m = _VERSION.search(path)
    if m:
        cur = int(m.group(1))
        for lower in range(cur - 1, -1, -1):
            out.append(Candidate(path=_VERSION.sub(f"/v{lower}\\2", path, count=1),
                                 tier="lineage", why=f"version downgrade v{cur}->v{lower}"))
    for word in ("internal", "legacy", "beta", "admin"):
        if f"/{word}/" not in path:
            # insert the lineage segment after the first /api or leading segment
            cand = re.sub(r"(/api)?/", rf"\1/{word}/", path, count=1)
            if cand != path:
                out.append(Candidate(path=cand, tier="lineage", why=f"lineage sibling '{word}'"))
    # de-dup
    seen, uniq = set(), []
    for c in out:
        if c.path not in seen:
            seen.add(c.path); uniq.append(c)
    return uniq


def extract_from_js(js_text: str) -> list:
    """API paths a served JS bundle calls — real endpoints the frontend uses, often
    undocumented in the public spec."""
    out, seen = [], set()
    for m in _JS_PATH.findall(js_text or ""):
        p = _norm_path(m)
        if p and p not in seen:
            seen.add(p); out.append(Candidate(path=p, tier="js", why="path literal in JS bundle"))
    return out


def mine_params(body) -> set:
    """Field names present in a body — candidate params/fields for mass-assignment / EDE
    probing that the spec may not list. Returns bare field names."""
    fields = set()

    def walk(n):
        if isinstance(n, dict):
            for k, v in n.items():
                if isinstance(k, str):
                    fields.add(k)
                walk(v)
        elif isinstance(n, list):
            for it in n:
                walk(it)
    walk(body)
    return fields


class SurfaceExpander:
    """Aggregates evidence-grounded candidates from bodies, JS, and version lineage, and
    yields only those NOT already in the observed set — tier-tagged, deduplicated."""

    def __init__(self):
        self._cands: dict = {}     # key -> Candidate (highest-confidence tier kept)
        self.params: set = set()

    _TIER_RANK = {"observed": 0, "spec": 1, "referenced": 2, "lineage": 3, "js": 2}

    def _add(self, c: Candidate):
        prev = self._cands.get(c.key())
        if prev is None or self._TIER_RANK.get(c.tier, 3) < self._TIER_RANK.get(prev.tier, 3):
            self._cands[c.key()] = c

    def feed_body(self, body):
        for c in harvest_references(body):
            self._add(c)
        self.params |= mine_params(body)

    def feed_js(self, js_text):
        for c in extract_from_js(js_text):
            self._add(c)

    def feed_lineage(self, observed_paths):
        for p in observed_paths:
            for c in derive_lineage(p):
                self._add(c)

    def new_endpoints(self, observed_keys: set) -> list:
        """Tier-tagged candidates not already observed, sorted for determinism."""
        return sorted((c for k, c in self._cands.items() if k not in observed_keys),
                      key=lambda c: (self._TIER_RANK.get(c.tier, 9), c.key()))
