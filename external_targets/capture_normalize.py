#!/usr/bin/env python3
"""
capture_normalize.py — EVIDENCE-BASED path templatization (a strict upgrade, zero-FP-safe).

The one remaining wart: the base-recon surface is built by templatize_path, which only collapses
NUMERIC / UUID id segments. A non-numeric object id (e.g. 'rec-101', 'inv-B-22') stays concrete,
so an ITEM path like /api/recs/rec-101 is mistaken for a COLLECTION — harvest reads it as every
principal, the object looks 'shared', and base-recon never probes that item family. That never
caused a false positive (shared → dropped), but it is a completeness gap: base-recon can miss a
plain BOLA on a non-numeric id (L4-X still catches it only when a refusal/leak exists).

THE GENIUS, SAFE FIX — templatize by EVIDENCE, not by shape:
  A path segment is an object id **iff the capture actually shows that exact value as an object's
  `id` (or `*_id`) field in a real response** — and it is id-shaped (carries a digit / dash /
  underscore or is a UUID), so a plain collection noun like 'orders' is never collapsed.
  This is measured, not guessed ("لا حكم بالحدس") — so it is MORE accurate than a numeric regex,
  and it cannot add a false positive: it only reshapes the SURFACE map. Every probe still runs
  through the untouched engine + IARC + the ownership gate, which decide the verdict.

Isolated: proven code (onyx_recon, sitemodel, the engine) is untouched, so selftest_recon's
18/0 baseline is unaffected. Only the Conductor's base-recon surface is built from here.
"""
from __future__ import annotations
import re, json
from urllib.parse import urlparse, parse_qs

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _id_shaped(seg: str) -> bool:
    """A value that could be an object id: numeric, UUID, or a token bearing a digit / dash /
    underscore. A bare alphabetic word (a collection noun like 'orders') is NOT id-shaped, so it
    is never collapsed to {id}."""
    if not seg:
        return False
    if seg.isdigit() or _UUID.match(seg):
        return True
    return (any(c.isdigit() for c in seg) or "-" in seg or "_" in seg) and not seg.isalpha()


def _body(raw):
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except ValueError:
            return None
    return None


def known_object_ids(har) -> set:
    """Every value the capture presents as an object's id (`id` or `*_id`/`*Id`) in a 2xx body.
    This is the EVIDENCE that a value denotes an object — not a guess from its characters."""
    ids = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                kl = k.lower()
                if (kl == "id" or kl.endswith("_id") or kl.endswith("id")) and isinstance(v, (str, int)):
                    s = str(v)
                    if _id_shaped(s):
                        ids.add(s)
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    for e in ((har or {}).get("log") or {}).get("entries") or []:
        resp = e.get("response") or {}
        status = resp.get("status", 0)
        if 200 <= status < 300:
            walk(_body((resp.get("content") or {}).get("text")))
    return ids


def evidence_templatize(path: str, known_ids: set) -> str:
    """Replace a path segment with {id} iff it is numeric/UUID OR an id-shaped value the capture
    proved is an object id. Collection nouns are preserved."""
    out = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg); continue
        if seg.isdigit() or _UUID.match(seg) or (seg in known_ids and _id_shaped(seg)):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out)


def _query_id(qs: dict):
    for k in qs:
        kl = k.lower()
        if kl == "id" or kl.endswith("_id") or kl.endswith("id"):
            return k
    return None


def normalized_surface(har, known_ids=None) -> list:
    """Build the base-recon surface from the capture with EVIDENCE-BASED templatization.
    Returns the same endpoint-dict shape onyx_recon.ingest_har produces, deduped by
    (method, templatized-path, query_id). A full replacement for ingest_har on the Conductor
    path: it collapses numeric AND evidence-proven non-numeric item ids to {id}, so item
    families are probeable and true collections stay collections."""
    known_ids = known_object_ids(har) if known_ids is None else known_ids
    seen = {}
    for e in ((har or {}).get("log") or {}).get("entries") or []:
        req = e.get("request") or {}
        method = (req.get("method") or "GET").upper()
        u = urlparse(req.get("url", ""))
        tmpl = evidence_templatize(u.path, known_ids)
        qs = parse_qs(u.query)
        qid = _query_id(qs)
        body = _body((req.get("postData") or {}).get("text")) if req.get("postData") else {}
        key = (method, tmpl, qid)
        if key in seen:
            continue
        seen[key] = {"method": method, "path": tmpl, "params": [], "other_params": [],
                     "query_id": qid, "body": body if isinstance(body, dict) else {},
                     "multi_param": tmpl.count("{id}") > 1}
    return list(seen.values())
