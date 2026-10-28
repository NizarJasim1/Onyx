"""
authpath.diag_export — one downloadable file that captures everything needed to
diagnose the tool's weaknesses on a REAL target, safe to share.

WHAT IT CAPTURES
  * run metadata (target host, scope, principal labels, timing, tool version)
  * the full engine snapshot (findings, per-trace outcomes, counts, severity)
  * the nerve self-diagnosis (coverage, candidate funnel, abstention taxonomy)
  * EVERY raw request/response observed, so a weakness can be traced to the exact
    exchange that caused it — this is the highest-resolution diagnostic signal.

SAFE TO SEND — redaction that loses NO diagnostic signal:
  * Credentials (Authorization / Cookie / API-key / CSRF / password fields) are
    replaced by `$REDACTED:<scheme>:len=N` — the auth SCHEME and token LENGTH stay
    (both are diagnostic) but the secret never leaves.
  * Sensitive PII VALUES (ssn, email, phone, address, dob, card, name…) become a
    short deterministic hash `#abcd1234`. Crucially this PRESERVES cross-principal
    value-equality — "did the accessor reproduce the owner's value?" is still
    answerable from the hashes — while the raw PII never leaves your machine.
  * Everything else (paths, statuses, field NAMES, non-sensitive values, header
    names, sizes) is kept verbatim, because that is what diagnosis needs.

This module performs NO detection and is imported only by the export path.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

_SECRET_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token", "x-session-token",
    "x-access-token", "authentication", "x-amz-security-token",
}
_SECRET_FIELDS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "id_token", "api_key", "apikey", "client_secret", "private_key", "session",
    "sessionid", "csrf", "xsrf", "otp", "pin_code", "auth",
}
_PII_FIELDS = {
    "ssn", "social_security", "email", "e_mail", "phone", "mobile", "address",
    "street", "dob", "date_of_birth", "birthdate", "credit_card", "card_number",
    "cardnumber", "cvv", "iban", "passport", "national_id", "name", "first_name",
    "last_name", "full_name", "tax_id", "license", "account_number",
}


def _short_hash(s: str) -> str:
    return "#" + hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:8]


def _scheme_of(value: str) -> str:
    v = value.strip()
    for scheme in ("Bearer", "Basic", "Digest", "Token", "JWT"):
        if v.lower().startswith(scheme.lower()):
            return scheme
    return "opaque"


def _redact_header(key: str, value: str) -> str:
    if key.lower() in _SECRET_HEADERS:
        return f"$REDACTED:{_scheme_of(value)}:len={len(value or '')}"
    return value


def redact_headers(headers: dict) -> dict:
    return {k: _redact_header(k, str(v)) for k, v in (headers or {}).items()}


def redact_tree(node: Any, _key: str = "") -> Any:
    """Walk a JSON body. Secret fields → $REDACTED; PII values → stable hash;
    everything else verbatim. The hash keeps value-equality diagnosable."""
    leaf_key = _key.split(".")[-1].lower()
    if isinstance(node, dict):
        return {k: redact_tree(v, k) for k, v in node.items()}
    if isinstance(node, list):
        return [redact_tree(v, _key) for v in node]
    # scalar
    if leaf_key in _SECRET_FIELDS:
        return f"$REDACTED:len={len(str(node))}"
    if leaf_key in _PII_FIELDS and node not in (None, "", True, False):
        return _short_hash(str(node))
    return node


def _req_dict(req) -> dict:
    return {
        "method": getattr(req, "method", ""),
        "host": getattr(req, "host", ""),
        "path": getattr(req, "path", ""),
        "query": redact_tree(getattr(req, "query", {}) or {}),
        "headers": redact_headers(getattr(req, "headers", {}) or {}),
        "body": redact_tree(getattr(req, "body", None)),
    }


def _resp_dict(resp) -> dict:
    body = getattr(resp, "body", None)
    return {
        "status": getattr(resp, "status", 0),
        "headers": redact_headers(getattr(resp, "headers", {}) or {}),
        "body": redact_tree(body),
        "body_size_bytes": len(json.dumps(body)) if body is not None else 0,
    }


def build_export(engine, exchanges, *, scope=None, meta=None) -> dict:
    """Assemble the full, redacted diagnostics object for one real run."""
    snap = engine.snapshot() if hasattr(engine, "snapshot") else {}
    try:
        nerve = engine.nerve_diagnostics()
    except Exception:                                  # noqa: BLE001
        nerve = {"enabled": False, "note": "nerve diagnostics unavailable"}
    try:
        bva = engine.bva_diagnostics()
    except Exception:                                  # noqa: BLE001
        bva = {"enabled": False, "note": "bva diagnostics unavailable"}

    principals = {}
    hosts = set()
    raw = []
    for ex in exchanges or []:
        p = getattr(ex, "principal", None)
        pid = getattr(p, "pid", "?")
        principals.setdefault(pid, {
            "label": getattr(p, "label", pid),
            "anonymous": bool(getattr(p, "is_anonymous", False)),
            "auth_header_names": sorted(
                k for k in (getattr(p, "auth", {}) or {}).keys()),
        })
        if getattr(ex.request, "host", ""):
            hosts.add(ex.request.host)
        raw.append({
            "rid": getattr(ex, "rid", ""),
            "principal": pid,
            "observed_at": getattr(ex, "observed_at", 0.0),
            "request": _req_dict(ex.request),
            "response": _resp_dict(ex.response),
        })

    scope_meta = {}
    if scope is not None:
        scope_meta = {
            "allowed_hosts": list(getattr(scope, "allowed_hosts", []) or []),
            "automation_permitted": bool(getattr(scope, "automation_permitted", False)),
            "dry_run": bool(getattr(scope, "dry_run", True)),
            "min_request_interval": getattr(scope, "min_request_interval", 0.0),
        }

    return {
        "schema": "onyx.diag-export/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "redaction": {
            "secrets": "credentials replaced by $REDACTED (scheme+length kept)",
            "pii": "sensitive field values replaced by stable hash (#xxxxxxxx) — "
                   "value-equality preserved, raw PII never leaves the host",
        },
        "run": {
            "target_hosts": sorted(hosts),
            "principals": principals,
            "exchange_count": len(raw),
            **(meta or {}),
        },
        "scope": scope_meta,
        "metrics": {
            "counts": snap.get("counts", {}),
            "nerve": nerve,
            "bva": bva,
        },
        "findings": snap.get("findings", []),
        "traces": snap.get("traces", []),
        "raw_exchanges": raw,
    }


def to_json_bytes(export: dict) -> bytes:
    return json.dumps(export, ensure_ascii=False, indent=2).encode("utf-8")
