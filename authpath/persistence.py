"""
authpath.persistence — SEALED CROSS-SESSION MEMORY (RL11).

D10 forbade a persistent cross-session provenance GRAPH — correctly, because that
would be a raw-payload / PII lake. But it also left ONYX with NO memory across
process runs, so temporal vulnerabilities that only manifest over time — a token
still honoured days after it was revoked, a single-use artifact replayed in a later
session, authority that should have shrunk but did not — are undetectable: every
run starts blind.

This module resolves D10 properly: it keeps the lake rejected and adds the missing
MEMORY, as a small store of DERIVED, FINGERPRINTED facts and nothing else.

Privacy guarantee (RL11, self-audited): the store NEVER contains a raw token, a raw
payload, PII, or a request graph. Credentials/artifacts are recorded only as a
salted hash prefix (a fingerprint); the rest is counts, status-classes, timestamps
and authority-level enums. The store grows with #credentials/#endpoints, not
#requests.

Fail-safe + additive: with no store path the store is DISABLED — every method is a
no-op, so a run is byte-identical to the pre-RL11 engine. A missing or corrupt file
loads as empty (a fresh run), never an error. Cross-session evidence is surfaced as
a provisional LEAD; it never promotes a finding by itself — the Δstate confirmer
still has the final word.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

# A fixed local salt namespace so fingerprints are stable across runs on the same
# machine but are not raw values. (Not a security secret — just de-identification.)
_SALT = "onyx.rl11.v1"

# status classes we persist (never the raw body/status code)
ALLOWED = "allowed"     # a 2xx — the credential was honoured
DENIED = "denied"       # a 401/403 — the credential was rejected/revoked


def fingerprint(value: str) -> str:
    """De-identifying fingerprint: a salted SHA-256 hex prefix. One-way; the raw
    value is never recoverable from the store."""
    h = hashlib.sha256((_SALT + "|" + str(value)).encode("utf-8")).hexdigest()
    return "fp_" + h[:24]


@dataclass
class CredentialRecord:
    """Lifecycle of ONE credential, by fingerprint. No raw token, ever."""
    fp: str
    first_seen: float = 0.0
    last_allowed: float = 0.0          # last time a 2xx was observed for it
    first_denied: float = 0.0          # first time a 401/403 was observed for it
    last_denied: float = 0.0
    allowed_count: int = 0
    denied_count: int = 0
    endpoints: list = field(default_factory=list)   # endpoint KEYS (no ids/values)


@dataclass
class ArtifactRecord:
    """Single-use artifact (coupon/nonce/one-time token) redemption ledger, by
    fingerprint. Persists only the count + timestamps across sessions."""
    fp: str
    redemptions: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


class SealedStore:
    """The cross-session memory. Holds only fingerprinted, derived facts."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.enabled = bool(path)
        self.credentials: dict[str, CredentialRecord] = {}
        self.artifacts: dict[str, ArtifactRecord] = {}
        self.authority_levels: dict[str, list] = {}   # "pid@host" -> sorted authority keys
        # RL11 two-layer artifact counting: `artifacts` holds PRIOR-SESSION
        # redemptions (loaded from disk, frozen for counting this session); this
        # session's new redemptions accrue in `_session_redemptions` and are merged
        # into the persistent count only at save(). This keeps prior_redemptions()
        # = prior sessions only, so the in-session provenance count never double
        # counts with the persisted one.
        self._session_redemptions: dict[str, int] = {}
        if self.enabled:
            self._load()

    # -- lifecycle persistence --------------------------------------------- #
    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
            return  # fail-safe: absent/corrupt ⇒ fresh empty store, never an error
        for fp, rec in (data.get("credentials") or {}).items():
            self.credentials[fp] = CredentialRecord(**rec)
        for fp, rec in (data.get("artifacts") or {}).items():
            self.artifacts[fp] = ArtifactRecord(**rec)
        self.authority_levels = dict(data.get("authority_levels") or {})

    def save(self) -> None:
        if not self.enabled:
            return
        # merge this session's artifact redemptions into the persistent counts
        import time as _t
        for fp, n in self._session_redemptions.items():
            rec = self.artifacts.get(fp)
            if rec is None:
                rec = ArtifactRecord(fp=fp, first_seen=_t.time())
                self.artifacts[fp] = rec
            rec.redemptions += n
            rec.last_seen = _t.time()
        self._session_redemptions = {}
        blob = {
            "credentials": {fp: asdict(r) for fp, r in self.credentials.items()},
            "artifacts": {fp: asdict(r) for fp, r in self.artifacts.items()},
            "authority_levels": self.authority_levels,
        }
        # PRIVACY self-audit (RL11): refuse to persist anything that is not a
        # fingerprint / count / timestamp / endpoint-key / authority enum.
        _assert_sealed(blob)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(blob, fh)
        os.replace(tmp, self.path)

    # -- credential lifecycle (the flagship temporal signal) --------------- #
    def record_credential(self, raw_credential: str, status_class: str,
                           endpoint_key: str, ts: float) -> Optional[dict]:
        """Record one observation of a credential (by fingerprint) and return a
        cross-session ANOMALY dict if this observation contradicts persisted
        history — specifically a credential that was DENIED in a prior session and
        is now ALLOWED (revocation reversed / credential resurrection), which no
        single-session run could ever see. Returns None when there is nothing
        anomalous. Disabled store ⇒ always None (no-op, byte-identical)."""
        if not self.enabled or not raw_credential:
            return None
        fp = fingerprint(raw_credential)
        rec = self.credentials.get(fp)
        anomaly = None
        if rec is None:
            rec = CredentialRecord(fp=fp, first_seen=ts)
            self.credentials[fp] = rec
        if status_class == ALLOWED:
            # cross-session resurrection: was denied before (a prior session), now allowed
            if rec.first_denied and ts >= rec.last_denied:
                anomaly = {
                    "kind": "credential_resurrection",
                    "fp": fp,
                    "first_denied": rec.first_denied,
                    "now_allowed_at": ts,
                    "endpoint": endpoint_key,
                }
            rec.last_allowed = ts
            rec.allowed_count += 1
        elif status_class == DENIED:
            if not rec.first_denied:
                rec.first_denied = ts
            rec.last_denied = ts
            rec.denied_count += 1
        if endpoint_key and endpoint_key not in rec.endpoints:
            rec.endpoints.append(endpoint_key)
        return anomaly

    # -- single-use artifact ledger ---------------------------------------- #
    def record_artifact(self, raw_artifact: str, ts: float) -> int:
        """Record one redemption of a single-use artifact (by fingerprint) in THIS
        session's tally and return the cross-session total (prior sessions + this
        session). Disabled ⇒ 0. The persistent count is updated only at save()."""
        if not self.enabled or not raw_artifact:
            return 0
        fp = fingerprint(raw_artifact)
        self._session_redemptions[fp] = self._session_redemptions.get(fp, 0) + 1
        rec = self.artifacts.get(fp)
        prior = rec.redemptions if rec else 0
        return prior + self._session_redemptions[fp]

    def prior_redemptions(self, raw_artifact: str) -> int:
        """Redemptions recorded in PRIOR sessions only (loaded from disk) — used by
        the coupon law to augment its in-session count without double-counting."""
        if not self.enabled or not raw_artifact:
            return 0
        rec = self.artifacts.get(fingerprint(raw_artifact))
        return rec.redemptions if rec else 0


# --------------------------------------------------------------------------- #
# privacy self-audit                                                          #
# --------------------------------------------------------------------------- #

def _assert_sealed(blob: dict) -> None:
    """Defensive guarantee that only sealed/derived data is being written. Every
    credential/artifact key must be a fingerprint (fp_…); record fields must be
    numeric/timestamp/count or an endpoint-key/authority list. Raises if anything
    looks like a raw token/payload leaked into the store."""
    for section in ("credentials", "artifacts"):
        for key, rec in (blob.get(section) or {}).items():
            if not str(key).startswith("fp_"):
                raise ValueError(f"RL11 privacy breach: non-fingerprint key in {section}: {key!r}")
            if isinstance(rec, dict) and rec.get("fp") and not str(rec["fp"]).startswith("fp_"):
                raise ValueError("RL11 privacy breach: raw value in record fp field")
