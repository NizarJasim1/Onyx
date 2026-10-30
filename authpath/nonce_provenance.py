"""
⑭ Nonce Provenance — cross-channel attribution (Gap G14).

THE PROBLEM THIS CLOSES
-----------------------
Today the "did my effect land?" check is `act_bridge` M-4: read the field back and
compare `got == privileged_value`. `privileged_value` is a SEMANTIC constant (e.g.
"admin", "true"). That is ambiguous as attribution: the field may have already held
"admin", a shared default may be "admin", or a *second* test may have written it.
And across an async / out-of-band boundary (the effect surfaces in a CSV export or a
webhook an hour later) there is NO way to prove that "admin" came from THIS test.

Semantic equality proves *a* value is present. It does NOT prove *this test* put it
there. That gap is why G1 (OOB channels), G7 (idempotency replay) and G8 (deep
second-order) cannot be built soundly first — they all need bullet-proof attribution.

THE MECHANISM (attack the cause, not the symptom — Anti-Patch #1)
-----------------------------------------------------------------
Mint a globally-unique, high-entropy, self-identifying token per mutation attempt.
Its later appearance ANYWHERE is proof-by-construction that this exact test caused it,
because the probability of a 128-bit token occurring by chance is ~0. Attribution
becomes cryptographic, not heuristic.

FIELD-TYPE AWARENESS (No-Regression #1 — never weaken detection)
----------------------------------------------------------------
We must NOT blindly overwrite a semantic value with a nonce: writing `role="ONYX-…"`
would be rejected as an invalid enum, the write would fail, and a real bug would be
MISSED (a false negative — a regression). So planting is strategy-selected:

  PURE_TEXT          free-text field (name/bio/note)      → plant a pure nonce
  HYBRID_COMPANION   semantic field + a free-text sibling → write the semantic value
                     in the SAME object/request AND stamp a nonce into the sibling
  ISOLATION          a freshly-provisioned throwaway object with a KNOWN pre-state
                     → attribute by exclusion (any change is ours)
  ABSTAIN            none of the above possible → NO finding (never downgrade the bar)

SEPARATION OF CONCERNS (Anti-Patch #1 again)
--------------------------------------------
The nonce proves ATTRIBUTION ("my effect landed"), NOT AUTHORIZATION ("it was
cross-principal"). The cross-principal read-back stays a SEPARATE, independent
requirement. G14 makes attribution unforgeable; it does not relax the authz verdict.

FP GATE — written before the code (Anti-Patch #2)
-------------------------------------------------
  P-0  pre-plant: the minted nonce is verified ABSENT in the target datum first.
  P-1  attribution requires an EXACT, FULL-ENTROPY match of the minted token.
       A prefix / substring / semantic-value match is NOT attribution → abstain.
  P-2  the token must be one WE minted (recognised()) — never attribute to target data.
  P-3  attribution alone is NOT a finding: the cross-principal condition is still
       required by the caller. Nonce-found ∧ ¬cross-principal → abstain.
  P-4  if no plant strategy achieves cryptographic (or isolation) attribution → abstain.

REVERSIBILITY (No-Regression #4)
--------------------------------
Everything here is opt-in. `act_bridge`/`confirmer` only use it when a NonceAuthority
is wired AND a nonce was planted; with no authority the legacy M-4 path runs
byte-for-byte unchanged, so the existing 542 tests stay green.

No model, no network, no randomness in the VERDICT — the mint uses entropy but the
verdict is exact string containment (RL1/RL2 deterministic).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional

# Self-identifying prefix: lets ONYX recognise its OWN tokens and never mistake
# target data for a nonce (P-2). 'oxpv' = ONYX provenance. The uuid4 hex carries
# 122 bits of entropy → collision-proof at any realistic test volume.
_PREFIX = "oxpv"


@dataclass(frozen=True)
class Nonce:
    """An immutable, minted attribution token."""
    value: str          # full token, e.g. "oxpv-9f86d081...-<mint_seq>"
    purpose: str        # human label (which mutation this tags) — cosmetic only
    seq: int            # monotonic mint index within an authority (for the ledger)

    def appears_in(self, blob: Any) -> bool:
        """P-1: EXACT full-token containment. Anything less is not attribution.
        Works on any stringifiable channel payload (JSON body, CSV text, webhook
        body, email source) — this is what makes G1/G7/G8 able to plug in later."""
        if blob is None:
            return False
        try:
            hay = blob if isinstance(blob, str) else _stringify(blob)
        except Exception:
            return False
        return self.value in hay

    # A nonce may need to sit inside a typed field. These renderers keep it a
    # SUBSTRING of a type-valid value, so the write is accepted but the token is
    # still exact-matchable on read-back.
    def as_text(self) -> str:
        return f"ONYX-{self.value}"

    def as_email(self, domain: str = "onyx.test") -> str:
        # plus-addressing keeps it a valid, deliverable-looking address
        return f"onyx+{self.value}@{domain}"

    def as_suffix(self, base: str) -> str:
        return f"{base}-{self.value}"


def _stringify(blob: Any) -> str:
    import json
    try:
        return json.dumps(blob, default=str, sort_keys=True)
    except Exception:
        return str(blob)


class NonceAuthority:
    """Mints nonces and recognises its own. One per engagement; feeds the evidence
    ledger so every attribution token is part of the tamper-evident record."""

    def __init__(self, ledger=None):
        self._seq = 0
        self._ledger = ledger
        self._minted: dict[str, Nonce] = {}

    def mint(self, purpose: str) -> Nonce:
        self._seq += 1
        token = f"{_PREFIX}-{uuid.uuid4().hex}-{self._seq}"
        n = Nonce(value=token, purpose=purpose, seq=self._seq)
        self._minted[token] = n
        if self._ledger is not None:
            # record into the hash-chained evidence trail if one is wired
            rec = getattr(self._ledger, "record", None)
            if callable(rec):
                try:
                    rec("nonce_mint", {"token": token, "purpose": purpose, "seq": n.seq})
                except Exception:
                    pass
        return n

    def recognises(self, s: Any) -> bool:
        """P-2: is `s` one of MY minted tokens (never target data)?"""
        if not isinstance(s, str):
            return False
        return s in self._minted

    def minted(self) -> Iterable[Nonce]:
        return tuple(self._minted.values())


class PlantStrategy(str, Enum):
    PURE_TEXT = "pure_text"
    HYBRID_COMPANION = "hybrid_companion"
    ISOLATION = "isolation"
    ABSTAIN = "abstain"


# Field-name fragments whose values are typically CONSTRAINED (enum/bool/number):
# writing a nonce into them would break the write, so they need a companion.
_SEMANTIC_HINTS = ("role", "isadmin", "is_admin", "admin", "status", "state",
                   "verified", "enabled", "active", "type", "kind", "level",
                   "privilege", "scope", "permission", "amount", "price", "qty",
                   "quantity", "balance", "paid", "plan", "tier")

# Field-name fragments that are typically FREE-TEXT (safe to carry a pure nonce).
_FREETEXT_HINTS = ("name", "title", "label", "bio", "about", "description", "desc",
                   "note", "notes", "comment", "message", "nickname", "display",
                   "address", "street", "city", "company", "subject", "text",
                   "summary", "headline", "tagline")


def _is_freetext(field_name: str) -> bool:
    n = field_name.lower()
    if any(h in n for h in _SEMANTIC_HINTS):
        return False
    return any(h in n for h in _FREETEXT_HINTS)


def choose_strategy(target_field: str,
                    object_fields: Optional[dict[str, Any]] = None,
                    isolation_available: bool = False) -> tuple[PlantStrategy, Optional[str]]:
    """Pick how to achieve cryptographic (or isolation) attribution for a write to
    `target_field`. Returns (strategy, companion_field_or_None).

    Deterministic, fail-safe: when in doubt, prefer ABSTAIN over a weak attribution.
    """
    if _is_freetext(target_field):
        return PlantStrategy.PURE_TEXT, None

    # target_field is semantic/constrained → need a free-text companion in the SAME object
    if object_fields:
        for name in object_fields:
            if name != target_field and _is_freetext(name):
                return PlantStrategy.HYBRID_COMPANION, name

    if isolation_available:
        return PlantStrategy.ISOLATION, None

    return PlantStrategy.ABSTAIN, None


@dataclass
class AttributionResult:
    attributed: bool
    strategy: PlantStrategy
    nonce: Optional[Nonce]
    reason: str
    # channel where the nonce was found (for G1: "readback" | "export" | "webhook" | "email" | ...)
    channel: str = ""


class NonceSeeker:
    """Channel-agnostic attribution oracle. Register planted nonces, then hand it
    ANY channel payload; it reports exact-match hits. G1/G7/G8 call `.seek(...)`
    with export text / webhook bodies / mailbox contents — the logic is identical
    because attribution is pure exact-containment of a unique token."""

    def __init__(self, authority: NonceAuthority):
        self._authority = authority
        self._planted: dict[str, Nonce] = {}

    def register_planted(self, n: Nonce) -> None:
        # P-2: only nonces this authority minted can be planted/attributed.
        if not self._authority.recognises(n.value):
            raise ValueError("refusing to plant a nonce this authority did not mint")
        self._planted[n.value] = n

    def seek(self, channel_payload: Any, channel: str = "readback") -> Optional[AttributionResult]:
        """Return an AttributionResult for the FIRST planted nonce that appears
        exactly in `channel_payload`, else None. Exact-match only (P-1)."""
        for _token, n in self._planted.items():
            if n.appears_in(channel_payload):
                return AttributionResult(True, PlantStrategy.PURE_TEXT, n,
                                         f"exact nonce match in {channel}", channel)
        return None

    def pre_plant_absent(self, n: Nonce, current_datum: Any) -> bool:
        """P-0: confirm the nonce is NOT already present before we plant it.
        (Trivially true by entropy, but the gate is honoured explicitly.)"""
        return not n.appears_in(current_datum)


def attributed_stick_check(*, seeker: NonceSeeker, planted: Nonce,
                           readback_body: Any, cross_principal_ok: bool,
                           channel: str = "readback") -> AttributionResult:
    """Drop-in, stronger replacement for act_bridge M-4's `got == value`.

    Enforces the full FP gate:
      P-1 exact nonce match required,
      P-3 attribution is NOT sufficient — cross_principal_ok must ALSO hold,
      → otherwise abstain with a precise reason.
    """
    hit = seeker.seek(readback_body, channel=channel)
    if hit is None:
        return AttributionResult(False, PlantStrategy.ABSTAIN, planted,
                                 "nonce not found on read-back — effect did not land (abstain)",
                                 channel)
    if not cross_principal_ok:
        # P-3: our effect landed, but it was not proven cross-principal → NOT a finding.
        return AttributionResult(False, hit.strategy, planted,
                                 "nonce attributed but cross-principal condition unproven (abstain)",
                                 channel)
    return AttributionResult(True, hit.strategy, planted,
                             "effect attributed to this test by unique nonce AND proven cross-principal",
                             channel)
