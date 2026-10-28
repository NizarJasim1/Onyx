"""
㉕ GraphQL in-request interleave (Gap G5) — logic layer; send is injected.

GraphQL allows a check->mutate->use interleave inside ONE request via aliased/batched
mutations (executed sequentially) and nested resolvers. Confirm ONLY via an
independent victim read-back query (not from the batched response), attributed by a
G14 nonce.

FP gate: GQ-0 confirm via an independent victim read-back, not the batched response;
GQ-1 mutation attributed by nonce (G14); GQ-2 read-only nested exposure confirmed
only across a proven principal boundary; GQ-3 default-OFF.
"""
from __future__ import annotations


def build_aliased_mutation_probe(mutations) -> str:
    """Build one operation with multiple aliased mutations executed sequentially.
    Pure string construction (no I/O)."""
    parts = [f"  m{i}: {m}" for i, m in enumerate(mutations)]
    return "mutation {\n" + "\n".join(parts) + "\n}"


def build_batched_operations(operations) -> list:
    """A JSON array batch of operations (server executes sequentially)."""
    return [{"query": op} for op in operations]


def confirm_interleave_drift(*, victim_readback_query, send_as_victim, seeker, planted,
                             cross_principal_ok):
    """Confirm only if the planted nonce appears in the victim's INDEPENDENT read-back
    AND cross_principal_ok. `send_as_victim` is the injected I/O adapter."""
    from .nonce_provenance import attributed_stick_check
    victim_resp = send_as_victim(victim_readback_query)
    body = getattr(victim_resp, "body", victim_resp)
    return attributed_stick_check(seeker=seeker, planted=planted,
                                  readback_body=body, cross_principal_ok=cross_principal_ok)
