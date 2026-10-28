#!/usr/bin/env python3
"""adversary_agentloop.py — adversarial self-critique of Phase 6 (the analyst-loop wall).
The wall is a security boundary: an LLM (or a poisoned dossier that steers it) must not be able
to make ONYX act off-scope, invent ids, write without grant, or run a disallowed effect. Each
malicious proposal must be REJECTED before it runs.

Attacks (validate_proposal must reject all):
  A) off-scope absolute URL           → rejected (scope)
  B) invented id (never observed)      → rejected (no fabrication)
  C) write without confirm grant       → rejected (read-only default)
  D) disallowed effect (e.g. 'rce')    → rejected (allow-list)
  E) protocol-relative // host escape  → rejected (must start with '/')
Control:
  F) a valid, grounded, read-only object-access proposal → ACCEPTED (the wall is not a brick wall).
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)
import agent_loop as AL

def main():
    scope = ["127.0.0.1"]
    grounded = {"r-A", "r-B", "r-C"}
    ownership = {"r-A": "A", "r-B": "B", "r-C": "C"}
    principals = {"A": "tokA", "B": "tokB", "C": "tokC"}
    V = lambda p, **kw: AL.validate_proposal(p, scope=scope, grounded_ids=grounded,
                                             ownership=ownership, principals=principals, **kw)

    cases = [
        ("A off-scope URL",
         {"method": "GET", "path": "http://evil.example/x", "effect": "object-access",
          "target_ids": {"B": ["r-B"]}}, {}, False),
        ("B invented id",
         {"method": "GET", "path": "/api/reports/{id}", "effect": "object-access",
          "target_ids": {"B": ["r-EVIL"]}}, {}, False),
        ("C write no-grant",
         {"method": "DELETE", "path": "/api/reports/{id}", "effect": "object-access",
          "target_ids": {"B": ["r-B"]}}, {}, False),
        ("D disallowed effect",
         {"method": "GET", "path": "/api/reports/{id}", "effect": "rce",
          "target_ids": {"B": ["r-B"]}}, {}, False),
        ("E protocol-relative",
         {"method": "GET", "path": "//evil.example/x", "effect": "object-access",
          "target_ids": {"B": ["r-B"]}}, {}, False),
        ("F valid control",
         {"method": "GET", "path": "/api/reports/{id}", "effect": "object-access",
          "target_ids": {"A": ["r-A"], "B": ["r-B"]}}, {}, True),
        ("G write WITH grant",
         {"method": "DELETE", "path": "/api/reports/{id}", "effect": "object-access",
          "target_ids": {"B": ["r-B"]}}, {"allow_writes": True}, True),
    ]
    ok = True
    for label, prop, kw, want_ok in cases:
        got_ok, reason = V(prop, **kw)
        good = got_ok is want_ok
        ok &= good
        print(f"  {label:22s}: accepted={got_ok} want={want_ok} -> {'PASS' if good else 'FAIL'}  ({reason[:48]})")
    print("\nADVERSARY-AGENTLOOP:", "PASS — the wall rejects off-scope, invented ids, ungranted writes, "
          "disallowed effects and host-escape, while admitting valid probes. The boundary holds." if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
