# CHANGELOG — G6: Async-commit seam follower (recall on 202/saga/CQRS)

## What
New module `authpath/async_seam.py` + pure suite `tests/test_async_seam_g6.py`
(7 tests) + engine wiring + ON-path suite `tests/test_g6_engine_wiring.py`
(3 tests). Closes gap **G6**: on a 202/saga/CQRS async commit, FOLLOW the commit to
its landed state instead of abstaining at the ack.

## Why
The engine did `return` on a 202 (correct for zero-FP: an optimistic ack the backend
later rejects must not forge a finding) but that lost recall — a real async mutation
that DOES commit was never followed. bol.com's own API docs confirm the principle:
the 202 "only confirms that we received your request… use the process status
endpoint — the only reliable way to confirm the outcome."

## Mechanism (network-wall-killer protocol: split logic from I/O)
- Layer A (pure, fully tested here): `async_seam_follow(read_back, persisted, ...)`
  polls a read-back over a bounded window; confirms ONLY when `persisted(rb)` is
  True; timeout ⇒ None (abstain).
- Layer B (engine): reuses the existing `_readback` + `_write_persisted`. No new I/O
  primitive.

## Why zero-FP is preserved (the subtle part)
We do NOT confirm on the 202. We confirm only on a subsequent read-back that shows
the effect PERSISTED. The optimistic-ack-then-rejected case never persists ⇒ still
abstains. Following is strictly safe: recovers real async commits (recall) while
still rejecting optimistic acks (FP). It is MORE rigorous than a synchronous 2xx.

## Engine wiring (all flag-gated, default OFF ⇒ byte-identical)
- `__init__`: `follow_async_commit=False`, `_async_max_polls=4`.
- 202 guard: `if status==202 and not follow_async_commit: return`.
- per-oid loop: when following, wrap the read-back in `async_seam_follow` (poll to a
  persisted landing) instead of a single check; legacy single-check otherwise.

## FP gate (W-0..W-3)
- W-0 bounded poll; settling-window timeout ⇒ abstain.
- W-1 confirm only when `persisted(rb)` is True on an actual read-back.
- W-2 a None read-back is never persisted.
- W-3 default-OFF ⇒ 202 handling byte-identical.

## Verification
- Pure suite: 7/7 (incl. optimistic-ack-then-rejected ⇒ abstain).
- Engine ON-path suite: 3/3 — the engine's REAL `_readback`+`_write_persisted`,
  composed exactly as the 202 site does, follow an async landing and abstain when it
  never lands.
- Full project suite: **638 → 648**, 0 failures, 0 import errors (no regression).

## Note
Rebuilt on the restored v11_G13 tree after a sandbox recycle; the surviving
`onyx_project_v11_G13.tar.gz` (638 green) was re-verified before G6 was applied.
