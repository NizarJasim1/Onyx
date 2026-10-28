# CRUCIBLE — problem #6 (GT3): secondary-key BOLA is invisible (path-identity blindness)

## LOOP 1 — TRIPLE-DIAGNOSE (converged on the root cause)
- TD1: the planted BOLA-strange (order via ?invoice=) is MISSED even after the order
  response is made to declare owner_id — across seeds 1337/99.
- TD2: zero nerve findings on any order resource; the access produces no candidate.
- TD3 (root cause): identify('/api/orders?invoice=INV-DDD') → None. The resource-identity
  layer keys on PATH segments (doc:4, account:4) and does NOT recognize an object addressed
  by a SECONDARY KEY (a query parameter: ?invoice=, ?id=, ?email=). So the secondary-key
  access is never filed as an object access → nerve 1 (and every object detector) is blind
  to it by construction.
- Converged: nerve 1 GENERALIZES to path-id BOLA (it catches doc:2) but MEMORIZES the
  path shape — it does not generalize to secondary-key BOLA. A real GT3 generalization gap.

## LOOP 2 — KILL-THE-PROBLEM (sound fix; FP trap identified)
- The fix lives in surface_map.identify(): recognize a query parameter that addresses a
  SINGLE object as a secondary-key resource identity, so endpoint?key=value becomes a
  distinct resource the detectors can reason about.
- FP TRAP (critical): not every query param is an object key — ?page=2, ?sort=date,
  ?limit=10, ?expand=full are pagination/filter/projection, NOT object identity. Treating
  them as objects would create noise and could mislead candidates.
- SOUND, non-inductive guard for "this query param is a secondary object key":
    * the response is a SINGLE object (not a list/collection), AND
    * it declares an owner (owner_id present) — i.e. it is a private, owner-scoped object,
    * and the key parameter's value is NOT a known pagination/projection word
      (page/limit/offset/sort/order/expand/fields/q/filter).
  Only then treat endpoint?key=value as a resource identity. This keeps precision: a
  collection or a projection query is never promoted to an object.

## LOOP 3 — FORGE-HARDEST (NEXT SESSION — execute directly)
1. surface_map.identify(): when the path is a collection endpoint and the query carries a
   single non-pagination key, MINT a secondary-key resource id of the form
   `endpoint:key=value` (stable, distinct). Gate it behind the response being a single
   owner-declaring object where possible; if identify() cannot see the response, mint the
   id but let the existing ownership/Δstate guards abstain when no owner is declared
   (so a pure collection/filter never convicts).
2. RE-MEASURE-CRUEL: the secondary-key BOLA (order via ?invoice=) must be caught; a
   pagination/filter query (?page, ?sort) must produce NO finding (precision); suite green;
   demo byte-identical. Then the catalog's OTHER strange forms (BOLA via nested body
   reference; BFLA shadow-admin endpoint + verb-tunneling; mass-assignment WRITE;
   AUTHN method-only gap) each get their own CRUCIBLE pass.

## SAFETY / DISCIPLINE NOTE
This touches resource IDENTITY — the spine every detector keys on. It must be built with a
cold mind + a precision regression (pagination/filter/projection queries stay non-objects),
not rushed. Deferred to protect the project at 369 green after five problems already
resolved this session.

## STATUS
Loops 1-2 DONE (by running): root cause = path-based identity; sound fix designed with its
FP guard. Build (loop 3) is the next session's first action.

## LOOP 3 — FORGE-HARDEST (DONE) — secondary-key resource identity
authpath/surface_map.py: when request.resource_name() yields no path id, identify() now
calls _secondary_key_identity(): a collection endpoint carrying exactly ONE meaningful
(non-pagination) query key mints a distinct ResourceIdentity `<coll>:<key>=<value>`.
FP GUARD (_PAGINATION_KEYS): page/limit/offset/sort/order/expand/fields/q/filter/cursor/...
are NEVER promoted to objects; zero or multiple meaningful keys → None (not one object).
Path ids still take precedence. Identity is the spine, so a 6-case precision regression pins
that pagination/projection/filter/bare-collection stay non-objects.

## LOOP 4 — RE-MEASURE-CRUEL (DONE) — PASSED across two seeds
seeds 1337 / 99: the secondary-key BOLA (order via ?invoice=) is now CAUGHT
(order:invoice=inv-ddd / inv-ccc), with ZERO false positives on a pagination decoy
(?page=2) or the public endpoint. Suite 369→375 (6 new); demo byte-identical.

## PROBLEM #6 — RESOLVED
nerve 1 now GENERALIZES from path-id BOLA to secondary-key BOLA. The strange form is caught;
pagination/projection stay non-objects (precision spine intact). Permanent regression:
tests/test_secondary_key.py.
