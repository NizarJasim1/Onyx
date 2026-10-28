#!/usr/bin/env bash
# =============================================================================
# onyx_dissect.sh — ONYX at FULL STRENGTH: crawl → deep anatomy → confirm →
# business-logic → self-proof → ONE deep dissection report for the analyst.
#
# This chains ONYX's whole arsenal in the order it was designed. It adds ZERO
# accept logic and relaxes ZERO guarantee: every CONFIRMED item is still proven
# by a Δstate read-back (zero false positives). Hypotheses are surfaced for
# The analyst to judge; agent_loop (Phase 6) proves the ones the analyst picks.
#
#   PHASE A · REACH        explorer            authenticated READ-ONLY deep crawl → rich HAR
#   PHASE B · ANATOMY      sitemodel (L1)      object / relation / decision-point map
#                          invariants (L2)     learned rules (ownership, money, state, uniqueness)
#                          dossier (L1⊕L2)     fused map + RANKED HYPOTHESES
#   PHASE C · CONFIRM      conductor           base-recon + L3 breaker + L4/L4X pivots → packet
#                          onyx_recon          independent GENERAL N-principal hunt + coverage
#                          graphql_surface     cross-owner GraphQL node reads (best-effort)
#                          token_probes        JWT alg=none (informational; Δstate-gated)
#   PHASE D · BUSINESS     sequences           multi-step: refund/state-gate + coupon reuse
#   PHASE E · SELF-PROOF   diagnostics         engine self-observation (health + coverage)
#   PHASE F · ASSEMBLE     → DISSECTION_REPORT.md (ordered, detailed)
#
#   ./onyx_dissect.sh --base-url http://localhost:8888 --mailhog http://localhost:8025
#   optional: --openapi <spec.json>   --max-requests 800
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

BASE="http://localhost:8888"; MH="http://localhost:8025"; SPEC=""; MAXREQ=800
while [ $# -gt 0 ]; do case "$1" in
  --base-url) BASE="$2"; shift 2;; --mailhog) MH="$2"; shift 2;;
  --openapi) SPEC="$2"; shift 2;; --max-requests) MAXREQ="$2"; shift 2;;
  *) echo "unknown arg: $1"; exit 1;; esac; done

PY="python3"; [ -x "$ROOT/.venv/bin/python" ] && PY="$ROOT/.venv/bin/python"
$PY -c "import requests" 2>/dev/null || { python3 -m venv "$ROOT/.venv" && "$ROOT/.venv/bin/python" -m pip -q install requests; PY="$ROOT/.venv/bin/python"; }

if [ -z "$SPEC" ]; then
  SPEC="$(find "$HOME" -ipath '*/openapi-spec/*.json' 2>/dev/null | grep -i crapi | head -1)"
  [ -z "$SPEC" ] && SPEC="$(find "$HOME" -iname 'crapi-openapi-spec.json' 2>/dev/null | grep -iv -e chatbot -e /services/ | head -1)"
fi
[ -n "$SPEC" ] && echo "· OpenAPI spec: $SPEC" || echo "· no spec — live discovery only"
SPECARG=""; [ -n "$SPEC" ] && SPECARG="--openapi $SPEC"

TS="$(date +%Y%m%d_%H%M%S)"; OUT="$ROOT/onyx_dissect_$TS"; SEEDDIR="$OUT/seed"; mkdir -p "$OUT" "$SEEDDIR"
log(){ tee -a "$OUT/$1"; }
sec(){ echo; echo "════════════ $1 ════════════"; }

# ---- preflight: fail fast with a clear message instead of a stack trace ----
sec "PREFLIGHT"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$BASE" 2>/dev/null || echo 000)"
if [ "$code" = "000" ]; then
  echo "✗ crAPI unreachable at $BASE (got 000)."
  echo "  Start it:  cd <your crAPI checkout>/deploy/docker && docker compose up -d   (wait 2-3 min)"
  echo "  Verify:    curl -s -o /dev/null -w '%{http_code}\\n' $BASE   → 200/302"
  exit 1
fi
$PY -c "import sys; sys.path.insert(0,'.'); import authpath.engine, authpath.confirmer" 2>/dev/null \
  && echo "✓ crAPI reachable ($code) · ONYX engine importable" \
  || { echo "✗ ONYX engine not importable from $ROOT — run from the project root"; exit 1; }

sec "0 · SEED — provision a rich object graph (3 principals)"
$PY external_targets/crapi_seed.py --base-url "$BASE" --mailhog "$MH" --principals A,B,C --out "$SEEDDIR" 2>&1 | log seed.log
[ -f "$SEEDDIR/seed.json" ] || { echo "✗ seeding failed — see $OUT/seed.log (is crAPI up on $BASE?)"; exit 1; }

eval "$($PY - "$SEEDDIR/seed.json" <<'PYEOF'
import json,sys,shlex
s=json.load(open(sys.argv[1])); acc=s["accounts"]; ids=s["ids"]; pr=s["principals"]
def g(p,k): return ",".join(str(x) for x in (ids.get(p,{}).get(k) or []))
prin=" ".join(f"--principal {p}:{acc[p]['token']}" for p in pr if acc[p].get('token'))
tokmap=json.dumps({acc[p]['token']:p for p in pr if acc[p].get('token')})
seeds=set(["/identity/api/v2/vehicle/vehicles","/identity/api/v2/user/dashboard",
           "/workshop/api/shop/orders","/workshop/api/shop/products",
           "/community/api/v2/community/posts/recent","/workshop/api/mechanic/"])
first_order=""
for p in pr:
    for u in ids.get(p,{}).get("vehicles") or []: seeds.add(f"/identity/api/v2/vehicle/{u}/location")
    for o in ids.get(p,{}).get("orders") or []:
        seeds.add(f"/workshop/api/shop/orders/{o}"); first_order=first_order or o
    for r in ids.get(p,{}).get("reports") or []: seeds.add(f"/workshop/api/mechanic/mechanic_report?report_id={r}")
seedargs=" ".join(f"--seed {shlex.quote(x)}" for x in sorted(seeds))
print(f'PRIN={shlex.quote(prin)}'); print(f'TOKMAP={shlex.quote(tokmap)}')
print(f'SEEDARGS={shlex.quote(seedargs)}'); print(f'AO1={shlex.quote(first_order)}')
print(f'ATOK={shlex.quote(acc[pr[0]]["token"])}'); print(f'BTOK={shlex.quote(acc.get("B",{}).get("token",""))}')
print(f'AO={shlex.quote(g("A","orders"))}'); print(f'BO={shlex.quote(g("B","orders"))}')
print(f'AR={shlex.quote(g("A","reports"))}'); print(f'BR={shlex.quote(g("B","reports"))}')
PYEOF
)"
echo "· wired: $(echo $SEEDARGS | grep -o -- --seed | wc -l) deep seed paths, $(echo $PRIN | grep -o -- --principal | wc -l) principals"

sec "A · REACH — explorer deep authenticated crawl → HAR"
HAR="$OUT/capture.har"
eval $PY external_targets/explorer.py --authorized --base-url "$BASE" $SPECARG $PRIN \
     $SEEDARGS --max-requests "$MAXREQ" --scope localhost --researcher me --out "$HAR" 2>&1 | log explorer.log || true
[ -f "$HAR" ] && echo "· HAR: $(wc -c <"$HAR") bytes" || echo "⚠ no HAR — see explorer.log"

sec "B · ANATOMY — sitemodel (L1) + invariants (L2) + dossier (fused)"
$PY external_targets/sitemodel.py --har "$HAR" $SPECARG --tokens "$TOKMAP" --out "$OUT/sitemodel.json" > "$OUT/sitemodel.md" 2>>"$OUT/anatomy.err" || true
$PY external_targets/invariants.py --har "$HAR" --tokens "$TOKMAP" --out "$OUT/invariants.json" > "$OUT/invariants.md" 2>>"$OUT/anatomy.err" || true
$PY external_targets/dossier.py --har "$HAR" $SPECARG --tokens "$TOKMAP" --out "$OUT/dossier.json" > "$OUT/dossier.md" 2>>"$OUT/anatomy.err" || true
# DEEP structural anatomy — every library-only analyzer (surface/roles/states/doors/temporal/mass-assign/contradictions)
$PY external_targets/onyx_deepmap.py --har "$HAR" $SPECARG --scope localhost --out "$OUT/deepmap.json" > "$OUT/deepmap.md" 2>>"$OUT/anatomy.err" || true
echo "· anatomy built (sitemodel/invariants/dossier + deepmap: roles/states/doors/surface/temporal/BOPLA/contradictions)"

sec "C · CONFIRM — conductor + onyx_recon + graphql + token"
$PY external_targets/conductor.py --authorized --base-url "$BASE" --har "$HAR" $SPECARG $PRIN \
     --confirm --researcher me --out "$OUT/packet" 2>&1 | log conductor.log || true
mkdir -p "$OUT/recon"
$PY external_targets/onyx_recon.py --authorized --base-url "$BASE" $SPECARG $PRIN \
     --confirm --researcher me --out "$OUT/recon" 2>&1 | log recon.log || true
# crAPI specialist confirmer (proven path, all seeded ids wired)
$PY external_targets/hunt_crapi.py --confirm --base-url "$BASE" --mailhog "$MH" \
     --a-token "$ATOK" --b-token "$BTOK" \
     --a-orders "$AO" --b-orders "$BO" --a-reports "$AR" --b-reports "$BR" \
     --coupon TRAC075 --researcher me --out "$OUT/hunt" 2>&1 | log hunt.log || true
for gp in /community/api/graphql /graphql /community/graphql; do
  $PY external_targets/graphql_surface.py --authorized --base-url "$BASE" --graphql-path "$gp" $PRIN --researcher me 2>&1 | log graphql.log || true
done
# build victim spec for token probe (B's vehicle vs A's)
eval "$($PY - "$SEEDDIR/seed.json" <<'PYEOF'
import json,sys,shlex
s=json.load(open(sys.argv[1])); ids=s["ids"]
bveh=(ids.get("B",{}).get("vehicles") or [""])[0]; aveh=(ids.get("A",{}).get("vehicles") or [""])[0]
print(f'BVEH={shlex.quote(bveh)}'); print(f'AVEH={shlex.quote(aveh)}')
print(f'BSUB={shlex.quote(s["accounts"]["B"].get("email",""))}')
PYEOF
)"
cat > "$OUT/victim.json" <<JSON
{"sub":"$BSUB","read_path":"/identity/api/v2/vehicle/{id}/location","oid":"$BVEH","own_path":"/identity/api/v2/vehicle/{id}/location","own_oid":"$AVEH"}
JSON
$PY external_targets/token_probes.py --authorized --base-url "$BASE" --attacker-token "$ATOK" \
     --victim "$OUT/victim.json" --probe alg-none --researcher me 2>&1 | log token.log \
     || echo "(alg=none not applicable — crAPI signs JWTs; ONYX confirms only by Δstate.)" | log token.log

sec "D · BUSINESS — sequences (refund/state-gate + coupon reuse)"
cat > "$OUT/flows.json" <<JSON
[
  {"name":"order-refund-mass-assign","setup":[],
   "critical":{"method":"PUT","path":"/workshop/api/shop/orders/{id}","effect":"STATE_GATE",
               "body":{"status":"returned","quantity":150},"ids":{"A":["$AO1"]}}},
  {"name":"coupon-reuse",
   "setup":[{"principal":"A","method":"POST","path":"/workshop/api/shop/apply_coupon","body":{"coupon_code":"TRAC075","amount":75}}],
   "critical":{"method":"POST","path":"/workshop/api/shop/apply_coupon","effect":"COUPON",
               "body":{"coupon_code":"TRAC075","amount":75},"ids":{"A":["self"]}}}
]
JSON
eval $PY external_targets/sequences.py --authorized --base-url "$BASE" $PRIN --flows "$OUT/flows.json" --researcher me 2>&1 | log sequences.log || true
# TOCTOU / double-spend (Phase 5) — best-effort; confirms ONLY on two independent conserved-quantity breaches
cat > "$OUT/race.json" <<JSON
{"op":{"path":"/workshop/api/shop/apply_coupon","body":{"coupon_code":"TRAC075","amount":75}},
 "signals":{"count":{"path":"/identity/api/v2/user/dashboard","field":"available_credit"},
            "value":{"path":"/identity/api/v2/user/dashboard","field":"available_credit","single":75}},
 "allowed":1,"k":8}
JSON
$PY external_targets/race.py --authorized --base-url "$BASE" --token "$ATOK" --spec "$OUT/race.json" --scope localhost --researcher me 2>&1 | log race.log || true

sec "E · PROVE-LOOP (Phase 6) — agent_loop auto-proves grounded proposals by Δstate"
# generate cross-principal proposals grounded in the seeded object graph (read-only, wall-guarded)
$PY - "$SEEDDIR/seed.json" > "$OUT/proposals.json" <<'PYEOF'
import json,sys
s=json.load(open(sys.argv[1])); ids=s["ids"]; pr=s["principals"]
P=[]
def add(atk,path,vid,eff,hyp): P.append({"method":"GET","path":path,"effect":eff,"target_ids":{atk:[str(vid)]},"hypothesis":hyp})
for owner in pr:
    for atk in pr:
        if atk==owner: continue
        for u in ids.get(owner,{}).get("vehicles") or []:
            add(atk,"/identity/api/v2/vehicle/{id}/location",u,"object-access",f"{atk} reads {owner}'s vehicle")
        for o in ids.get(owner,{}).get("orders") or []:
            add(atk,"/workshop/api/shop/orders/{id}",o,"object-access",f"{atk} reads {owner}'s order")
        for r in ids.get(owner,{}).get("reports") or []:
            add(atk,"/workshop/api/mechanic/mechanic_report?report_id={id}",r,"object-access",f"{atk} reads {owner}'s report")
json.dump(P,open(sys.argv[2] if len(sys.argv)>2 else "/dev/stdout","w"),indent=2) if len(sys.argv)>2 else print(json.dumps(P,indent=2))
PYEOF
$PY external_targets/agent_loop.py --authorized --base-url "$BASE" --har "$HAR" \
     --proposals "$OUT/proposals.json" $PRIN --tokens "$TOKMAP" --researcher me 2>&1 | log agentloop.log || true

sec "F · SELF-PROOF — engine self-diagnostics"
$PY -m authpath diagnostics --out "$OUT/diagnostics.json" 2>&1 | log diagnostics.log || true

# ------------------------------- ASSEMBLE -------------------------------
sec "G · ASSEMBLE — DISSECTION_REPORT.md"
REP="$OUT/DISSECTION_REPORT.md"
{
  echo "# ONYX — Deep Site Dissection for the analyst"
  echo
  echo "**Target:** \`$BASE\`  ·  **When:** $TS  ·  **Spec:** \`${SPEC:-live-discovery}\`"
  echo "**Method:** explorer crawl → L1/L2 anatomy → conductor+recon confirm → sequences → self-diagnostics."
  echo "**Guarantee (unrelaxed):** every CONFIRMED item is Δstate-proven — zero false positives, no ML/LLM in the decision path. Hypotheses are for the analyst to judge; none is a finding until Δstate-confirmed."
  echo
  echo "## 0 · Provisioned object graph"
  echo '```'; $PY - "$SEEDDIR/seed.json" <<'PYEOF'
import json,sys
s=json.load(open(sys.argv[1]))
for p in s["principals"]: print(p, {k:v for k,v in s["ids"].get(p,{}).items()})
print("coupon_live:", s.get("coupon_live"))
PYEOF
  echo '```'
  echo; echo "## 1 · Crawl reach (explorer)"; echo '```'; grep -E "explorer:|capture" "$OUT/explorer.log" 2>/dev/null | tail -4 || echo "(see explorer.log)"; echo '```'
  echo; echo "## 2 · L1 site model — objects, relations, decision points"; echo; cat "$OUT/sitemodel.md" 2>/dev/null | head -120 || echo "_(none)_"
  echo; echo "## 3 · L2 invariants — learned rules"; echo; cat "$OUT/invariants.md" 2>/dev/null | head -120 || echo "_(none)_"
  echo; echo "## 4 · Fused dossier + RANKED HYPOTHESES (the analyst's reasoning surface)"; echo; cat "$OUT/dossier.md" 2>/dev/null || echo "_(none)_"
  echo; echo "## 4b · DEEP structural anatomy — roles, states, doors, surface gaps, temporal, BOPLA, contradictions"; echo; cat "$OUT/deepmap.md" 2>/dev/null || echo "_(none — see anatomy.err)_"
  echo; echo "---"; echo "## 5 · Dissection packet (conductor — CONFIRMED Δstate + hypotheses)"; echo; cat "$OUT/packet.md" 2>/dev/null || echo "_(see conductor.log)_"
  echo; echo "## 6 · Independent general hunt (onyx_recon)"; echo '```'; cat "$OUT/recon/recon_report.md" 2>/dev/null | head -60 || echo "(see recon.log)"; echo '```'
  echo '```'; cat "$OUT/recon/recon_performance.md" 2>/dev/null | sed -n '1,40p' || true; echo '```'
  echo; echo "## 6b · crAPI specialist confirmer (hunt_crapi)"; echo '```'; cat "$OUT/hunt/crapi_report.md" 2>/dev/null | head -40 || echo "(see hunt.log)"; echo '```'
  echo '```'; cat "$OUT/hunt/crapi_performance.md" 2>/dev/null | sed -n '1,60p' || true; echo '```'
  echo; echo "## 7 · GraphQL + token probes"; echo '```'; tail -6 "$OUT/graphql.log" 2>/dev/null; echo "---"; tail -4 "$OUT/token.log" 2>/dev/null; echo '```'
  echo; echo "## 8 · Business-logic multi-step (sequences)"; echo '```'; tail -25 "$OUT/sequences.log" 2>/dev/null || true; echo '```'
  echo; echo "## 8b · Concurrency / TOCTOU double-spend (race — best-effort, doubled-signal gate)"; echo '```'; tail -12 "$OUT/race.log" 2>/dev/null || echo "(see race.log)"; echo '```'
  echo; echo "## 8c · Closed prove-loop (agent_loop — Δstate-proven, wall-guarded)"; echo '```'; tail -20 "$OUT/agentloop.log" 2>/dev/null || echo "(see agentloop.log)"; echo '```'
  echo; echo "## 9 · Engine self-diagnostics"; echo '```'; grep -iE "pass|fail|coverage|law|module|ok" "$OUT/diagnostics.log" 2>/dev/null | head -20 || echo "(see diagnostics.json)"; echo '```'
  echo; echo "---"; echo "## 10 · ONYX law-coverage matrix (the detection model)"
  echo "| effect class | law | OWASP API |"; echo "|---|---|---|"
  echo "| OBJECT_ACCESS | object_id ∈ owner envelope | API1 BOLA |"
  echo "| FIELD_PROJECTION | no private field leaks in a read | API3 |"
  echo "| OWNERSHIP | privileged field is server-authoritative | API3 BOPLA |"
  echo "| AUTHORITY | action.effect ⊆ principal envelope | API5 BFLA |"
  echo "| AUTHORITY_GRANT | grant conservation | API5 |"
  echo "| PAYMENT | amount_paid ≥ amount_due | API6 |"
  echo "| PRICE | total == Σ line items | API6 |"
  echo "| STATE_GATE | terminal state needs predecessor | API6 |"
  echo "| INVENTORY | 0 ≤ qty ≤ available | API6 |"
  echo "| COUPON | redemptions ≤ declared limit | API6 |"
  echo "| TEMPORAL_DRIFT | credential valid after revocation | — |"
  echo "| AUTH_REGRESSION | field withheld@T1 → shown@T2, no role change | — |"
  echo "| CROSS_SURFACE | non-canonical door ⊆ canonical | — |"
  echo "| STRUCTURAL_DIVERGENCE | response fits higher-privilege grammar | — |"
  echo "| EMERGENT_BREAK | child reachable while parent forbidden | — |"
  echo; echo "## 11 · Evidence tiers"
  echo "T1 independent · T2 self-measured · T3 mechanism-estimate · T4 by-construction. This run is live against a third-party target (crAPI) → CONFIRMED BOLA findings carry real T1-grade Δstate proof; precision is T4 by-construction."
  echo; echo "---"; echo "## 12 · Instructions for the analyst"
  echo "1. Study the anatomy (§2–§4) as a researcher; the ranked hypotheses name the exact probe each needs."
  echo "2. CONFIRMED items (§5, §6) are Δstate-proven — write them up directly, mapped to §10."
  echo "3. For each plausible hypothesis, name the precise probe; ONYX proves/refutes it by Δstate via \`agent_loop.py\` (Phase 6) — nothing becomes a finding without Δstate."
  echo "4. Out-of-model (injection, SSRF, JWT-crypto, rate-limit) → flag for a complementary tool; never fabricate."
} > "$REP"

echo; echo "=================================================="
echo " DONE.  Deep dissection: $REP"
echo "=================================================="
