#!/usr/bin/env bash
# =============================================================================
# crapi_deep.sh — FULL, hands-off ONYX level-test on a live crAPI.
#
#   1) SEED   : populate crAPI (vehicles, orders, mechanic reports, coupon) so the
#               whole in-scope challenge set has real objects to attack.
#   2) ATTACK : run ONYX (hunt_crapi) with EVERY id wired, TWICE (determinism),
#               with --confirm so write/business-logic challenges are driven too.
#   3) REPORT : collect findings + the honest capability-coverage map into one file.
#
# One command, no manual id-copying:
#   ./crapi_deep.sh --base-url http://localhost:8888 --mailhog http://localhost:8025
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

BASE="http://localhost:8888"; MH="http://localhost:8025"
while [ $# -gt 0 ]; do case "$1" in
  --base-url) BASE="$2"; shift 2;; --mailhog) MH="$2"; shift 2;;
  *) echo "unknown arg: $1"; exit 1;; esac; done

PY="python3"; [ -x "$ROOT/.venv/bin/python" ] && PY="$ROOT/.venv/bin/python"
$PY -c "import requests" 2>/dev/null || { python3 -m venv "$ROOT/.venv" && "$ROOT/.venv/bin/python" -m pip -q install requests; PY="$ROOT/.venv/bin/python"; }

TS="$(date +%Y%m%d_%H%M%S)"; OUT="$ROOT/crapi_deep_$TS"; mkdir -p "$OUT"
SEEDDIR="$OUT/seed"; mkdir -p "$SEEDDIR"

echo "== 1/3  SEEDING crAPI (accounts, vehicles, orders, mechanic reports) =="
$PY external_targets/crapi_seed.py --base-url "$BASE" --mailhog "$MH" --out "$SEEDDIR" \
    2>&1 | tee "$OUT/seed.log"
[ -f "$SEEDDIR/seed.json" ] || { echo "✗ seeding failed — see $OUT/seed.log"; exit 1; }

# pull wired ids out of seed.json
read -r AE AP BE BP AO BO AR BR < <($PY - "$SEEDDIR/seed.json" <<'PYEOF'
import json,sys
s=json.load(open(sys.argv[1]))
a,b=s["accounts"]["A"],s["accounts"]["B"]; ids=s["ids"]
def c(p,k): return ",".join(ids[p].get(k) or []) or "-"
print(a["email"],a["password"],b["email"],b["password"],
      c("A","orders"),c("B","orders"),c("A","reports"),c("B","reports"))
PYEOF
)
echo "  wired -> A.orders=$AO B.orders=$BO A.reports=$AR B.reports=$BR"

fix(){ [ "$1" = "-" ] && echo "" || echo "$1"; }
run_hunt(){  # run_hunt <outdir>
  $PY external_targets/hunt_crapi.py --confirm \
    --base-url "$BASE" --mailhog "$MH" \
    --a-email "$AE" --a-pass "$AP" --b-email "$BE" --b-pass "$BP" \
    --a-orders "$(fix "$AO")" --b-orders "$(fix "$BO")" \
    --a-reports "$(fix "$AR")" --b-reports "$(fix "$BR")" \
    --coupon TRAC075 --researcher me --out "$1"
}

echo "== 2/3  ATTACK run 1 =="
run_hunt "$OUT/run1" 2>&1 | tee "$OUT/attack_run1.log"
echo "== 2/3  ATTACK run 2 (determinism check) =="
run_hunt "$OUT/run2" 2>&1 | tee "$OUT/attack_run2.log"

echo "== 3/3  BUILDING combined report =="
REP="$OUT/FULL_REPORT.md"
{
  echo "# ONYX — full crAPI level test ($TS)"; echo
  echo "## Seed summary"; echo '```'; cat "$SEEDDIR/seed.json"; echo '```'; echo
  echo "## Confirmed findings (run 1)"; echo '```'; cat "$OUT/run1/crapi_report.md" 2>/dev/null; echo '```'; echo
  echo "## Capability & coverage (run 1)"; echo '```'; cat "$OUT/run1/crapi_performance.md" 2>/dev/null; echo '```'; echo
  echo "## Determinism check"
  if diff -q "$OUT/run1/crapi_report.md" "$OUT/run2/crapi_report.md" >/dev/null 2>&1; then
     echo "- ✅ run1 == run2 (identical findings)"; else
     echo "- ⚠ run1 vs run2 differ (ids differ per fresh objects; compare finding COUNT/CLASSES):"; echo '```'; diff "$OUT/run1/crapi_report.md" "$OUT/run2/crapi_report.md" 2>/dev/null | head -40; echo '```'; fi
} > "$REP"

echo; echo "=================================================="
echo " DONE.  Full report: $REP"
echo " Read the report:  cat \"$REP\""
echo "=================================================="
