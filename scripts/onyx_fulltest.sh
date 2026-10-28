#!/usr/bin/env bash
# =============================================================================
# onyx_fulltest.sh — ONE-COMMAND, comprehensive + harsh test battery for ONYX.
#
# Two phases:
#   PHASE A  (offline, always runs) — proves the METHOD is sound & zero-FP:
#       core suite, labeled demo, every FP-adversary trap, every measure/adversary
#       layer, the randomized proving-world distribution, the chaos/anvil curve,
#       the blind external-taxonomy benchmark, and the VAmPI (3rd-party) anchor.
#   PHASE B  (live crAPI, runs only if --base-url is given) — proves it on the
#       real, independently-authored target: full auto hunt, run TWICE to check
#       determinism, reports + honest coverage map collected.
#
# Minimal input. Example:
#   ./onyx_fulltest.sh                                   # offline battery only
#   ./onyx_fulltest.sh --base-url http://localhost:8888 --mailhog http://localhost:8025 --researcher me
#
# Everything lands in ./onyx_testrun_<timestamp>/  (logs + SUMMARY.md).
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE_URL=""; MAILHOG=""; RESEARCHER="tester"; TIMEOUT="${TIMEOUT:-180}"
while [ $# -gt 0 ]; do case "$1" in
  --base-url) BASE_URL="$2"; shift 2;;
  --mailhog) MAILHOG="$2"; shift 2;;
  --researcher) RESEARCHER="$2"; shift 2;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done

# pick a python that has requests for the LIVE phase; offline phase is pure stdlib
PY="python3"
if [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"; fi

TS="$(date +%Y%m%d_%H%M%S)"
OUT="$ROOT/onyx_testrun_$TS"; LOGS="$OUT/logs"; mkdir -p "$LOGS"
SUM="$OUT/SUMMARY.md"
PASS=0; FAIL=0

echo "# ONYX full test — $TS" > "$SUM"
echo "" >> "$SUM"

run () {  # run <label> <cmd...>
  local label="$1"; shift
  local log="$LOGS/${label}.log"
  printf "· %-34s " "$label"
  timeout "$TIMEOUT" "$@" >"$log" 2>&1
  local rc=$?
  local last; last="$(tail -n 1 "$log" 2>/dev/null | cut -c1-90)"
  if [ $rc -eq 0 ]; then
    echo "PASS"; PASS=$((PASS+1))
    echo "- ✅ **$label** — $last" >> "$SUM"
  else
    echo "FAIL (rc=$rc)"; FAIL=$((FAIL+1))
    echo "- ❌ **$label** (rc=$rc) — $last" >> "$SUM"
  fi
}

echo "== PHASE A : method soundness (offline) =="
echo "## Phase A — method soundness (offline)" >> "$SUM"
run core_suite            $PY tests/run_all.py
run labeled_demo          $PY -m authpath demo

echo "### FP adversarial traps (must confirm ZERO, must still catch controls)" >> "$SUM"
for f in external_targets/audit_fp.py external_targets/audit_fp_hard.py \
         external_targets/audit_fp_hard2.py external_targets/audit_fp_advanced.py; do
  run "$(basename "$f" .py)" $PY "$f"
done

echo "### per-layer adversary (each must add 0 FP)" >> "$SUM"
for f in external_targets/adversary_*.py; do
  run "$(basename "$f" .py)" $PY "$f"
done

echo "### per-layer measured recall/precision" >> "$SUM"
for f in external_targets/measure_*.py; do
  run "$(basename "$f" .py)" $PY "$f"
done

echo "### distribution / chaos / blind / third-party" >> "$SUM"
run proving_world         $PY proving_world/harness.py
run chaos_anvil           $PY proving_world/chaos_harness.py
run blind_cert            $PY proving_world/blind_cert_benchmark.py
run vampi_thirdparty      $PY external_targets/run_vampi.py

# ---------------------------------------------------------------------------
if [ -n "$BASE_URL" ]; then
  echo ""; echo "== PHASE B : live crAPI (real, third-party target) =="
  echo "" >> "$SUM"; echo "## Phase B — live crAPI ($BASE_URL)" >> "$SUM"
  if ! $PY -c "import requests" 2>/dev/null; then
    echo "  installing requests into .venv …"
    python3 -m venv "$ROOT/.venv" 2>/dev/null && "$ROOT/.venv/bin/python" -m pip -q install requests
    PY="$ROOT/.venv/bin/python"
  fi
  MH=(); [ -n "$MAILHOG" ] && MH=(--mailhog "$MAILHOG")

  run crapi_doctor $PY external_targets/hunt_crapi.py --doctor --base-url "$BASE_URL" "${MH[@]}"

  # run 1
  run crapi_hunt_run1 $PY external_targets/hunt_crapi.py --full --confirm \
      --base-url "$BASE_URL" "${MH[@]}" --researcher "$RESEARCHER" --out "$OUT/crapi_run1" --fresh
  # run 2 (fresh accounts again) — determinism of VERDICTS, not of ids
  run crapi_hunt_run2 $PY external_targets/hunt_crapi.py --full --confirm \
      --base-url "$BASE_URL" "${MH[@]}" --researcher "$RESEARCHER" --out "$OUT/crapi_run2" --fresh

  # surface the two human reports + coverage map
  for r in crapi_run1/crapi_report.md crapi_run1/crapi_performance.md; do
    [ -f "$OUT/$r" ] && { echo ""; echo "### $r"; echo '```'; sed -n '1,40p' "$OUT/$r"; echo '```'; } >> "$SUM"
  done
else
  echo "" >> "$SUM"
  echo "## Phase B — SKIPPED (no --base-url; offline battery only)" >> "$SUM"
fi

echo "" >> "$SUM"
echo "## Tally: $PASS passed, $FAIL failed" >> "$SUM"
echo ""
echo "=================================================="
echo " DONE — $PASS passed, $FAIL failed"
echo " Full results: $OUT/"
echo " Summary:      $SUM"
echo "=================================================="
