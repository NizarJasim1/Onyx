#!/usr/bin/env bash
# =============================================================================
# auto_crapi.sh — ONE command, fully automatic, zero manual steps.
#
# It creates the accounts, sets their emails/passwords, activates a vehicle for
# each (via MailHog), places orders, exercises crAPI, and hunts — twice:
#   1) the crAPI-specialized hunter (provisions everything + writes crapi_out/…)
#   2) the GENERAL engine over crAPI's whole OpenAPI surface (recon_out/…)
# You type nothing: no emails, no passwords, no orders.
#
#   ./auto_crapi.sh                         # defaults: localhost:8888 + :8025
#   ./auto_crapi.sh --base-url http://HOST:PORT --mailhog http://HOST:8025
#
# Reads crAPI's OpenAPI spec from ./crAPI next to this repo (or set CRAPI_DIR / --crapi-dir).
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BASE="http://localhost:8888"
MAILHOG="http://localhost:8025"
CRAPI_DIR="${CRAPI_DIR:-$HERE/../crAPI}"
RESEARCHER="auto"
while [ $# -gt 0 ]; do
  case "$1" in
    --base-url) BASE="$2"; shift 2;;
    --mailhog)  MAILHOG="$2"; shift 2;;
    --crapi-dir) CRAPI_DIR="$2"; shift 2;;
    --researcher) RESEARCHER="$2"; shift 2;;
    *) echo "unknown option: $1"; exit 1;;
  esac
done
HOST="$(echo "$BASE" | sed -E 's#https?://##; s#[:/].*##')"

echo "==> 0/3  checking crAPI at $BASE"
if ! curl -fsS -o /dev/null "$BASE/"; then
  echo "✗ crAPI is not reachable at $BASE."
  echo "  Start it first:"
  echo "    cd $CRAPI_DIR/deploy/docker && docker compose up -d"
  echo "  then re-run ./scripts/auto_crapi.sh"
  exit 1
fi
echo "    crAPI is up."

echo "==> 1/3  provision + crAPI-specialized hunt (creates accounts, vehicles, orders — automatic)"
"$HERE/scripts/run.sh" --full --confirm --mailhog "$MAILHOG" --base-url "$BASE" --researcher "$RESEARCHER" --out "$HERE/crapi_out"

STATE="$HERE/crapi_out/state.json"
if [ ! -f "$STATE" ]; then
  echo "✗ provisioning did not produce $STATE — see the output above."
  exit 1
fi

echo "==> 2/3  locating crAPI OpenAPI spec"
SPEC=""
for c in "$CRAPI_DIR/openapi-spec/crapi-openapi-spec.json" \
         "$CRAPI_DIR/services/web/src/resources/crapi-openapi-spec.json"; do
  [ -f "$c" ] && SPEC="$c" && break
done
if [ -z "$SPEC" ]; then
  SPEC="$(find "$CRAPI_DIR" -iname '*openapi*spec*.json' 2>/dev/null | head -n1 || true)"
fi
if [ -z "$SPEC" ]; then
  # not cloned locally — fetch the official spec straight from GitHub (no clone needed)
  echo "    no local spec; downloading the official crAPI OpenAPI spec from GitHub…"
  SPEC="$HERE/crapi_out/crapi-openapi-spec.json"; mkdir -p "$HERE/crapi_out"
  for URL in \
    "https://raw.githubusercontent.com/OWASP/crAPI/main/openapi-spec/crapi-openapi-spec.json" \
    "https://raw.githubusercontent.com/OWASP/crAPI/develop/openapi-spec/crapi-openapi-spec.json"; do
    if curl -fsSL "$URL" -o "$SPEC" 2>/dev/null && [ -s "$SPEC" ]; then
      echo "    fetched spec from $URL"; break
    fi
    SPEC=""
  done
fi
if [ -z "$SPEC" ] || [ ! -s "$SPEC" ]; then
  echo "! could not obtain the OpenAPI spec (offline?) — skipping the general-engine pass."
  echo "  (The specialized report is ready in crapi_out/.)  Pass --crapi-dir to point at a clone."
  echo; echo "Done. See: $HERE/crapi_out/crapi_report.md"; exit 0
fi
echo "    spec: $SPEC"

echo "==> 3/3  general engine over crAPI's whole surface (auto-loads the accounts just created)"
"$HERE/scripts/recon.sh" --authorized \
  --base-url "$BASE" --scope "$HOST" \
  --openapi "$SPEC" \
  --login-url /identity/api/auth/login \
  --state "$STATE" \
  --researcher "$RESEARCHER" \
  --confirm --delay 0.1,0.3 \
  --out "$HERE/recon_out"

echo
echo "================ DONE — reports ================"
echo "  crAPI-specialized : $HERE/crapi_out/crapi_report.md   (+ crapi_performance.md)"
echo "  general engine    : $HERE/recon_out/recon_report.md   (+ recon_performance.md)"
echo "  submission packs  : $HERE/crapi_out/submission_pack/   $HERE/recon_out/submission_pack/"
