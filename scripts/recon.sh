#!/usr/bin/env bash
# One command to set up + run the GENERAL recon engine (onyx_recon.py) on any
# authorized target. Shares the same .venv as run.sh; installs requests if missing.
#
#   ./recon.sh --authorized --base-url http://localhost:8888 \
#       --openapi ./crapi-openapi-spec.json \
#       --login-url /identity/api/auth/login \
#       --principal A:a@x.com:Pass1! --principal B:b@x.com:Pass1! --confirm
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$HERE/.venv"; PY="${PYTHON:-python3}"
if [ ! -x "$VENV/bin/python" ]; then
  echo "· creating virtual environment (.venv) …"
  "$PY" -m venv "$VENV" 2>/dev/null || { echo "✗ install python3-venv: sudo apt install -y python3-venv"; exit 1; }
fi
if ! "$VENV/bin/python" -c "import requests" >/dev/null 2>&1; then
  echo "· installing requests into .venv …"
  "$VENV/bin/python" -m pip install -q --disable-pip-version-check requests
fi
exec "$VENV/bin/python" "$HERE/external_targets/onyx_recon.py" "$@"
