#!/usr/bin/env bash
# =============================================================================
# ONYX crAPI hunter — one command to set up AND run.
#
# Creates a local virtual environment (.venv) the first time, installs `requests`
# into it (never touches your system Python — no --break-system-packages, no sudo),
# then runs the tool with whatever arguments you pass. Re-runs are instant.
#
#   ./run.sh --doctor                    # only check the connection + credentials
#   ./run.sh --full --confirm            # sign up accounts, sweep, write both reports
#   ./run.sh --full --confirm --mailhog http://localhost:8025
#   ./run.sh --a-email a@x.com --a-pass 'P!' --b-email b@x.com --b-pass 'P!'
#
# Everything after ./run.sh is passed straight to hunt_crapi.py.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$HERE/.venv"
PY="${PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "✗ python3 not found. Install Python 3, then re-run." >&2
  exit 1
fi

# 1) create the venv once
if [ ! -x "$VENV/bin/python" ]; then
  echo "· creating virtual environment (.venv) …"
  if ! "$PY" -m venv "$VENV" 2>/tmp/onyx_venv_err; then
    echo "✗ could not create the venv. Install the venv module, then re-run:" >&2
    echo "    sudo apt install -y python3-venv        # Debian / Kali / Ubuntu" >&2
    echo "    sudo dnf install -y python3-virtualenv  # Fedora / RHEL" >&2
    exit 1
  fi
fi

# 2) install requests into the venv only if missing (keeps re-runs instant)
if ! "$VENV/bin/python" -c "import requests" >/dev/null 2>&1; then
  echo "· installing requests into .venv …"
  "$VENV/bin/python" -m pip install -q --disable-pip-version-check requests
fi

# 3) run the tool with all passed-through arguments
exec "$VENV/bin/python" "$HERE/external_targets/hunt_crapi.py" "$@"
