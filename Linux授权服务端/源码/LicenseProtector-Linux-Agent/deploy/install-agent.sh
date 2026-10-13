#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <path-to-license-protector-source>" >&2
  exit 2
fi
SOURCE_ROOT=$(CDPATH= cd -- "$1" && pwd)
INSTALL_ROOT=/opt/license-protector-agent
python3 -m venv "$INSTALL_ROOT/venv"
"$INSTALL_ROOT/venv/bin/python" -m pip install --no-deps "$SOURCE_ROOT"
"$INSTALL_ROOT/venv/bin/python" -m pip install 'cryptography>=41'
echo "Agent installed at $INSTALL_ROOT"
