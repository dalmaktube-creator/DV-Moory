#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$ROOT/install.sh" "$ROOT"/scripts/*.sh "$ROOT/scripts/moory" "$ROOT/scripts/moory-setup"
python3 -m py_compile "${ROOT}/src/moory/server.py"
python3 "${ROOT}/tests/test_static_security.py"
echo "All tests passed"
