#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python3 -m py_compile "${ROOT}/src/moory/server.py"
python3 "${ROOT}/tests/test_static_security.py"
echo "All tests passed"
