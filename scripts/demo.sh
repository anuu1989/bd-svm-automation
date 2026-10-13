#!/usr/bin/env bash
# Both phases end to end against devtools/mock_blackduck.py (no credentials).
set -euo pipefail
PY="${PY:-.venv/bin/python}"
PORT="${PORT:-8098}"

export BD_HOST="http://127.0.0.1:$PORT" BD_API_KEY=mock BD_HTTP_RETRIES=0 BD_VULN_WAIT_SECONDS=5
export STATE_FILE="${STATE_FILE:-$(mktemp -d)/state.json}"

$PY -m devtools.mock_blackduck --port "$PORT" >/dev/null &
MOCK=$!
trap 'kill $MOCK 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -fs "$BD_HOST/mock/state" >/dev/null && break; sleep 0.2; done

echo ">>> baseline:        $(curl -s "$BD_HOST/mock/state" | $PY -c 'import json,sys; print(json.load(sys.stdin)["count"])') components"
echo ">>> smoke test";     $PY -m pytest -q tests/test_api_health.py
echo ">>> PHASE 1 (12)";   $PY -m pytest -q tests/phase1
echo ">>> state.json:";    cat "$STATE_FILE"
echo ">>> after phase 1:   $(curl -s "$BD_HOST/mock/state" | $PY -c 'import json,sys; print(json.load(sys.stdin)["count"])') components"
echo ">>> PHASE 2 (5)";    $PY -m pytest -q tests/phase2
echo ">>> after phase 2:   $(curl -s "$BD_HOST/mock/state" | $PY -c 'import json,sys; print(json.load(sys.stdin)["count"])') components (baseline restored)"
