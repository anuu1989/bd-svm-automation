#!/usr/bin/env bash
# Full demo against the in-process mock Black Duck/SVM: no credentials needed.
set -euo pipefail
PY="${PY:-.venv/bin/python}"
CFG="${CFG:-config/config.mock.yaml}"
PORT="${PORT:-8099}"

rm -f data/mock-state.db
$PY -m bd_svm.mock_server --port "$PORT" >/dev/null &
MOCK=$!
trap 'kill $MOCK 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/mock/state" >/dev/null && break; sleep 0.2; done

echo ">>> start (adds 4 components: standard, remediation, upgrade, negative)"
$PY -m bd_svm -c "$CFG" start
echo ">>> drain (polls SVM until both tests finish)"
$PY -m bd_svm -c "$CFG" drain --fast
echo ">>> report"
$PY -m bd_svm -c "$CFG" report
echo ">>> mock BOM afterwards (must be empty):"
curl -s "http://127.0.0.1:$PORT/mock/state"; echo
