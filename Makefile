.DEFAULT_GOAL := help
SHELL := /bin/bash

PY      ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
PYTEST  := $(BIN)/python -m pytest
REPORTS := reports
WAIT_HOURS ?= 4

.PHONY: help venv install install-dev health phase1 phase2 cycle state-show report \
        selftest demo mock-server lint fix test ci clean distclean

help:  ## Show this help
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z_-]+:.*## /{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}' $(MAKEFILE_LIST)

$(BIN)/python:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

venv: $(BIN)/python  ## Create the virtualenv

install: venv  ## Install runtime dependencies
	$(BIN)/pip install -q -r requirements.txt

install-dev: install  ## Install dev tools (ruff)
	$(BIN)/pip install -q -r requirements-dev.txt

# ---- the two phases ---------------------------------------------------------------------
health: install  ## Smoke test: auth, version, project, version, KB component (read-only)
	@mkdir -p $(REPORTS)
	$(PYTEST) tests/test_api_health.py --html=$(REPORTS)/health-report.html --self-contained-html

phase1: install  ## PHASE 1: add component, verify, remediate, write state.json (12 steps)
	@mkdir -p $(REPORTS)
	$(PYTEST) tests/phase1 --html=$(REPORTS)/phase1-report.html --self-contained-html

phase2: install  ## PHASE 2: load state.json, delete component, verify baseline restored (5 steps)
	@mkdir -p $(REPORTS)
	$(PYTEST) tests/phase2 --html=$(REPORTS)/phase2-report.html --self-contained-html

cycle: install  ## Full cycle locally: health, phase1, wait WAIT_HOURS (default 4; 0 = none), phase2
	$(MAKE) health phase1
	@if [ "$(WAIT_HOURS)" != "0" ]; then echo "waiting $(WAIT_HOURS)h before phase 2 ..."; \
	  sleep $$(python3 -c "print(int(float('$(WAIT_HOURS)')*3600))"); fi
	$(MAKE) phase2

state-show:  ## Print state.json (written by phase 1, read by phase 2)
	@test -f state.json && cat state.json || echo "no state.json - run: make phase1"

report:  ## Open the HTML reports (macOS: open, Linux: xdg-open)
	@for f in $(REPORTS)/*.html; do (open "$$f" 2>/dev/null || xdg-open "$$f" 2>/dev/null || echo "$$f"); done

# ---- no credentials needed ----------------------------------------------------------------
selftest: install  ## Framework self-tests: state, auth cache, phases vs mock incl. failure paths
	$(BIN)/python -m unittest devtools.test_selftest

demo: install  ## Both phases end to end against the mock Black Duck
	PY=$(BIN)/python ./scripts/demo.sh

mock-server: install  ## Run the mock Black Duck on :8099 (BD_HOST=http://127.0.0.1:8099 BD_API_KEY=x)
	$(BIN)/python -m devtools.mock_blackduck --port 8099

# ---- quality ------------------------------------------------------------------------------
lint: install-dev  ## ruff
	$(BIN)/ruff check .

fix: install-dev  ## ruff --fix
	$(BIN)/ruff check . --fix

test: selftest  ## Alias of selftest

ci: lint selftest demo  ## What CI runs

clean:  ## Remove caches and reports
	find . -name __pycache__ -type d -prune -not -path "./.venv/*" -exec rm -rf {} +
	rm -rf reports .pytest_cache

distclean: clean  ## Also remove the venv and state.json
	rm -rf $(VENV) state.json
