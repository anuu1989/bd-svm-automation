.DEFAULT_GOAL := help
SHELL := /bin/bash

PY      ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
CONFIG  ?= config/config.yaml
CLI     := $(BIN)/python -m bd_svm $(if $(wildcard $(CONFIG)),--config $(CONFIG))
RUN_ID  ?=

# Parameters for the bd-* recipes (override on the command line: make bd-add NAME=log4j-core CV=2.14.1 YES=1)
NAME    ?=
CV      ?=
VULN    ?=
STATUS  ?= IGNORED
COMMENT ?=
PROJECT ?=
VERSION ?=
METHOD  ?= GET
API_PATH ?=
DATA    ?=
HREF    ?=
YES     ?=
BD      := $(CLI) bd
SCOPE   := $(if $(PROJECT),--project "$(PROJECT)") $(if $(VERSION),--version "$(VERSION)")
COMP    := $(if $(HREF),--href "$(HREF)",--name "$(NAME)" --component-version "$(CV)")
CONFIRM := $(if $(YES),--yes)

.PHONY: help venv install install-ui install-dev config test lint fix check ci doctor start tick tick-idle loop status \
        status-json report cleanup smoke clean distclean db-backup db-reset \
        bd-whoami bd-projects bd-versions bd-bom bd-vulns bd-search bd-component-vulns bd-vuln \
        bd-upgrade bd-policy bd-risk bd-bom-status bd-codelocations bd-add bd-delete bd-ignore \
        bd-unignore bd-remediate bd-create-project bd-create-version bd-delete-version \
        bd-delete-project bd-api svm-check svm-check-absent pipeline-trigger need-name need-vuln \
        drain sweep sweep-apply notify-test report-junit report-json mock-server demo \
        state-pull state-push docker-build docker-run

help:  ## Show this help
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z_-]+:.*## /{printf "  \033[36m%-20s\033[0m %s\n",$$1,$$2}' $(MAKEFILE_LIST)

$(BIN)/python:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

venv: $(BIN)/python  ## Create virtualenv

install: venv  ## Install runtime dependencies
	$(BIN)/pip install -r requirements.txt

install-ui: install  ## Also install Selenium for the SVM UI check
	$(BIN)/pip install -r requirements-ui.txt

install-dev: install  ## Install dev tools (ruff)
	$(BIN)/pip install -q -r requirements-dev.txt

config:  ## Create config/config.yaml and .env from the examples (never overwrites)
	@test -f $(CONFIG) || cp config/config.example.yaml $(CONFIG)
	@test -f .env || cp .env.example .env
	@echo "Edit $(CONFIG) and .env, then run: make doctor"

test: install  ## Run unit + lifecycle tests (no network needed)
	$(BIN)/python -m unittest discover -s tests -v

doctor: install  ## Validate config and Black Duck connectivity
	$(CLI) doctor

start: install  ## Start one cycle: find -> add -> verify in Black Duck -> save
	$(CLI) start

tick: install  ## Advance runs whose 8h wait elapsed (run from cron / CI schedule)
	$(CLI) tick

tick-idle: install  ## tick, and start a new cycle if nothing is active (best for cron)
	$(CLI) tick --start-if-idle

loop: install  ## Run continuously (foreground daemon)
	$(CLI) loop

status: install  ## Show runs and when the next step is due
	$(CLI) status

report: install  ## Write reports/report.md
	@mkdir -p reports
	$(CLI) report -o reports/report.md

cleanup: install  ## Abort + remove component from Black Duck: make cleanup RUN_ID=<id>
	@test -n "$(RUN_ID)" || (echo "usage: make cleanup RUN_ID=<run id>"; exit 1)
	$(CLI) cleanup $(RUN_ID)

smoke: install  ## Quick real-system run: tiny deadline (--wait-hours 0.01), start then drain
	$(CLI) --wait-hours 0.01 start
	$(CLI) --wait-hours 0.01 drain --fast
	$(CLI) status

drain: install  ## Tick until no run is active (one-shot CI job / demo)
	$(CLI) drain

sweep: install  ## Find orphaned test components in the test BOM (dry run)
	$(CLI) sweep

sweep-apply: install  ## Delete orphaned test components, needs YES=1
	@test -n "$(YES)" || (echo "sweep-apply deletes from Black Duck: re-run with YES=1 (preview with: make sweep)"; exit 1)
	$(CLI) sweep --apply

notify-test: install  ## Send a test notification to NOTIFY_WEBHOOK_URL
	$(CLI) notify-test

lint: install-dev  ## ruff + byte-compile
	$(BIN)/ruff check .
	$(BIN)/python -m compileall -q bd_svm tests

fix: install-dev  ## ruff --fix
	$(BIN)/ruff check . --fix

check: lint test  ## lint + tests

ci: check  ## What CI should run

report-junit: install  ## Write reports/junit.xml (CI test tab)
	@mkdir -p reports
	$(CLI) report --format junit -o reports/junit.xml

report-json: install  ## Write reports/summary.json (incl. sync latency stats)
	@mkdir -p reports
	$(CLI) report --format json -o reports/summary.json

status-json: install  ## Full run details (events, results) as JSON
	$(CLI) status --json

db-backup:  ## Copy the state DB to data/state.db.<timestamp>
	@test -f data/state.db && cp data/state.db data/state.db.$$(date +%Y%m%d%H%M%S) && echo backed up || echo "no state db"

db-reset:  ## Delete the state DB (asks first). Active runs are forgotten - cleanup in BD first!
	@read -p "Delete data/state.db? [y/N] " a && [ "$$a" = y ] && rm -f data/state.db && echo removed || echo kept

# ---- Black Duck ad-hoc API recipes -------------------------------------------
# Read-only unless noted. Mutating recipes require YES=1.
# Scope to another project/version with PROJECT=... VERSION=...
# Identify a component with NAME=... CV=<component version>, or HREF=<url>.
need-name:
	@test -n "$(HREF)$(NAME)" || (echo "set NAME=<component> CV=<version> (or HREF=)"; exit 1)

need-vuln:
	@test -n "$(VULN)" || (echo "set VULN=<CVE/BDSA id>"; exit 1)

bd-whoami: install  ## BD: current user and server version
	$(BD) whoami

bd-projects: install  ## BD: list projects (optional NAME=filter)
	$(BD) projects $(if $(NAME),--name "$(NAME)")

bd-versions: install  ## BD: list versions of the configured project
	$(BD) versions $(SCOPE)

bd-bom: install  ## BD: list BOM components
	$(BD) bom $(SCOPE)

bd-vulns: install  ## BD: list vulnerable BOM components
	$(BD) vulns $(SCOPE)

bd-search: install  ## BD: search KB components: NAME=log4j (add VERSIONS=1 to list versions)
	@test -n "$(NAME)" || (echo "set NAME="; exit 1)
	$(BD) search "$(NAME)" $(if $(VERSIONS),--versions)

bd-component-vulns: install need-name  ## BD: vulnerabilities of NAME CV
	$(BD) component-vulns $(COMP)

bd-vuln: install need-vuln  ## BD: vulnerability details: VULN=CVE-2021-44228
	$(BD) vuln "$(VULN)"

bd-upgrade: install need-name  ## BD: upgrade guidance for NAME CV
	$(BD) upgrade-guidance $(COMP)

bd-policy: install  ## BD: policy status of the version
	$(BD) policy $(SCOPE)

bd-risk: install  ## BD: risk profile of the version
	$(BD) risk $(SCOPE)

bd-bom-status: install  ## BD: BOM processing status
	$(BD) bom-status $(SCOPE)

bd-codelocations: install  ## BD: list code locations (scans)
	$(BD) codelocations

bd-add: install need-name  ## BD (writes): add NAME CV to BOM, needs YES=1
	$(BD) add $(SCOPE) $(COMP) $(CONFIRM)

bd-delete: install need-name  ## BD (writes): delete NAME CV from BOM, needs YES=1
	$(BD) delete $(SCOPE) $(COMP) $(CONFIRM)

bd-ignore: install need-name  ## BD (writes): ignore NAME CV in BOM, needs YES=1
	$(BD) ignore $(SCOPE) $(COMP) $(CONFIRM)

bd-unignore: install need-name  ## BD (writes): un-ignore NAME CV, needs YES=1
	$(BD) ignore $(SCOPE) $(COMP) --undo $(CONFIRM)

bd-remediate: install need-name need-vuln  ## BD (writes): set remediation STATUS on VULN, needs YES=1
	$(BD) remediate $(SCOPE) $(COMP) --vuln-id "$(VULN)" --status "$(STATUS)" --comment "$(COMMENT)" $(CONFIRM)

bd-create-project: install  ## BD (writes): create project NAME, needs YES=1
	@test -n "$(NAME)" || (echo "set NAME="; exit 1)
	$(BD) create-project "$(NAME)" $(CONFIRM)

bd-create-version: install  ## BD (writes): create version VERSION in project PROJECT, needs YES=1
	@test -n "$(PROJECT)$(VERSION)" || (echo "set PROJECT= and VERSION="; exit 1)
	$(BD) create-version "$(PROJECT)" "$(VERSION)" $(CONFIRM)

bd-delete-version: install  ## BD (writes): delete PROJECT/VERSION, needs YES=1
	@test -n "$(PROJECT)$(VERSION)" || (echo "set PROJECT= and VERSION="; exit 1)
	$(BD) delete-version $(SCOPE) $(CONFIRM)

bd-delete-project: install  ## BD (writes): delete project NAME, needs YES=1
	@test -n "$(NAME)" || (echo "set NAME="; exit 1)
	$(BD) delete-project "$(NAME)" $(CONFIRM)

bd-api: install  ## BD: any endpoint: make bd-api METHOD=GET API_PATH=/api/projects [DATA='{...}' YES=1]
	@test -n "$(API_PATH)" || (echo "set API_PATH=/api/..."; exit 1)
	$(BD) api $(METHOD) "$(API_PATH)" $(if $(DATA),--data '$(DATA)') $(CONFIRM)

# ---- SVM / pipeline --------------------------------------------------------------
svm-check: install need-name  ## SVM: is NAME CV (VULN optional) present? exit 1 if not
	$(CLI) svm-check --name "$(NAME)" --component-version "$(CV)" --vuln-id "$(VULN)"

svm-check-absent: install need-name  ## SVM: is NAME CV absent? (delete test) exit 1 if still present
	$(CLI) svm-check --name "$(NAME)" --component-version "$(CV)" --vuln-id "$(VULN)" --expect-absent

pipeline-trigger: install  ## Trigger the verification pipeline now
	$(CLI) pipeline-trigger

# ---- Demo / mock -------------------------------------------------------------------
mock-server: install  ## Run the fake Black Duck + SVM + pipeline on :8099
	$(BIN)/python -m bd_svm.mock_server --port 8099

demo: install  ## Full flow against the mock: all scenarios, no credentials
	PY=$(BIN)/python ./scripts/demo.sh

# ---- Durable state (for CI runners) ---------------------------------------------------
state-pull:  ## Restore data/state.db (STATE_BACKEND=git-branch|s3|none)
	./scripts/state.sh pull

state-push:  ## Save data/state.db (STATE_BACKEND=git-branch|s3|none)
	./scripts/state.sh push

# ---- Container -------------------------------------------------------------------------
docker-build:  ## Build the image (WITH_UI=1 to include Chromium + Selenium)
	docker build --build-arg WITH_UI=$(or $(WITH_UI),0) -t bd-svm .

docker-run:  ## Run a command in the image: make docker-run ARGS="tick --start-if-idle"
	docker run --rm --env-file .env -v "$$PWD/data:/app/data" -v "$$PWD/config:/app/config" bd-svm $(ARGS)

clean:  ## Remove caches and reports
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf reports

distclean: clean  ## Also remove venv and state DB
	rm -rf $(VENV) data
