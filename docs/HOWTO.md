# How-to guide

Task-oriented steps for working with the Black Duck → SVM sync test. For the
design see [ARCHITECTURE.md](ARCHITECTURE.md); for every setting see
[CONFIGURATION.md](CONFIGURATION.md).

**Contents**

1. [Try it in two minutes (no credentials)](#1-try-it-in-two-minutes-no-credentials)
2. [Connect to your Black Duck](#2-connect-to-your-black-duck)
3. [Choose which components to test](#3-choose-which-components-to-test)
4. [Wire up the SVM API check](#4-wire-up-the-svm-api-check)
5. [Wire up the pipeline trigger](#5-wire-up-the-pipeline-trigger)
6. [Run your first real cycle](#6-run-your-first-real-cycle)
7. [Schedule it](#7-schedule-it)
8. [Read the results](#8-read-the-results)
9. [Deal with failures and leftovers](#9-deal-with-failures-and-leftovers)
10. [Get notified](#10-get-notified)
11. [Add the SVM UI check](#11-add-the-svm-ui-check)
12. [Test more, faster](#12-test-more-faster)
13. [Do one-off Black Duck operations](#13-do-one-off-black-duck-operations)
14. [Adapt to a different Black Duck version](#14-adapt-to-a-different-black-duck-version)
15. [Run in Docker or GitHub Actions](#15-run-in-docker-or-github-actions)

---

## 1. Try it in two minutes (no credentials)

```bash
make demo
```

This starts a fake Black Duck + SVM + pipeline on `127.0.0.1:8099`, runs one
cycle with four components (one per scenario), polls until both the ADD and
DELETE tests pass, prints the report, and shows the fake BOM is empty
afterwards. Use it to see what a successful run looks like before touching
real systems.

To poke at the mock yourself:

```bash
make mock-server                     # terminal 1
python -m bd_svm -c config/config.mock.yaml start      # terminal 2
python -m bd_svm -c config/config.mock.yaml status
curl localhost:8099/mock/state       # BOM + what SVM currently shows
```

## 2. Connect to your Black Duck

1. Create a **dedicated** project and version in Black Duck (for example
   `svm-e2e-test` / `main`). The tool adds and deletes components in its BOM —
   never point it at a real product BOM.
2. Create an API token for a user with write access to that project.
3. Set up the config files:

   ```bash
   make config            # copies config.example.yaml -> config/config.yaml, .env.example -> .env
   ```

4. Edit `.env`:

   ```ini
   BLACKDUCK_URL=https://blackduck.mycompany.com
   BLACKDUCK_API_TOKEN=<token>
   BLACKDUCK_PROJECT=svm-e2e-test
   BLACKDUCK_PROJECT_VERSION=main
   ```

5. Check the connection:

   ```bash
   make doctor            # config valid? auth OK? project/version found?
   make bd-whoami         # which user and server version
   ```

If `doctor` says the project is not found, fix the names or the token's access.
A TLS error means a self-signed certificate: set `blackduck.verify_ssl: false`
(lab only) in `config/config.yaml`.

## 3. Choose which components to test

The tool needs components that exist in the Black Duck knowledge base. Check
what is available:

```bash
make bd-search NAME=log4j-core VERSIONS=1          # versions of a component
make bd-component-vulns NAME=log4j-core CV=2.14.1  # its vulnerabilities
```

Then list them under `blackduck.candidates` in `config/config.yaml`:

```yaml
blackduck:
  candidates:
    - { name: log4j-core, version: "2.14.1" }                        # standard
    - { name: jackson-databind, version: "2.9.8",
        scenario: remediation, status: IGNORED }                     # status must show in SVM
    - { name: commons-text, version: "1.9",
        scenario: upgrade, upgrade_to: "1.10.0" }                    # swap to fixed version
    - { name: some-clean-lib, version: "1.0.0", scenario: negative } # no vulns: must NOT show
test:
  batch_size: 3          # how many candidates per cycle
```

Rules of thumb:

- `standard`, `remediation`, `upgrade` need a version **with** at least one
  vulnerability; `negative` needs one **without**.
- A candidate already in the test BOM is skipped.
- Details of each scenario: [TESTING.md](TESTING.md#scenarios).

## 4. Wire up the SVM API check

Goal: given a component name, make the tool receive the SVM records for it.

1. Find the SVM endpoint that lists vulnerabilities for a component, and try it
   with curl, e.g.:

   ```bash
   curl -H "Authorization: Bearer $SVM_API_TOKEN" \
     "https://svm.mycompany.com/api/v1/vulnerabilities?component=log4j-core"
   ```

2. Note where the record list is in the response (`items`, `data.items`, …) and
   what the severity / status keys are called.
3. Put it in `config/config.yaml`:

   ```yaml
   svm:
     require: all
     api:
       enabled: true
       base_url: ${SVM_URL}
       token: ${SVM_API_TOKEN}
       path: /api/v1/vulnerabilities
       params: { component: "{component_name}" }   # also {component_version} {vuln_id} {project_name}
       list_key: data.items                        # "" = auto-detect
       fields: { severity: severity, remediation_status: status }   # optional field checks
   ```

   and `SVM_URL` / `SVM_API_TOKEN` in `.env`.
4. Test the mapping **before** running a cycle. Add a component to Black Duck
   manually, run the pipeline (or wait for the sync), then:

   ```bash
   make svm-check NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228      # exit 0 = found
   make svm-check-absent NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228
   ```

   Add `SEVERITY=CRITICAL` and/or `STATUS_EXPECT=IGNORED` to also verify the
   mapped fields. The JSON output shows how many records matched and any
   mismatch (`severity: expected CRITICAL, got 9.8`).

A record matches when the component name, version and vulnerability id all
appear in the same record. If SVM paginates, ask for a large page in `params`
or filter by component so the match is on the first page.

## 5. Wire up the pipeline trigger

The pipeline is whatever makes SVM pick up Black Duck changes. Choose one:

| Your situation | Config |
|---|---|
| GitLab pipeline | `pipeline.type: gitlab` + `project_id`, `trigger_token`, optional `access_token` to wait for completion |
| Another CI with an HTTP trigger | `pipeline.type: webhook` + `webhook.url`, `headers`, `body` |
| A script/CLI | `pipeline.type: command` + `command.argv: ["./sync.sh", "{run_id}"]` |
| Sync runs on its own schedule | `pipeline.type: none`, and set `test.wait_hours` above the schedule interval |

GitLab example:

```yaml
pipeline:
  type: gitlab
  gitlab:
    base_url: https://gitlab.mycompany.com
    project_id: "1234"
    trigger_token: ${GITLAB_TRIGGER_TOKEN}
    access_token: ${GITLAB_ACCESS_TOKEN}   # read_api, needed to poll status
    ref: main
```

Try it on its own:

```bash
make pipeline-trigger
```

## 6. Run your first real cycle

```bash
make test             # offline checks still pass
make doctor           # connectivity and config
make smoke            # tiny deadline; proves add -> verify -> delete in Black Duck
```

`smoke` will most likely end with a `FAILED` run (SVM cannot sync within ~36
seconds). That is expected — what matters is that the Black Duck steps worked
and the component was cleaned up (`make bd-bom` shows an empty test BOM).

Now a real one:

```bash
make start            # adds the batch, verifies it in Black Duck, saves the run
make status           # shows NEXT STEP DUE
make tick             # run whenever due; or schedule it (next section)
make drain            # alternative: block until the run finishes
```

## 7. Schedule it

Runs are resumable, so you just call `make tick-idle` regularly. It advances
due runs and starts a new cycle when capacity allows.

| Where | How |
|---|---|
| cron | `*/20 * * * * cd /opt/bd-svm-automation && make tick-idle >> /var/log/bd-svm.log 2>&1` |
| Always-on host | `make loop` (add `--stop-on-failure` via `python -m bd_svm loop --stop-on-failure`) |
| GitHub Actions | enable `.github/workflows/e2e-sync.yml` — see [section 15](#15-run-in-docker-or-github-actions) |

Only one process should tick at a time.

## 8. Read the results

```bash
make status          # one line per run: status, phase, next step due, components
make report          # reports/report.md with per-item results and sync latency
make report-junit    # reports/junit.xml for a CI test tab
make report-json     # reports/summary.json
make status-json     # everything: events, per-item checks, evidence
```

In `make report`, the **Sync latency** table answers "how long does Black Duck
→ SVM take?". The **Items** table shows PASS/FAIL per component for the ADD
and DELETE tests. A run is `PASSED` only when every item passed both tests.

## 9. Deal with failures and leftovers

| You see | Meaning | Do |
|---|---|---|
| `ADD TEST failed: … not found` | SVM never showed the component before the deadline | Compare the stored evidence (`make status-json`) with `make svm-check`; check the pipeline ran; check the SVM mapping |
| `ADD TEST failed: … severity: expected X, got Y` | Present but wrong value | Fix `svm.api.fields` mapping, or this is a real sync defect |
| `DELETE TEST failed: … found` | SVM kept the record after Black Duck removed it — the bug this test hunts | Investigate SVM sync/removal |
| `gave up after N attempts` | SVM/Black Duck kept erroring | Check connectivity/tokens, then `make cleanup RUN_ID=<id>` if needed |
| `cleanup_failed` notification | A test component is still in the test BOM | `make sweep`, then `make sweep-apply YES=1` |

Useful commands:

```bash
make cleanup RUN_ID=bd-svm-20260101T120000Z-ab12   # abort a run and remove its components
make sweep                                         # list orphans (dry run)
make sweep-apply YES=1                             # delete them
make db-backup                                     # copy the state DB
```

Failed runs always attempt to remove their components from Black Duck
automatically.

## 10. Get notified

1. Create an incoming webhook in Slack (or Teams) and put it in `.env`:

   ```ini
   NOTIFY_WEBHOOK_URL=https://hooks.slack.com/services/...
   ```

2. Optional in `config/config.yaml`:

   ```yaml
   notify:
     format: slack            # slack | teams | generic
     on: [failed, cleanup_failed]   # drop "passed" if it is too chatty
     prefix: "@oncall "
   ```

3. Test it: `make notify-test`.

## 11. Add the SVM UI check

```bash
make install-ui          # installs Selenium; needs Chrome/Chromium on the machine
```

```yaml
svm:
  ui:
    enabled: true
    url: https://svm.mycompany.com
    search_url: "{ui_url}/components?search={component_name}"
    row_selector: "table.vulns tbody tr"     # important: match per row, not the whole page
    wait_selector: "table.vulns"
    login:
      url: https://svm.mycompany.com/login
      username: ${SVM_UI_USER}
      password: ${SVM_UI_PASSWORD}
      username_selector: "#user"
      password_selector: "#pass"
      submit_selector: "button[type=submit]"
```

Find the CSS selectors with your browser's *Inspect*. With `svm.require: all`
both the API and UI checks must agree; use `any` if either is enough. A
screenshot of each UI check is saved under `data/evidence/<run_id>/`.

## 12. Test more, faster

| Want | Change |
|---|---|
| More coverage per run | `test.batch_size: 4` with mixed scenarios |
| Use the idle time between waits | `test.max_active_runs: 3` and `test.start_interval_minutes: 120` |
| Faster feedback / finer latency | lower `test.first_check_seconds` and `test.check_interval_seconds` |
| Less load on SVM | raise `check_interval_seconds` |
| Strict "exactly N hours" behaviour | `test.mode: fixed` |

Overlapping cycles share pipeline triggers automatically
(`pipeline.coalesce: true`), so more cycles do not mean more pipeline runs.

## 13. Do one-off Black Duck operations

Read-only recipes run freely; anything that changes Black Duck needs `YES=1`.

```bash
make bd-bom                                   # what is in the test BOM
make bd-vulns                                 # vulnerable components in the BOM
make bd-add NAME=log4j-core CV=2.14.1 YES=1
make bd-remediate NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228 STATUS=IGNORED COMMENT="e2e" YES=1
make bd-delete NAME=log4j-core CV=2.14.1 YES=1
make bd-policy ; make bd-risk                 # version policy status / risk profile
make bd-api METHOD=GET API_PATH=/api/projects # any endpoint
make bd-add NAME=x CV=1 PROJECT=other VERSION=v2 YES=1   # another project/version
```

Full list: `make help`, or [OPERATIONS.md](OPERATIONS.md#make-recipe-reference).

## 14. Adapt to a different Black Duck version

Every endpoint and media type is configuration. If a call fails with HTTP
404/406 on your server:

1. Open `<BLACKDUCK_URL>/api-doc/public.html` and find the right path or
   `application/vnd.blackducksoftware.*` version.
2. Override only that key in `config/config.yaml`:

   ```yaml
   blackduck:
     paths:
       vulnerable_bom_components: /api/projects/{project_id}/versions/{version_id}/vulnerable-bom-components
     media_types:
       bom: application/vnd.blackducksoftware.bill-of-materials-6+json
   ```

3. Re-check with `make doctor` and the relevant `make bd-*` read recipe.

The list of paths and which are least verified is in
[BLACKDUCK_API.md](BLACKDUCK_API.md).

## 15. Run in Docker or GitHub Actions

**Docker**

```bash
make docker-build                       # WITH_UI=1 to include Chromium + Selenium
make docker-run ARGS="doctor"
make docker-run ARGS="tick --start-if-idle"
```

`./data` (state) and `./config` are mounted; secrets come from `.env`.

**GitHub Actions**

1. Use a **private** repo (the state branch contains component names and Black
   Duck URLs), or set the `STATE_BACKEND` variable to `s3` and `STATE_S3_URI`.
2. Add the secrets and variables listed at the top of
   `.github/workflows/e2e-sync.yml` (at minimum `BLACKDUCK_URL`,
   `BLACKDUCK_API_TOKEN`, `SVM_URL`, `SVM_API_TOKEN`).
3. Put your real SVM/pipeline settings in the repository variable
   `BD_SVM_CONFIG_YAML` (the whole `config.yaml`); otherwise the example config
   is used and its placeholder SVM path will not work.
4. *Actions → E2E Black Duck-SVM sync → Run workflow → `doctor`* to verify,
   then let the 30-minute schedule take over.
5. Results: job summary, `bd-svm-reports` artifact, and failure notifications.

If Black Duck or SVM are not reachable from GitHub-hosted runners, change
`runs-on` to a self-hosted runner.
