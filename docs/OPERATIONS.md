# Operations runbook

## First run checklist

1. `make config` and fill in `.env` + `config/config.yaml`.
2. Create a **dedicated** Black Duck project/version for the test.
3. `make test` – offline tests must pass. `make demo` – full flow against the mock.
4. `make doctor` – config valid, Black Duck auth and project/version found.
5. `make bd-search NAME=log4j-core VERSIONS=1` – confirm your candidates exist in the KB.
6. `make smoke` – a real cycle with a tiny deadline. Proves Black Duck
   add/verify/delete works; SVM checks will fail unless your sync is fast —
   that is fine, the components are cleaned up.
7. Schedule it (below), enable notifications (`make notify-test`).

## Running

| Mode | Command | Use when |
|---|---|---|
| Scheduler-driven (recommended) | `make tick-idle` every 15–30 min | cron, GitHub/GitLab schedule, Jenkins. Stateless processes; survives reboots. |
| Daemon | `make loop` | A host/container that stays up. `--stop-on-failure` halts after a failed run. |
| One-shot | `make start` then `make drain` | Ad-hoc run that blocks until done (CI job, demo). |
| Manual | `make start`, later `make tick` | Debugging. |

`tick --start-if-idle` starts a new cycle whenever capacity allows:
`test.max_active_runs` not reached and `test.start_interval_minutes` elapsed.
With the defaults (1 run, no spacing) that is "start the next cycle as soon as
the previous one finished".

cron example:

```cron
*/20 * * * * cd /opt/bd-svm-automation && make tick-idle >> /var/log/bd-svm.log 2>&1
```

Exit codes: `0` ok, `1` a run failed (or a Black Duck error), `2` configuration
error / refused action, `3` `drain` hit `--max-hours`.

## Throughput and efficiency knobs

| Goal | Setting |
|---|---|
| Know the real sync time, finish early | `test.mode: poll` (default), keep `wait_hours` as the SLA deadline |
| More coverage per pipeline run | `test.batch_size: 4` with mixed scenarios |
| Use the dead time between waits | `test.max_active_runs: 3`, `test.start_interval_minutes: 120` |
| Less load on SVM | larger `check_interval_seconds`; `require: any` avoids running the slow UI check when the API check suffices |
| Pipeline not re-run needlessly | `pipeline.coalesce: true` (default) |
| Flaky network | `blackduck.http_retries`, `svm.api.retries` (backoff on 429/5xx) |

## State persistence

`data/state.db` must survive between scheduled runs. Locally it is just a
file. On ephemeral runners (GitHub Actions) use `scripts/state.sh`:

| `STATE_BACKEND` | Where | Notes |
|---|---|---|
| `git-branch` (default) | force-pushed single-commit branch `bd-svm-state` | needs push rights; the DB contains component names and Black Duck URLs → **private repo** |
| `s3` | `STATE_S3_URI` (`s3://bucket/key`) | needs `aws` CLI + credentials |
| `none` | – | local file only |

`make state-pull` / `make state-push`; the workflow does both around each run.
`make db-backup` copies the DB locally.

## GitHub Actions

`.github/workflows/e2e-sync.yml` runs `make tick-idle` every 30 minutes
(secrets/variables listed at the top of the file), restores/saves state via
`scripts/state.sh`, writes the report to the job summary, and uploads
`reports/` (Markdown, JUnit, JSON) and evidence. *Run workflow* lets you run any
action by hand (`sweep`, `doctor`, `cleanup` …). `ci.yml` runs `make ci` and
`make demo` on push/PR.

Notes: schedules are best-effort and GitHub disables them after 60 days
without repo activity; a failed run fails the job; a self-hosted runner is
needed if Black Duck/SVM are not reachable from GitHub.

## Docker

```bash
make docker-build                   # WITH_UI=1 adds Chromium + Selenium
make docker-run ARGS="doctor"
make docker-run ARGS="tick --start-if-idle"
```

Mounts `./data` (state) and `./config`; reads `.env`.

## Notifications

Set `NOTIFY_WEBHOOK_URL` (Slack-compatible incoming webhook; `notify.format:
teams|generic` for others) and `make notify-test`. Events: `failed`, `passed`,
`cleanup_failed` (component left in Black Duck — act on it). Delivery failures
are logged, never fatal.

## Observing and reports

```bash
make status                  # run, status, phase, next step due, items
make status-json             # full details: events, per-item results, evidence
make report                  # reports/report.md   (with latency table)
make report-junit            # reports/junit.xml   (CI test tab)
make report-json             # reports/summary.json
```

## Cleanup and orphans

- `make cleanup RUN_ID=<id>` aborts a run and removes its components.
- `make sweep` lists **orphans**: manually-added items in the test BOM whose
  name is a configured candidate and that no active run owns. `make
  sweep-apply YES=1` deletes them. Schedule `sweep` occasionally; a `FAILED`
  run with `cleanup_error` is the usual source.

## Make recipe reference

Parameters: `NAME`, `CV` (component version), `HREF`, `VULN`, `STATUS`,
`COMMENT`, `PROJECT`, `VERSION`, `METHOD`, `API_PATH`, `DATA`, `RUN_ID`, `YES`,
`ARGS`, `WITH_UI`.

| Group | Recipes |
|---|---|
| Setup | `venv` `install` `install-ui` `install-dev` `config` |
| Quality | `lint` `fix` `test` `check` `ci` |
| Test flow | `doctor` `start` `tick` `tick-idle` `loop` `drain` `smoke` `cleanup` |
| Hygiene | `sweep` `sweep-apply` `db-backup` `db-reset` |
| Observe | `status` `status-json` `report` `report-junit` `report-json` `notify-test` |
| Black Duck read | `bd-whoami` `bd-projects` `bd-versions` `bd-bom` `bd-vulns` `bd-search` `bd-component-vulns` `bd-vuln` `bd-upgrade` `bd-policy` `bd-risk` `bd-bom-status` `bd-codelocations` |
| Black Duck write (need `YES=1`) | `bd-add` `bd-delete` `bd-ignore` `bd-unignore` `bd-remediate` `bd-create-project` `bd-create-version` `bd-delete-version` `bd-delete-project` |
| Any endpoint | `bd-api` |
| SVM / pipeline | `svm-check` `svm-check-absent` `pipeline-trigger` |
| Demo / mock | `mock-server` `demo` |
| State / container | `state-pull` `state-push` `docker-build` `docker-run` |
| Clean | `clean` `distclean` |

Examples:

```bash
make bd-search NAME=log4j-core VERSIONS=1
make bd-add NAME=log4j-core CV=2.14.1 YES=1
make bd-remediate NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228 STATUS=IGNORED COMMENT="e2e" YES=1
make svm-check NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228    # exit 1 if not in SVM
make bd-delete NAME=log4j-core CV=2.14.1 YES=1
make svm-check-absent NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228
make bd-api METHOD=GET API_PATH=/api/projects
make bd-add NAME=x CV=1 PROJECT=other-proj VERSION=v2 YES=1
```

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `authentication failed: HTTP 401` | Wrong/expired token or `base_url`; self-signed certs show as an SSL error (`verify_ssl`). |
| `project '…' not found` | Create it, or fix `blackduck.project_name`; token user needs access. |
| `no usable candidate component found` | Candidates unknown to your KB, already in the BOM, or (for `negative`) have vulnerabilities. Extend `blackduck.candidates`; check with `make bd-search`. |
| `Black Duck assessment missing CVE-…` | BD still computing — raise `test.assessment_timeout_seconds`; or field names differ (see [BLACKDUCK_API.md](BLACKDUCK_API.md)). |
| `ADD TEST failed: … not found` at the deadline | Sync slower than `wait_hours`, pipeline didn't pick up the BOM, or SVM matching/`list_key`/pagination is wrong. Compare `make status-json` evidence with `make svm-check`. |
| `ADD TEST failed: … severity: expected X, got Y` | `svm.api.fields` mapping wrong, or SVM normalises values differently (e.g. `Critical` vs `CRITICAL` is fine; `9.8` vs `CRITICAL` is not). |
| `DELETE TEST failed … found` | SVM did not remove the record (what the test is designed to catch) — or UI matching too loose (`row_selector`). |
| `check error (ui: selenium not installed)` | `make install-ui`. |
| `refusing to delete non-manual BOM item` | Safety guard; see [BLACKDUCK_API.md](BLACKDUCK_API.md). |
| Runs pile up | `max_active_runs` too high for the sync time, or the scheduler runs more often than `tick` can finish. |
| Run stuck `ACTIVE` | `make status` shows `NEXT STEP DUE`; make sure the scheduler runs and state is restored (`make state-pull`). |
| `cleanup_failed` notification | A component is still in the test BOM: `make sweep`, then `make sweep-apply YES=1`. |

## Security

- Tokens live in `.env`/CI secrets; `.env` and `config/config.yaml` are
  git-ignored.
- Least privilege: BD write access only on the test project; SVM read-only.
- `state.db` has no secrets but does contain component names and Black Duck
  hrefs; keep the state branch/bucket private.
- Destructive recipes require `YES=1`; deletion is limited to the exact
  component versions a run added (or `sweep` candidates in the test BOM).
