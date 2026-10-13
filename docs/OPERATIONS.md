# Operations runbook

## First run checklist

1. `make config` and fill in `.env` + `config/config.yaml`.
2. Create a **dedicated** Black Duck project/version for the test.
3. `make test` – offline tests must pass.
4. `make doctor` – config valid, Black Duck auth and project/version found.
5. `make smoke` – full cycle with a ~36 s wait. Needs the SVM check and
   pipeline configured; with a real 8h-sync pipeline the SVM checks will
   (correctly) fail in a smoke test, and the component is cleaned up.
   Use it mainly to prove Black Duck add/verify/delete works.
6. Schedule it (below).

## Running

| Mode | Command | Use when |
|---|---|---|
| Scheduler-driven (recommended) | `make tick-idle` every 15–30 min | cron, GitLab schedule, Jenkins. Stateless processes; survives reboots. |
| Daemon | `make loop` | A host/container that stays up. `--stop-on-failure` halts after a failed run. |
| Manual | `make start`, later `make tick` | Debugging. |

cron example:

```cron
*/20 * * * * cd /opt/bd-svm-automation && make tick-idle >> /var/log/bd-svm.log 2>&1
```

GitLab CI schedule job: `script: [make tick-idle]`, persist `data/` with a
cache or artifact (or point `test.state_db` to a mounted volume). Only one
process should tick at a time.

`tick` exit codes: `0` ok, `1` a run failed, `2` configuration error.

## Make recipe reference

Parameters are passed as make variables: `NAME`, `CV` (component version),
`HREF` (component version URL, alternative to NAME+CV), `VULN`, `STATUS`,
`COMMENT`, `PROJECT`, `VERSION`, `METHOD`, `API_PATH`, `DATA`, `RUN_ID`,
`YES`.

| Group | Recipes |
|---|---|
| Setup | `venv` `install` `install-ui` `config` |
| Quality | `lint` `test` `check` `ci` |
| Test flow | `doctor` `start` `tick` `tick-idle` `loop` `smoke` `cleanup` |
| Observe | `status` `status-json` `report` |
| State | `db-backup` `db-reset` |
| Black Duck read | `bd-whoami` `bd-projects` `bd-versions` `bd-bom` `bd-vulns` `bd-search` `bd-component-vulns` `bd-vuln` `bd-upgrade` `bd-policy` `bd-risk` `bd-bom-status` `bd-codelocations` |
| Black Duck write (need `YES=1`) | `bd-add` `bd-delete` `bd-ignore` `bd-unignore` `bd-remediate` `bd-create-project` `bd-create-version` `bd-delete-version` `bd-delete-project` |
| Any endpoint | `bd-api` |
| SVM / pipeline | `svm-check` `svm-check-absent` `pipeline-trigger` |
| Clean | `clean` `distclean` |

Examples:

```bash
make bd-search NAME=log4j-core VERSIONS=1
make bd-component-vulns NAME=log4j-core CV=2.14.1
make bd-add NAME=log4j-core CV=2.14.1 YES=1               # manual add
make bd-remediate NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228 STATUS=IGNORED COMMENT="e2e" YES=1
make svm-check NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228   # exit 1 if not in SVM
make bd-delete NAME=log4j-core CV=2.14.1 YES=1
make svm-check-absent NAME=log4j-core CV=2.14.1 VULN=CVE-2021-44228
make bd-api METHOD=GET API_PATH=/api/projects
make bd-add NAME=x CV=1 PROJECT=other-proj VERSION=v2 YES=1    # different BOM
```

## Observing

```bash
make status                       # table: run, status, phase, next step due
.venv/bin/python -m bd_svm status --json   # full details incl. events
make report                       # reports/report.md
```

Each run's `events` list records every step with timestamps; failures include
the `failure` reason and, if cleanup failed, `cleanup_error`.

## Cleanup

`make cleanup RUN_ID=<id>` aborts a run and deletes its component from Black
Duck. Runs always clean up on failure, but if Black Duck was unreachable at
that moment the component can remain: look for `cleanup_error` in the report
and remove the item from the test BOM manually or with this command.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `authentication failed: HTTP 401` | Wrong/expired token; wrong `base_url`; check `verify_ssl` for self-signed certs shows as an SSL error instead. |
| `project '…' not found` | Create it, or fix `blackduck.project_name`; token user needs access. |
| `no vulnerable, not-yet-in-BOM candidate found` | Candidates unknown to your BD KB or already in the BOM. Add others in `blackduck.candidates`. |
| `Black Duck assessment missing CVE-…` | BD still computing — raise `test.assessment_timeout_seconds`; or vulnerable-bom-components field names differ (see [BLACKDUCK_API.md](BLACKDUCK_API.md)). |
| `ADD TEST failed: expected present; api=not found` | Sync not finished in 8h, pipeline didn't pick the BOM, or the SVM matching/`list_key`/pagination is wrong. Inspect `python -m bd_svm status --json`, query the SVM API manually with the same params. |
| `check error (ui: selenium not installed)` | `make install-ui`. |
| `DELETE TEST failed … found` | SVM did not remove the record after sync (the thing this test is designed to catch) — or UI matching is too loose (set `row_selector`). |
| `refusing to delete non-manual BOM item` | Safety guard; see [BLACKDUCK_API.md](BLACKDUCK_API.md) item 3. |
| Run stuck `ACTIVE` | `make status` shows `NEXT STEP DUE`; make sure the scheduler is running. |

## Security

- Tokens live in `.env`/CI secrets; `.env` and `config/config.yaml` are
  git-ignored. Don't commit them.
- Use least-privilege tokens: BD write access only on the test project; SVM
  read-only.
- `state.db` contains no secrets (component names, hrefs, results).
