# Test scenarios, mock server and evidence

## Scenarios

Set per candidate in `blackduck.candidates`. A cycle uses the first
`test.batch_size` usable candidates (skipping any already in the BOM, unknown
to the Black Duck KB, or lacking the vulnerability the scenario needs).

| scenario | Candidate needs | ADD test asserts | After ADD passes | DELETE test asserts |
|---|---|---|---|---|
| `standard` | ≥1 vulnerability | record present; severity matches (if `svm.api.fields.severity` mapped) | delete from BD | record absent |
| `remediation` | ≥1 vulnerability; `status:` | as standard **and** `remediation_status` shows `status` in SVM | delete from BD | record absent |
| `upgrade` | ≥1 vulnerability; `upgrade_to:` version | as standard | delete old version **and add `upgrade_to`** in BD | old version's record absent; the upgraded version is removed at the end |
| `negative` | **no** vulnerabilities | **no** record for the component | delete from BD | record absent |

Notes:

- `negative` assumes SVM does not list components without vulnerabilities. If
  yours lists clean components, exclude that scenario or adapt `svm.api` to
  return only vulnerability records.
- Field checks compare case-insensitively and are skipped for any field that
  is not mapped in `svm.api.fields` (the UI check is presence-only).
- All items in a run must pass for the run to pass; per-item results and
  latencies are in the report.

## Sync latency

In `poll` mode each item's latency is `time first seen as expected − time of
the Black Duck change`, with a resolution of `check_interval_seconds`. The
report shows min / avg / p95 / max for add and delete (`make report`,
`make report-json`). Use `first_check_seconds` and `check_interval_seconds` to
trade resolution against load on SVM.

## Evidence

Every check stores its evidence in the run (`make status-json`):

- API: request URL, HTTP status, total records, and up to
  `evidence.max_records` matching records.
- UI: matching row text and a screenshot saved to
  `evidence.dir/<run_id>/<phase>-<component>-ui.png`.

In CI the evidence directory is uploaded as an artifact.

## Mock server and demo

`bd_svm/mock_server.py` is an in-memory model of the Black Duck endpoints this
tool calls plus an SVM API that reflects the BOM **as of the last pipeline
trigger**.

```bash
make demo          # starts the mock, runs all 4 scenarios end to end, prints the report
make mock-server   # run it yourself on :8099, then use config/config.mock.yaml
```

Options: `--sync-delay N` makes SVM lag N seconds behind a trigger (exercises
polling); `POST /mock/fail-next?count=2` makes the next 2 SVM calls return 503
(exercises retry); `GET /mock/state` shows the BOM and SVM snapshot.

> The mock encodes this project's *understanding* of the Black Duck API.
> Passing against it proves orchestration, retries, polling and cleanup — not
> compatibility with your Black Duck release. Use `make doctor` and
> `make smoke` against the real system for that.

## Automated tests

| File | Covers |
|---|---|
| `tests/test_lifecycle.py` | State machine with fakes: fixed + poll modes, deadline, retries, scenarios, batching, overlap, pipeline coalescing, sweep, reports, notifications, Black Duck client payloads/paths |
| `tests/test_mock_e2e.py` | The real client/orchestrator over HTTP against the mock: all scenarios, sync lag, never-syncs → fail + cleanup, injected 503 retried |

`make test` runs everything offline; `make ci` adds lint (ruff).
