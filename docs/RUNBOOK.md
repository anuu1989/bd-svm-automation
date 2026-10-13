# Runbook

Operational reference: what the targets do, how to read a failure, and what to
do about it. Step-by-step tasks are in [HOWTO.md](HOWTO.md).

## Targets

| Target | Does |
|---|---|
| `health` | smoke test `tests/test_api_health.py` (read-only) |
| `phase1` / `phase2` | the two phases, each writes an HTML report to `reports/` |
| `cycle` | health → phase1 → wait `WAIT_HOURS` (default 4, `0` = none) → phase2 |
| `state-show` | print `state.json` |
| `report` | open the HTML reports |
| `selftest` | framework self-tests: state, auth cache, phases vs the mock, failure paths |
| `demo` | both phases against the mock Black Duck (no credentials) |
| `mock-server` | run the mock on `:8099` |
| `lint` / `fix` / `ci` | ruff / ruff --fix / lint + selftest + demo |
| `clean` / `distclean` | remove caches and reports / also the venv and `state.json` |

## Reading a failure

Open the HTML report of the failed run; expand the failed step to see its
request and response. Then:

| Failing step | Meaning | What to do |
|---|---|---|
| P1 01 | authentication failed | wrong/expired `BD_API_KEY`, wrong `BD_HOST` |
| P1 02 / 03 | project / version not found | create them or fix `BD_PROJECT_*`; the token's user needs access |
| P1 04 | component not in the KB | check `BD_COMPONENT_NAME` / `BD_COMPONENT_VERSION` |
| P1 05 "already in the BOM" | a previous run left it behind | remove it from the test BOM, then rerun |
| P1 05 status ≠ 200/201 | add rejected | permissions, wrong media type (`BD_MEDIA_BOM`), wrong path |
| P1 06 count | BOM changed by someone else, or the add was not applied | use a dedicated project |
| P1 06 matchTypes | item not flagged `MANUAL_BOM_COMPONENT` | read the response in the report; server variant |
| P1 07 CVE not reported | Black Duck still computing, or the version has no such CVE | raise `BD_VULN_WAIT_SECONDS`; check `BD_VULN_ID` |
| P1 08–12 | update/remediation rejected or not persisted | read request/response; check status values are valid for your release |
| P2 02 | `state.json` missing or incomplete | phase 1 did not pass, or the artifact expired (1 day) |
| P2 03 count | BOM changed between the phases, or the component is already gone | investigate; nothing was deleted |
| P2 04 ≠ 204 | delete rejected | permissions; 404 = already gone |
| P2 05 count | removal not reflected / BOM changed | investigate; the component may still be present |

Phase-level behaviour: the first failing step aborts the phase (later steps are
*skipped*); a failed phase 1 removes the component it added; phase 2 never
deletes anything it has not verified. Details: [DESIGN.md](DESIGN.md#failure-behaviour).

## Recovery

See [HOWTO.md §12](HOWTO.md#12-recover-after-a-failed-or-missed-phase) for the
table and the manual removal command.

## Operating notes

- One cycle at a time (shared concurrency group `bd-api-cycle`).
- Artifacts: `state-json` (1 day), `phase1-report`, `phase2-report`.
- Cron is best effort; scheduled workflows pause after 60 days of repo
  inactivity ([GITHUB_ACTIONS.md](GITHUB_ACTIONS.md)).
- The reports contain API responses (project/component names), never the token.
- What has and has not been verified against a real server:
  [ASSUMPTIONS.md](ASSUMPTIONS.md).
