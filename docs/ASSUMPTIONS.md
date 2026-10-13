# Assumptions and open points

> Related: [DESIGN.md](DESIGN.md) · [HOWTO.md](HOWTO.md) · [RUNBOOK.md](RUNBOOK.md)

What this suite takes for granted, where each assumption came from, and what to
change if it turns out to be wrong. **Review the "Verify" items before the
first scheduled run** — none of the Black Duck calls have been exercised
against a real server yet (only against the bundled mock).

Legend — *Basis*: **Design** = read from the design diagrams; **Inferred** =
my interpretation of an unclear or blurry detail; **API** = Black Duck REST
behaviour assumed from the public Hub API; **Ops** = environment expectation.

## 1. Interpretation of the design

| ID | Assumption | Basis | If wrong |
|---|---|---|---|
| D1 | Repo root plays the role of `api-automation/` shown in the structure panel. | Design | Rename the folder; no code depends on it. |
| D2 | **test_07 "Reset remediation → NEEDS_REVIEW"** means: set the remediation status of the known CVE (`BD_VULN_ID`) to `NEEDS_REVIEW` via the remediation endpoint. The CVE is known up front because the flowchart names `CVE-2022-42889`. | Inferred | Change the call in `test_07` (e.g. to a component-level reset). |
| D3 | **test_08 "Update usage + reviewStatus"** means a `PUT` of the BOM item with `usages=[DYNAMICALLY_LINKED]` and `reviewStatus=REVIEWED`. The diagram does not show the values. | Inferred | Set `BD_USAGE` / `BD_REVIEW_STATUS`. |
| D4 | **test_10 "List all vulnerabilities"** lists the version's vulnerable BOM components, filtered to the added component, and asserts the CVE is present with status `NEEDS_REVIEW`. | Inferred | Adjust `test_10` / `vulnerability_status()`. |
| D5 | The add must return **200 or 201**; the delete must return exactly **204** (diagram: "Status 200/201?", "Status 204?"). | Design | Relax the assertion in `test_05` / `test_04`. |
| D6 | "matchType = MANUAL_BOM_COMPONENT" is checked as membership in the item's `matchTypes` list. | Inferred | Adjust `test_06`. |
| D7 | `state.json` has exactly the 8 keys shown; `run_id` is `GITHUB_RUN_ID` in CI, `local-<epoch>` locally. | Design | Edit `REQUIRED_KEYS` in `utils/state.py`. |
| D8 | "Expires in 1 day" = artifact `retention-days: 1`. | Design | Change it in `phase1.yml`. |
| D9 | The 4-hour wait is produced **only by the two cron times** (08:00 / 12:00 UTC). Phase 2 does not check elapsed time. | Design | Add an age check against a timestamp in `state.json`. |
| D10 | "Notify team" = failing the job (GitHub e-mail) plus an optional webhook message. | Inferred | Replace the notify step. |
| D11 | "Repeat for next cycle" = the next day's cron; there is no loop. | Design | — |
| D12 | The baseline **N** is the `totalCount` of *all* BOM components of the version before the add. | Design | — |
| D13 | **SVM verification is not part of this design** and was removed with the previous engine (tag `svm-engine-v0.2`). The suite verifies Black Duck only. | Design | Restore from the tag or add a phase-2 step. |
| D14 | Setting names (`BD_HOST`, `BD_API_KEY`, `BD_PROJECT_NAME`, …) are my choice; the diagram truncates `BD_HOST, BD_API_KEY_…`. | Inferred | Rename in `config/settings.py` and the workflows. |
| D15 | "HTML report extras" = `pytest-html` extras. | Inferred | — |

## 2. Black Duck API behaviour (**Verify** against your server)

Check against `<BD_HOST>/api-doc/public.html`. Every path and media type is
overridable (`BD_PATH_*`, `BD_MEDIA_*`, see [SETTINGS.md](SETTINGS.md)).

| ID | Assumption | Basis | If wrong |
|---|---|---|---|
| A1 | `POST /api/tokens/authenticate` with `Authorization: token <key>` returns `bearerToken` and `expiresInMilliseconds`. | API | `utils/auth.py` |
| A2 | List endpoints are paged with `offset`/`limit` and return `items` + `totalCount`. | API | `BDClient.paginate` |
| A3 | Filtering works with `?q=name:<x>` (projects, KB components) and `?q=versionName:<x>`; the response may contain partial matches, so the code requires an **exact** name/version match. | API | `find_project`, `find_version`, `find_kb_component` |
| A4 | The KB is searchable via `GET /api/components?q=name:…` and its versions via `…/components/{id}/versions`; IDs are the **last path segment** of each `_meta.href`. | API | `find_kb_component` |
| A5 | `GET …/versions/{v}/components?limit=1` reports the full BOM size in `totalCount`. | API | `bom_count` |
| A6 | Adding is `POST …/components` with body `{"component": "<component version URL>"}` and content type `…bill-of-materials-6+json`. Some releases need extra fields (e.g. origin). | API | `test_05` body |
| A7 | A BOM item has `componentVersion` (a URL ending in `/components/{cid}/versions/{cvid}`), `matchTypes`, `usages`, `reviewStatus`. | API | `find_bom_item`, tests 06/09 |
| A8 | A BOM item can be updated by `PUT` to `…/components/{cid}/versions/{cvid}` with the item JSON (minus `_meta`) and changed fields; success is 200/202/204. | API | `test_08` |
| A9 | Remediation is set with `PUT …/components/{cid}/versions/{cvid}/vulnerabilities/{vuln}/remediation` and body `{"remediationStatus", "comment"}`. | API | `BD_PATH_VULNERABILITY_REMEDIATION`, `set_remediation` |
| A10 | The status values `NEEDS_REVIEW` and **`NOT_AFFECTED`** are accepted by your release. (`NOT_AFFECTED` is newer than the classic set.) | API | `BD_RESET_STATUS`, `BD_REMEDIATION_STATUS` |
| A11 | `vulnerable-bom-components` items carry `componentVersion` and `vulnerabilityWithRemediation.{vulnerabilityName,remediationStatus}`. | API | `vulnerability_status` |
| A12 | Black Duck computes vulnerabilities **asynchronously** after an add; the suite waits up to `BD_VULN_WAIT_SECONDS` (180 s) in step 07. | API | raise the setting |
| A13 | `DELETE …/components/{cid}/versions/{cvid}` removes a manually added component and returns 204. | API | `test_04` |
| A14 | Media-type revisions (`user-4`, `project-detail-4`, `bill-of-materials-6`, `vulnerability-4`) are supported; HTTP 406 means bump them. | API | `BD_MEDIA_*` |

## 3. Environment and operations

| ID | Assumption | Basis | Consequence if wrong |
|---|---|---|---|
| O1 | The test project/version is **dedicated**; nobody changes its BOM during the 4-hour window. | Ops | The count audit (phase 2 step 03/05) fails on drift; nothing is deleted on drift in step 03. |
| O2 | The component is **not already in the BOM** at phase 1. | Ops | Step 05 fails with an explanatory message (prevents deleting something we did not add). |
| O3 | The API token's user may read the KB and edit the test project's BOM. | Ops | 401/403 in steps 02–11. |
| O4 | GitHub-hosted runners can reach `BD_HOST`. | Ops | Use a self-hosted runner (`runs-on`). |
| O5 | One cycle at a time: both workflows share the concurrency group `bd-api-cycle`. | Ops | — |
| O6 | Phase 2 uses the **latest successful** `phase1.yml` run's artifact. A manual phase 1 re-run before phase 2 supersedes the earlier state; that earlier component then stays in the BOM until removed manually (a second phase 1 would stop at step 05 because the component is already there). | Ops | Remove it by hand; avoid manual re-runs between the phases. |
| O7 | The `state-json` artifact exists for only one day. If phase 2 does not run in time, the component stays in the BOM. | Ops | Remove it manually using the IDs from the phase 1 report. |
| O8 | `gh` CLI is present on `ubuntu-latest`, and `GITHUB_TOKEN` with `actions: read` may download another workflow's artifact in the same repo. | Ops | Phase 2 download step fails clearly. |
| O9 | GitHub cron is best effort (can be minutes late) and scheduled workflows are paused after 60 days without repository activity. | Ops | Re-enable / dispatch manually. |
| O10 | `state.json` and the HTML reports are uploaded as artifacts and readable by anyone with repo read access. `state.json` holds IDs only; reports hold API responses (project and component names, no token — the auth response is redacted). | Ops | Use a private repository for internal Black Duck data. |
| O11 | Python 3.10+, `requests`, `pytest` 8+, `pytest-html` 4.x. | Ops | `requirements.txt` |
| O12 | All times are UTC. | Design | — |

## 4. Framework decisions

| ID | Decision | Rationale |
|---|---|---|
| F1 | Steps in a phase are **sequential**: the first failure skips the rest. | Later steps are meaningless (or harmful) after an earlier one failed — matches "Stop – notify team". |
| F2 | If phase 1 fails **after** the add, its teardown deletes the component again; no `state.json` is written. | The diagram stops at failure, but leaving test data in the BOM for ever (with no state for phase 2) would be worse. If this cleanup itself fails it is logged in the report and must be handled manually. |
| F3 | Phase 2 does **not** delete anything on its own failure paths (count drift, missing state). | Deleting without a verified baseline could remove something we did not add. |
| F4 | GET/PUT/DELETE are retried with backoff on 429/5xx; **POST is never retried**. A 401 triggers one re-authentication. | A retried POST could add the component twice and break the count audit. |
| F5 | One component and one CVE per cycle. | As designed; parametrising means storing a list in `state.json`. |
| F6 | The bundled mock Black Duck models the API **as understood here**. | Passing against it proves test logic, failure handling and reporting — not compatibility with your server. |

## 5. Verification status

| Area | Verified | How |
|---|---|---|
| Phase 1 (12) and phase 2 (5) logic, count audit 10 → 11 → 10, `state.json` content | Yes | Against the mock (`make demo`) |
| Abort-on-failure, cleanup after a failed phase 1, missing state, count drift | Yes | `make selftest` |
| Token cache / forced refresh, state validation | Yes | `make selftest` |
| HTML report contains per-call extras and notes | Yes | Inspected generated report |
| Real Black Duck endpoints, payloads and status values (section 2) | **No** | Needs a first run: `make health`, then `make phase1` / `make phase2` |
| GitHub workflows (cron, artifact hand-off, notification) | **No** | Parse-checked only; needs a first dispatch of phase 1 then phase 2 |

## 6. Suggested first-run order

1. `make health` — confirms A1–A5 and the project/version/KB objects.
2. `make phase1` — confirms A6–A12; inspect `reports/phase1-report.html` if a step fails (request and response are attached to it).
3. `make state-show`, then `make phase2` — confirms A13 and the count audit.
4. Dispatch **Phase 1 - Setup** then **Phase 2 - Teardown** in GitHub Actions — confirms O4, O8 and the artifact hand-off.
5. Leave the schedules on.
