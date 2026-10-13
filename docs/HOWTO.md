# How-to guide

Task-oriented steps for running, configuring and extending the two-phase Black
Duck BOM lifecycle automation. For the design see [DESIGN.md](DESIGN.md); for
every setting see [SETTINGS.md](SETTINGS.md); when something fails see
[RUNBOOK.md](RUNBOOK.md).

**Contents**

1. [Try it without a Black Duck server](#1-try-it-without-a-black-duck-server)
2. [Set up against your Black Duck](#2-set-up-against-your-black-duck)
3. [Check the connection (smoke test)](#3-check-the-connection-smoke-test)
4. [Run phase 1 and phase 2 locally](#4-run-phase-1-and-phase-2-locally)
5. [Read the HTML report](#5-read-the-html-report)
6. [Test a different component or CVE](#6-test-a-different-component-or-cve)
7. [Use different assessment values](#7-use-different-assessment-values)
8. [Adapt to your server (paths, media types, TLS)](#8-adapt-to-your-server-paths-media-types-tls)
9. [Run it on GitHub Actions](#9-run-it-on-github-actions)
10. [Change the schedule or the wait](#10-change-the-schedule-or-the-wait)
11. [Get notified on failure](#11-get-notified-on-failure)
12. [Recover after a failed or missed phase](#12-recover-after-a-failed-or-missed-phase)
13. [Add a step, assertion or API helper](#13-add-a-step-assertion-or-api-helper)
14. [Test the framework itself](#14-test-the-framework-itself)
15. [Command cheat sheet](#15-command-cheat-sheet)

---

## 1. Try it without a Black Duck server

```bash
make demo
```

Starts a built-in mock Black Duck (10 baseline BOM components), runs the smoke
test, phase 1 (12 steps), prints `state.json`, runs phase 2 (5 steps) and shows
the BOM count `10 → 11 → 10`. Nothing leaves your machine.

Want to drive it yourself?

```bash
make mock-server                                   # terminal 1, listens on :8099
export BD_HOST=http://127.0.0.1:8099 BD_API_KEY=anything   # terminal 2
make health && make phase1 && make state-show && make phase2
```

Inject a server error to see the failure handling:

```bash
curl -X POST "http://127.0.0.1:8099/mock/fail-next?status=500&count=1"
```

(GET/PUT/DELETE are retried with backoff, so a single 500 is absorbed; use
`BD_HTTP_RETRIES=0` to see the failure surface.)

## 2. Set up against your Black Duck

1. **Create a dedicated project and version** in Black Duck (default names:
   `svm-e2e-test` / `main`). The phases add to and delete from its BOM — never
   use a real product BOM.
2. **Create an API token** for a user who can read the KB and edit that
   project's BOM.
3. Install and configure:

   ```bash
   make install
   cp .env.example .env
   ```

4. Edit `.env`:

   ```ini
   BD_HOST=https://blackduck.mycompany.com
   BD_API_KEY=<your token>
   BD_PROJECT_NAME=svm-e2e-test
   BD_PROJECT_VERSION=main
   ```

`.env` is git-ignored. Anything already exported in your shell wins over
`.env`.

## 3. Check the connection (smoke test)

```bash
make health
```

Five read-only checks: bearer token, server version endpoint, project exists,
project version exists, KB component resolvable. All must pass before running
the phases. The HTML report is `reports/health-report.html`.

| Failing check | Usually |
|---|---|
| auth | wrong `BD_API_KEY` / `BD_HOST` |
| server version | wrong host, proxy, or path override (`BD_PATH_CURRENT_VERSION`) |
| project / version | not created yet, or the token's user has no access |
| KB component | `BD_COMPONENT_NAME` / `BD_COMPONENT_VERSION` not in the knowledge base |

## 4. Run phase 1 and phase 2 locally

```bash
make phase1        # 12 steps: add, verify, assess, remediate, write state.json
make state-show    # the IDs and counts handed to phase 2
make phase2        # 5 steps: fresh auth, delete, verify the baseline is restored
```

Or the whole cycle in one command, with the real 4-hour wait (or none):

```bash
make cycle                  # health → phase1 → wait 4h → phase2
make cycle WAIT_HOURS=0     # same, without waiting (quick end-to-end check)
make cycle WAIT_HOURS=0.5   # custom wait
```

What a successful run proves:

| Evidence | Where |
|---|---|
| component added: BOM count `N → N+1`, flagged `MANUAL_BOM_COMPONENT` | phase 1 steps 05–06 |
| usage + reviewStatus persisted | steps 08–09 |
| CVE remediated to `NOT_AFFECTED` and persisted | steps 11–12 |
| component still present after the wait | phase 2 step 03 |
| deleted with 204, count back to `N`, component gone | phase 2 steps 04–05 |

If a phase fails, the remaining steps of that phase are *skipped* and, for
phase 1, the component it added is removed again.

## 5. Read the HTML report

```bash
make report         # opens reports/*.html (or just open the file)
```

Each test row can be expanded to show **every API call it made**: method, URL,
HTTP status, timing, request body and a response snippet, plus notes such as
`COMPONENT_ID=… COMP_VER_ID=…` and the count audit
(`baseline 10 → +1 = 11 → −1 = 10 (baseline restored)`). The token is never
included. When a step fails, start by reading its last call.

## 6. Test a different component or CVE

Change three settings (`.env` locally, repository variables in GitHub):

```ini
BD_COMPONENT_NAME=log4j-core
BD_COMPONENT_VERSION=2.14.1
BD_VULN_ID=CVE-2021-44228
```

Requirements: the version exists in the KB, it actually has that CVE, and it is
**not already in the test BOM**. Check first with `make health` (the KB step).

## 7. Use different assessment values

| Want | Set |
|---|---|
| a different final status (e.g. `IGNORED`, `MITIGATED`) | `BD_REMEDIATION_STATUS` |
| a different reset status | `BD_RESET_STATUS` |
| different usage / review state | `BD_USAGE`, `BD_REVIEW_STATUS` |
| a different comment on the assessment | `BD_REMEDIATION_COMMENT` |

Status values must be valid for your Black Duck release; an invalid one shows
up as an HTTP 4xx on step 07 or 11 in the report. Slow vulnerability
computation (step 07 cannot find the CVE) → raise `BD_VULN_WAIT_SECONDS`.

## 8. Adapt to your server (paths, media types, TLS)

**API path differs** (gateway prefix, different release): override only the
key that differs.

```ini
BD_PATH_PROJECTS=/blackduck/api/projects
BD_PATH_BOM_COMPONENTS=/blackduck/api/projects/{project_id}/versions/{version_id}/components
```

Placeholders such as `{project_id}` are filled by the code; keep them. The
full list of keys and defaults is in [SETTINGS.md](SETTINGS.md#api-paths--configurable).
Confirm the right paths in `<BD_HOST>/api-doc/public.html`.

**HTTP 406 / unsupported media type** → bump the revision:

```ini
BD_MEDIA_BOM=application/vnd.blackducksoftware.bill-of-materials-6+json
```

**Self-signed certificate** (lab only):

```ini
BD_VERIFY_SSL=false
```

**Slow or flaky server**: `BD_TIMEOUT` (seconds) and `BD_HTTP_RETRIES`.

## 9. Run it on GitHub Actions

1. Push the repo. In **Settings → Secrets and variables → Actions** add:

   | Kind | Name | Notes |
   |---|---|---|
   | Secret | `BD_HOST` | required |
   | Secret | `BD_API_KEY` | required |
   | Secret | `NOTIFY_WEBHOOK_URL` | optional (Slack-compatible) |
   | Variable | `BD_PROJECT_NAME`, `BD_PROJECT_VERSION`, `BD_COMPONENT_NAME`, `BD_COMPONENT_VERSION`, `BD_VULN_ID` | optional, defaults as in [SETTINGS.md](SETTINGS.md) |

2. **Actions → Phase 1 - Setup → Run workflow.** Wait for it to pass (it
   uploads the `state-json` artifact and `phase1-report`).
3. **Actions → Phase 2 - Teardown → Run workflow.** It downloads the state from
   the latest successful phase 1 run and tears down.
4. Open the uploaded `phase1-report` / `phase2-report` artifacts.
5. Leave the schedules on: phase 1 at 08:00 UTC, phase 2 at 12:00 UTC daily.

If your Black Duck is not reachable from GitHub-hosted runners, set `runs-on`
to a self-hosted runner in both workflow files. Details and caveats:
[GITHUB_ACTIONS.md](GITHUB_ACTIONS.md).

## 10. Change the schedule or the wait

Edit the `cron:` line of each workflow (UTC). The wait between the phases *is*
the gap between the two cron times:

| Want | phase1.yml | phase2.yml |
|---|---|---|
| 4 h (default) | `0 8 * * *` | `0 12 * * *` |
| 2 h | `0 8 * * *` | `0 10 * * *` |
| weekdays only | `0 8 * * 1-5` | `0 12 * * 1-5` |
| twice a day | add a second `cron:` line to both, 12 h apart | keep a 4 h offset |

Keep the artifact lifetime in mind: `retention-days: 1` in `phase1.yml` means the
gap must stay under a day. Locally use `WAIT_HOURS` (see section 4).

## 11. Get notified on failure

1. Create an incoming webhook (Slack, or any Slack-compatible endpoint).
2. Save it as the secret `NOTIFY_WEBHOOK_URL`.

Both workflows then post a message with a link to the run when a phase fails.
Without the secret you still get GitHub's own failure e-mail for the workflow.

## 12. Recover after a failed or missed phase

| Situation | What to do |
|---|---|
| Phase 1 failed | Nothing to clean up — it removes what it added. Fix the cause from the report and re-run phase 1. |
| Phase 1 failed *and* the report says "cleanup FAILED" | Remove the component by hand (below). |
| Phase 2 failed on a count mismatch | The BOM changed in between; nothing was deleted. Check the BOM, then re-run phase 2 or remove by hand. |
| Phase 2 failed on delete | Re-run phase 2 within a day (artifact still valid). |
| Phase 2 missed and the artifact expired | Remove the component by hand (below). |

**Manual removal** using the IDs in `state.json` or the phase 1 report:

```bash
TOKEN=$(curl -s -X POST -H "Authorization: token $BD_API_KEY" \
  -H "Accept: application/vnd.blackducksoftware.user-4+json" \
  "$BD_HOST/api/tokens/authenticate" | python3 -c 'import sys,json; print(json.load(sys.stdin)["bearerToken"])')

curl -i -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$BD_HOST/api/projects/$PROJECT_ID/versions/$VERSION_ID/components/$COMPONENT_ID/versions/$COMP_VER_ID"
# expect: HTTP 204
```

or delete it in the Black Duck UI (BOM → remove the manually added component).

Re-running **phase 1** while a previous component is still in the BOM stops at
step 05 ("already in the BOM") — that is deliberate.

## 13. Add a step, assertion or API helper

**New assertion in a phase**: add a test function to
`tests/phase1/test_setup.py` or `tests/phase2/test_teardown.py`. Keep the
`test_NN_name` numbering (pytest runs them in file order) and use the shared
`ctx` dict for values later steps need:

```python
def test_13_example(client, ctx):
    item = client.find_bom_item(**_ids(ctx))
    assert item["ignored"] is False
```

**New API helper**: add a method to `BDClient` in `utils/api_client.py`. Every
call made through `self.request(...)` is recorded in the HTML report
automatically. Add the path as a template to `DEFAULT_PATHS` in
`config/settings.py` so it is overridable with `BD_PATH_<KEY>`.

**New value to hand to phase 2**: add the key to `REQUIRED_KEYS` in
`utils/state.py` and to the dict written in step 12; `load_state()` validates it
on the other side.

Run `make selftest` and `make lint` afterwards.

## 14. Test the framework itself

```bash
make selftest     # state handling, token cache, both phases vs the mock,
                  # incl. failure paths: abort, cleanup, missing state, count drift
make lint         # ruff
make ci           # lint + selftest + demo (what CI runs)
```

These need no credentials. They validate the framework's logic, not your Black
Duck's API behaviour — see [ASSUMPTIONS.md](ASSUMPTIONS.md) for what still has
to be confirmed on a real server.

## 15. Command cheat sheet

| Goal | Command |
|---|---|
| install | `make install` |
| smoke test | `make health` |
| phase 1 / phase 2 | `make phase1` / `make phase2` |
| both, with / without the wait | `make cycle` / `make cycle WAIT_HOURS=0` |
| show handed-over state | `make state-show` |
| open reports | `make report` |
| offline demo / self-tests | `make demo` / `make selftest` |
| mock server | `make mock-server` |
| lint / fix / CI bundle | `make lint` / `make fix` / `make ci` |
| clean | `make clean` / `make distclean` |
| list everything | `make help` |
