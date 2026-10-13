# GitHub Actions

> Step-by-step setup: [HOWTO.md §9–11](HOWTO.md#9-run-it-on-github-actions).

```
08:00 UTC  phase1.yml ──► state.json (artifact "state-json", 1 day) ──► 12:00 UTC  phase2.yml
           smoke test → test_setup.py (12)                              download → test_teardown.py (5)
           uploads phase1-report.html                                    uploads phase2-report.html
```

## One-time setup

1. Repository **Settings → Secrets and variables → Actions**:

   | Kind | Name | Required | Notes |
   |---|---|---|---|
   | Secret | `BD_HOST` | yes | Black Duck URL |
   | Secret | `BD_API_KEY` | yes | token of a user with BOM write access on the test project |
   | Secret | `NOTIFY_WEBHOOK_URL` | no | Slack-compatible webhook, used when a phase fails |
   | Variable | `BD_PROJECT_NAME`, `BD_PROJECT_VERSION` | no | default `svm-e2e-test` / `main` |
   | Variable | `BD_COMPONENT_NAME`, `BD_COMPONENT_VERSION`, `BD_VULN_ID` | no | default `commons-text` / `1.9` / `CVE-2022-42889` |

2. Create the dedicated Black Duck project/version.
3. **Actions → Phase 1 - Setup → Run workflow**, then (after it passes)
   **Phase 2 - Teardown → Run workflow** to verify the whole cycle by hand.
4. Leave the schedules to run daily.

## How the hand-off works

- `phase1.yml` uploads `state.json` as artifact **`state-json`** with
  `retention-days: 1`, only if phase 1 passed.
- `phase2.yml` finds the latest *successful* `phase1.yml` run with
  `gh run list`, downloads that artifact with `gh run download`, and fails
  clearly if there is none. It needs `actions: read` (already set).
- Both workflows share the concurrency group `bd-api-cycle`, so they never
  overlap.

## Things to know

- **Artifact lifetime is 1 day.** If phase 2 is skipped or fails before
  deleting, rerun it within a day; after that the component remains in the BOM
  and must be removed manually (`BD` UI, or delete with the IDs from the
  phase 1 report).
- **Cron timing is best effort**; runs can start minutes late. Phase 2 does not
  check the elapsed time, it only needs phase 1 to have succeeded.
- GitHub **disables scheduled workflows** after 60 days without repository
  activity.
- **Reachability:** GitHub-hosted runners must be able to reach `BD_HOST`. For
  an internal server change `runs-on` to a self-hosted runner in both files.
- A failing phase fails the job, which sends GitHub's normal failure e-mail;
  `NOTIFY_WEBHOOK_URL` adds a chat message.
- Re-running phase 2 after a successful teardown fails at step 03 (count is
  back to N, not N+1) — that is the audit working as intended.

## Changing the schedule

Edit the `cron:` lines. Keep phase 2 after phase 1 by the wait you want (the
design uses 4 hours: `0 8 * * *` and `0 12 * * *`). `make cycle WAIT_HOURS=…`
mirrors the same wait locally.

## CI

`ci.yml` runs `make ci` on push/PR: lint, the framework self-tests, and both
phases against the mock Black Duck. It needs no secrets.
