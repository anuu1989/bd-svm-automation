# Black Duck BOM lifecycle automation

Two-phase, scheduled API test of the Black Duck BOM lifecycle on GitHub
Actions. **Phase 1** (08:00 UTC) adds a vulnerable component, verifies it,
updates its review state and remediates the CVE. **Phase 2** (12:00 UTC, four
hours later) deletes it and proves the BOM count is back to the baseline. The
IDs travel between phases in `state.json` (a 1-day GitHub artifact).

```
Phase 1 · 08:00 UTC                        Phase 2 · 12:00 UTC
 01 auth                                     01 auth (token expired)
 02 find project        ┌──────────────┐     02 load state.json → IDs + counts
 03 find version        │   4 HOURS    │     03 verify BOM count still N+1
 04 find KB component   │ state.json   │     04 DELETE component → 204
 05 baseline N → POST   │ as artifact  │     05 verify count = N (baseline restored)
 06 verify N+1, MANUAL  └──────────────┘
 07 reset → NEEDS_REVIEW
 08 update usage + reviewStatus
 09 verify update persisted
 10 list vulnerabilities
 11 remediate CVE → NOT_AFFECTED
 12 verify remediation + write state.json
```

## Quick start

```bash
make install
cp .env.example .env     # BD_HOST, BD_API_KEY, (BD_PROJECT_NAME ...)
make health              # smoke test
make phase1              # 12 steps -> state.json
make phase2              # 5 steps  -> baseline restored
```

No Black Duck available? `make demo` runs both phases against a built-in mock; `make selftest` also exercises the failure paths.

## Layout

```
tests/phase1/test_setup.py      12 steps          .github/workflows/phase1.yml   cron 08:00 UTC
tests/phase2/test_teardown.py    5 steps          .github/workflows/phase2.yml   cron 12:00 UTC
tests/test_api_health.py        smoke test        config/settings.py             BD_HOST, BD_API_KEY, paths…
utils/  auth · api_client · state · reporter · bd_headers
```

Black Duck URL and **every API path / media type are configurable**
(`BD_HOST`, `BD_PATH_*`, `BD_MEDIA_*`).

## Documentation

| Doc | Contents |
|---|---|
| **[docs/HOWTO.md](docs/HOWTO.md)** | **Start here** — task-by-task guide: demo, setup, run, reports, configuration, GitHub Actions, schedule, recovery, extending |
| [docs/DESIGN.md](docs/DESIGN.md) | steps, flows, `state.json`, failure behaviour |
| [docs/SETTINGS.md](docs/SETTINGS.md) | every setting, API paths, media types |
| [docs/GITHUB_ACTIONS.md](docs/GITHUB_ACTIONS.md) | secrets, schedule, artifact hand-off, caveats |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | targets, reading failures, operating notes |
| [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md) | what is assumed, what is verified, what to check first |

## Safety

The phases add to and delete from a BOM: use a **dedicated** project version.
Phase 2 only deletes the component recorded in `state.json`, and only after the
BOM count audit passes.
