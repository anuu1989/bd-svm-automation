# Black Duck → SVM synchronization test

Automated end-to-end test that proves a change made in **Black Duck** is
reflected in the **SVM** UI/API after the sync pipeline runs — for both
*adding* and *removing* a vulnerable component.

```
find vulnerable component → add to Black Duck → verify BD assessment → save transaction
   → wait 8h → trigger pipeline → SVM API + UI check → ADD TEST
   → delete from Black Duck → verify BD deleted
   → wait 8h → trigger pipeline → SVM API + UI check → DELETE TEST → next cycle
```

## Quick start

```bash
make config        # creates config/config.yaml and .env from the examples
$EDITOR .env config/config.yaml   # Black Duck URL/token, SVM endpoint, pipeline
make test          # offline unit + lifecycle tests
make doctor        # validates config and Black Duck connectivity
make start         # begin one cycle (adds component, verifies in Black Duck)
make status        # see when the next step is due
make tick-idle     # advance due runs; schedule this with cron / CI (see docs)
```

`make help` lists every target, including ad-hoc Black Duck recipes
(`bd-add`, `bd-delete`, `bd-remediate`, `bd-search`, `bd-api`, …) and
`svm-check` / `pipeline-trigger` for running single steps by hand. See
[docs/OPERATIONS.md](docs/OPERATIONS.md#make-recipe-reference).

## What is configurable

| Thing | Where |
|---|---|
| Black Duck URL, token, TLS | `blackduck.base_url`, `api_token`, `verify_ssl` (or `BLACKDUCK_URL`, `BLACKDUCK_API_TOKEN`) |
| **Black Duck API paths** | `blackduck.paths.*` – every endpoint is a path template |
| Media types / API versions | `blackduck.media_types.*` |
| Target project/version, candidate components | `blackduck.project_*`, `blackduck.candidates` |
| SVM API endpoint, auth, response shape | `svm.api.*` |
| SVM UI selectors / login | `svm.ui.*` |
| Pipeline trigger (GitLab / webhook / command) | `pipeline.*` |
| Wait time, retries, DB location | `test.*` |

## Documentation

| Doc | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Flow, state machine, modules, failure semantics |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every setting, with examples |
| [docs/BLACKDUCK_API.md](docs/BLACKDUCK_API.md) | Endpoints used, payloads, what to verify on your instance |
| [docs/SVM_AND_PIPELINE.md](docs/SVM_AND_PIPELINE.md) | Wiring the SVM API/UI checks and pipeline trigger |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Scheduling, reports, cleanup, troubleshooting |

## Safety

This tool **writes to and deletes from a Black Duck BOM**. Point it at a
dedicated project version (`blackduck.project_name/project_version`), never a
real product BOM. Deletion is limited to the exact component version the test
added, and refused if Black Duck does not flag the item as a manual component.

## Status / caveats

The Black Duck client (add, update, delete, projects, versions, BOM,
vulnerabilities, remediation, policy, risk, code locations, raw passthrough)
follows the public Hub REST API, but the SVM API/UI
endpoints and the pipeline are specific to your environment, so those defaults
are placeholders you must set. The orchestration logic is covered by offline
tests; the live Black Duck/SVM calls have **not** been exercised against a real
instance — run `make doctor` and a `make smoke` cycle first (see
[docs/OPERATIONS.md](docs/OPERATIONS.md)).
