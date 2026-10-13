# Configuration

Resolution order (later wins): built-in defaults (`bd_svm/config.py`) →
`config/config.yaml` (or `-c FILE`, or `$BD_SVM_CONFIG`) → `--wait-hours` CLI
override. String values may contain `${VAR}` or `${VAR:-default}`, expanded
from the environment; `.env` in the working directory is loaded first (it never
overrides variables that are already exported).

Put secrets in `.env` / CI variables, structure in `config.yaml`.

## `blackduck`

| Key | Default | Notes |
|---|---|---|
| `base_url` | `${BLACKDUCK_URL}` | e.g. `https://blackduck.corp.com`. No trailing path. |
| `api_token` | `${BLACKDUCK_API_TOKEN}` | User API token (exchanged for a bearer token via `paths.authenticate`; re-auth on 401). |
| `verify_ssl` | `true` | `false` disables verification; use only in lab environments. |
| `timeout_seconds` / `page_size` | 60 / 100 | |
| `http_retries` | 3 | Retries with backoff on connection errors and 429/5xx for GET/PUT/DELETE (never POST). |
| `project_name`, `project_version` | `svm-e2e-test` / `main` | **Dedicated** BOM that gets mutated. Must already exist. |
| `paths.*` | see below | Path templates, joined to `base_url`. Absolute `https://…` values are used as-is. |
| `search_query` | `name:{name}` | `q=` value for component search. |
| `media_types.*` | see below | Accept / Content-Type values per API family. |
| `candidates` | log4j-core, jackson-databind, commons-text | Tried in order; up to `test.batch_size` usable ones are used per cycle. Per-candidate keys: `scenario` (`standard`\|`remediation`\|`upgrade`\|`negative`), `status` (remediation), `upgrade_to` (version). See [TESTING.md](TESTING.md). |
| `vulnerability_severities` | `[]` | e.g. `[CRITICAL, HIGH]` to restrict which vulnerability is asserted. |
| `assessment.enabled/status/comment` | `false` / `IGNORED` / – | Set a remediation status on the test vulnerability after adding. |
| `require_manual_match_type` | `true` | Refuse to delete BOM items not flagged `MANUAL_BOM_COMPONENT`. |

### Path templates

| Key | Default | Placeholders |
|---|---|---|
| `authenticate` | `/api/tokens/authenticate` | |
| `projects` | `/api/projects` | |
| `project_versions` | `/api/projects/{project_id}/versions` | `project_id` |
| `bom_components` | `/api/projects/{project_id}/versions/{version_id}/components` | `project_id`, `version_id` |
| `vulnerable_bom_components` | `…/versions/{version_id}/vulnerable-bom-components` | `project_id`, `version_id` |
| `components_search` | `/api/components` | |
| `component_versions` | `{component_href}/versions` | `component_href` (full URL from API) |
| `component_version_vulnerabilities` | `{component_version_href}/vulnerabilities` | `component_version_href` |
| `current_user`, `current_version` | `/api/current-user`, `/api/current-version` | |
| `project` | `/api/projects/{project_id}` | `project_id` |
| `project_version` | `/api/projects/{project_id}/versions/{version_id}` | `project_id`, `version_id` |
| `policy_status`, `risk_profile`, `bom_status` | `…/versions/{version_id}/policy-status` etc. | `project_id`, `version_id` |
| `vulnerability` | `/api/vulnerabilities/{vuln_id}` | `vuln_id` |
| `vulnerability_remediation` | `…/components/{component_id}/versions/{component_version_id}/vulnerabilities/{vuln_id}/remediation` | all ids |
| `upgrade_guidance` | `{component_version_href}/upgrade-guidance` | `component_version_href` |
| `code_locations` | `/api/codelocations` | |

### Media types

`authenticate` (`…user-4+json`), `default` (`application/json`), `bom`
(`…bill-of-materials-6+json`, used as Content-Type when adding a component),
`vulnerability` (`…vulnerability-4+json`). Bump these if your Black Duck
version requires a different `-N+json` revision.

## `svm`

| Key | Notes |
|---|---|
| `require` | `all` (default) or `any` enabled check must agree. |
| `api.enabled`, `api.base_url`, `api.token`, `api.auth_header`, `api.auth_scheme` | Sends `Authorization: Bearer <token>` by default. `auth_scheme: ""` sends the raw token; `auth_header: X-Api-Key` for key headers. |
| `api.method`, `api.path`, `api.params` | `path` and param values may use `{component_name}`, `{component_version}`, `{vuln_id}`, `{project_name}`. |
| `api.list_key` | Dotted path to the array in the response (`data.items`). Empty = auto-detect first list of objects. |
| `api.match_version` | Also require the component version in the record (default true). |
| `api.fields` | Field-level checks: `{severity: <dotted key>, remediation_status: <dotted key>}`. Expected values come from Black Duck / the scenario; unmapped fields are not checked. `{}` = presence only. |
| `api.retries` | HTTP retries on 429/5xx (default 3). |
| `ui.enabled`, `ui.url`, `ui.search_url` | `search_url` may use `{ui_url}` plus the placeholders above. |
| `ui.login.*` | If `login.url` is set, logs in with CSS selectors first. |
| `ui.row_selector`, `ui.wait_selector`, `ui.wait_seconds` | Rows to match; element to wait for. |

At least one of `api` / `ui` must be enabled (`make doctor` checks).

## `pipeline`

`type`: `gitlab` | `webhook` | `command` | `none`. See
[SVM_AND_PIPELINE.md](SVM_AND_PIPELINE.md). `wait_for_completion`,
`timeout_seconds`, `poll_seconds` apply to GitLab.

| Key | Default | Notes |
|---|---|---|
| `coalesce` | `true` | Reuse a trigger that *started after* the run's add/delete instead of triggering again — one pipeline run serves overlapping cycles and every item of a batch. |
| `retrigger_every_seconds` | `0` | Re-trigger within a phase if SVM still doesn't match after N seconds (0 = never). |

## `test`

| Key | Default | Notes |
|---|---|---|
| `mode` | `poll` | `poll`: first check after `first_check_seconds`, then every `check_interval_seconds`; pass as soon as SVM matches; fail at the `wait_hours` deadline; per-item sync latency recorded. `fixed`: one check after `wait_hours`. |
| `wait_hours` | 8 | Deadline (poll) / fixed wait. `--wait-hours 0.01` for smoke tests. |
| `first_check_seconds` | 900 | Poll mode: delay before the first SVM check (and pipeline trigger). Capped at the deadline. |
| `check_interval_seconds` | 600 | Poll mode: interval between checks. |
| `batch_size` | 1 | Components per cycle (`--batch N` overrides). |
| `max_active_runs` | 1 | Number of cycles in flight; >1 overlaps cycles. |
| `start_interval_minutes` | 0 | Minimum gap between cycle starts. |
| `state_db` | `data/state.db` | SQLite file (see state persistence in [OPERATIONS.md](OPERATIONS.md)). |
| `max_attempts` | 5 | Consecutive errors on a step before the run fails. |
| `retry_seconds` | 600 | Delay between retries. |
| `poll_seconds` | 300 | `loop` / `drain` sleep between ticks. |
| `assessment_timeout_seconds` | 180 | How long to wait for Black Duck to compute vulnerabilities after adding. |
| `run_prefix` | `bd-svm` | Prefix of run ids. |

## `notify`

| Key | Default | Notes |
|---|---|---|
| `webhook_url` | `${NOTIFY_WEBHOOK_URL}` | Empty = notifications off. |
| `format` | `slack` | `slack` (`{"text": …}`), `teams` (MessageCard), `generic` (JSON with run id, status, items). |
| `on` | `[failed, passed, cleanup_failed]` | Events to send. |
| `prefix` | `""` | Prepended to the message, e.g. `"@oncall "`. |

## `evidence`

| Key | Default | Notes |
|---|---|---|
| `dir` | `data/evidence` | UI screenshots: `<dir>/<run_id>/<phase>-<component>-ui.png`. |
| `max_records` | 5 | SVM records / UI rows kept in the run per check. |

## Environment variables

`BLACKDUCK_URL`, `BLACKDUCK_API_TOKEN`, `BLACKDUCK_PROJECT`,
`BLACKDUCK_PROJECT_VERSION`, `SVM_URL`, `SVM_API_TOKEN`, `SVM_UI_URL`,
`SVM_UI_USER`, `SVM_UI_PASSWORD`, `GITLAB_URL`, `GITLAB_PROJECT_ID`,
`GITLAB_TRIGGER_TOKEN`, `GITLAB_ACCESS_TOKEN`, `NOTIFY_WEBHOOK_URL`, `BD_SVM_CONFIG`; for state persistence `STATE_BACKEND`, `STATE_S3_URI`, `STATE_DB`, `STATE_BRANCH`.
