# Settings

> Task-oriented examples: [HOWTO.md §6–8](HOWTO.md#6-test-a-different-component-or-cve).

All settings are environment variables, read by `config/settings.py`. A local
`.env` (copy of `.env.example`) is loaded automatically and never overrides
variables that are already set. In GitHub Actions they come from repository
**secrets** and **variables** (see [GITHUB_ACTIONS.md](GITHUB_ACTIONS.md)).

## Connection

| Variable | Default | Notes |
|---|---|---|
| `BD_HOST` | – (required) | Black Duck base URL, e.g. `https://blackduck.corp.com` |
| `BD_API_KEY` | – (required) | User API token (exchanged for a bearer token) |
| `BD_VERIFY_SSL` | `true` | `false` only for lab servers with self-signed certs |
| `BD_TIMEOUT` | `60` | seconds per request |
| `BD_HTTP_RETRIES` | `3` | retries with backoff on connection errors and 429/5xx for GET/PUT/DELETE (never POST) |

## What is tested

| Variable | Default | Notes |
|---|---|---|
| `BD_PROJECT_NAME` | `svm-e2e-test` | **Use a dedicated project** — phases add and delete BOM items |
| `BD_PROJECT_VERSION` | `main` | |
| `BD_COMPONENT_NAME` | `commons-text` | KB component to add |
| `BD_COMPONENT_VERSION` | `1.9` | must have the CVE below |
| `BD_VULN_ID` | `CVE-2022-42889` | vulnerability that is remediated |

## Assessment values

| Variable | Default | Used in |
|---|---|---|
| `BD_RESET_STATUS` | `NEEDS_REVIEW` | phase 1 step 07 (asserted in step 10) |
| `BD_REMEDIATION_STATUS` | `NOT_AFFECTED` | phase 1 step 11 (asserted in step 12) |
| `BD_REMEDIATION_COMMENT` | `api-automation e2e test` | remediation comment |
| `BD_USAGE` | `DYNAMICALLY_LINKED` | step 08 `usages` |
| `BD_REVIEW_STATUS` | `REVIEWED` | step 08 `reviewStatus` |
| `BD_VULN_WAIT_SECONDS` | `180` | how long step 07 waits for Black Duck to compute the CVE after the add |

## State and timing

| Variable | Default | Notes |
|---|---|---|
| `STATE_FILE` | `<repo>/state.json` | hand-off file |
| `WAIT_HOURS` | `4` | only for `make cycle` (`0` = no wait) |
| `NOTIFY_WEBHOOK_URL` | – | optional Slack-compatible webhook used by the workflows on failure |

## API paths — configurable

Every path is a template; override any with `BD_PATH_<KEY>`:

| Key | Default |
|---|---|
| `AUTHENTICATE` | `/api/tokens/authenticate` |
| `CURRENT_VERSION` | `/api/current-version` |
| `PROJECTS` | `/api/projects` |
| `PROJECT_VERSIONS` | `/api/projects/{project_id}/versions` |
| `COMPONENTS_SEARCH` | `/api/components` |
| `COMPONENT_VERSIONS` | `/api/components/{component_id}/versions` |
| `BOM_COMPONENTS` | `/api/projects/{project_id}/versions/{version_id}/components` |
| `BOM_COMPONENT_VERSION` | `…/components/{component_id}/versions/{comp_ver_id}` |
| `VULNERABLE_BOM_COMPONENTS` | `…/versions/{version_id}/vulnerable-bom-components` |
| `VULNERABILITY_REMEDIATION` | `…/components/{component_id}/versions/{comp_ver_id}/vulnerabilities/{vuln_id}/remediation` |

Example (Black Duck behind a gateway prefix):

```ini
BD_HOST=https://gateway.corp.com
BD_PATH_PROJECTS=/blackduck/api/projects
```

## Media types — configurable

Override with `BD_MEDIA_<KEY>`: `DEFAULT` (`application/json`), `AUTH`
(`…user-4+json`), `PROJECT` (`…project-detail-4+json`), `BOM`
(`…bill-of-materials-6+json`), `VULNERABILITY` (`…vulnerability-4+json`).
Bump the revision if your server rejects the default with HTTP 406.
