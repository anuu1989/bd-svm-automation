# SVM checks and pipeline trigger

These two pieces are environment-specific, so they are configuration-driven
with no hard-coded endpoints.

## SVM API check (`svm.api`)

Sends one HTTP request per check and decides if the component appears.

```yaml
svm:
  api:
    enabled: true
    base_url: https://svm.corp.com
    token: ${SVM_API_TOKEN}
    path: /api/v1/products/{project_name}/vulnerabilities
    params: { search: "{component_name}", limit: "500" }
    list_key: data.items        # where the records live
```

- Records are the objects in `list_key` (or the first list of objects found).
- A record matches if its JSON text contains the component name, version and
  vulnerability id (case-insensitive).
- Pagination is not followed — use `params` to request a large page or filter
  server-side by component so the match is in the first page.
- Any HTTP/JSON error ⇒ result "error" ⇒ the step is retried, never
  silently passed.

## SVM UI check (`svm.ui`)

Selenium + headless Chrome. `make install-ui` installs Selenium (Selenium
Manager downloads the driver).

```yaml
svm:
  ui:
    enabled: true
    url: https://svm.corp.com
    search_url: "{ui_url}/components?search={component_name}"
    row_selector: "table.vuln-table tbody tr"
    wait_selector: "table.vuln-table"
    login:
      url: https://svm.corp.com/login
      username_selector: "#user"
      password_selector: "#pass"
      submit_selector: "button[type=submit]"
```

Each row's visible text is matched like an API record. Without
`row_selector` the whole `<body>` text is matched, which is looser (a CVE in
an unrelated row on the same page can match) — set a row selector for the
DELETE test to be meaningful. If SVM uses SSO you may need to extend
`SvmUiCheck` (e.g. reuse a session cookie) — it is ~40 lines in `bd_svm/svm.py`.

## Pipeline trigger (`pipeline`)

| type | Behaviour |
|---|---|
| `gitlab` | `POST /api/v4/projects/{id}/trigger/pipeline` with trigger token, `ref`, and `variables` (plus `BD_SVM_RUN_ID`). With `wait_for_completion` it polls `GET …/pipelines/{id}` (needs `access_token`, scope `read_api`) and fails the test unless status is `success`. |
| `webhook` | HTTP request to `webhook.url` with JSON `body` + `run_id`. Does not wait. |
| `command` | Runs `command.argv` (`{run_id}` substituted). Non-zero exit fails the test. |
| `none` | Does nothing — use when the sync pipeline is already scheduled externally and you only want to wait and verify. |

If the verification pipeline is a schedule you don't control, use `none` and
set `wait_hours` to cover the schedule interval.
