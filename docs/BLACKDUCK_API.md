# Black Duck API usage

All calls go to `blackduck.base_url` + a configurable path
([CONFIGURATION.md](CONFIGURATION.md)). Black Duck's API is hypermedia-driven,
so where the API returns an `_meta.href`, that full URL is used rather than a
constructed path.

> **Verify on your instance.** This client was written from the public Black
> Duck Hub REST API (Swagger at `<base_url>/api-doc/public.html`) and has not
> been run against your server. The table below lists exactly what to check.
> Black Duck has changed some vulnerability/BOM endpoints between releases; if
> a call differs, change `paths.*` / `media_types.*` — or adjust
> `bd_svm/blackduck.py`, which is intentionally small.

## Calls

| Step | Request | Notes |
|---|---|---|
| Authenticate | `POST {paths.authenticate}` with `Authorization: token <api_token>` | Response `bearerToken` used as `Authorization: Bearer …`. Re-authenticates on 401. |
| Find project | `GET {paths.projects}?q=name:<project>` | Exact name match on `items[].name`. |
| Find version | `GET {paths.project_versions}?q=versionName:<v>` | Exact match on `versionName`. |
| Resolve component | `GET {paths.components_search}?q=name:<n>` then `GET {component_versions}` | Match `versionName`; yields the *component version* URL. |
| Find vulnerability | `GET {component_version_vulnerabilities}` (`Accept: …vulnerability-4+json`) | First item's `name` (CVE/BDSA id) is asserted downstream. |
| Add component | `POST {paths.bom_components}` body `{"component": "<component version url>"}`, `Content-Type: …bill-of-materials-6+json` | Then BOM is listed to find the created item. |
| Assessment | `GET {paths.vulnerable_bom_components}` | Items filtered by `componentVersion`; vulnerability ids read from `vulnerabilityWithRemediation.vulnerabilityName`. Polled up to `assessment_timeout_seconds` since BD computes it asynchronously. |
| Delete | `DELETE <_meta.href of the BOM item>` | Only for the exact component version the run added; refused when `matchTypes` is present and lacks `MANUAL_BOM_COMPONENT`. |
| Verify deleted | `GET {paths.bom_components}` | Item must be gone. |

Token permissions: the API token's user needs write access to the test
project (BOM edit) and read access to the component KB.

## Things worth checking first

1. `make doctor` – auth + project/version lookup.
2. Whether the add response requires a `componentVersionOrigin` / `origin` in
   your release (some versions need `{"component": …, "componentVersion": …}`).
   Adjust the payload in `BlackDuckClient.add_component`.
3. That the BOM item's `matchTypes` contains `MANUAL_BOM_COMPONENT` for
   manually-added components; otherwise set
   `require_manual_match_type: false` (the exact-href guard still applies).
4. The field names in `vulnerable-bom-components` items
   (`componentVersion`, `vulnerabilityWithRemediation.vulnerabilityName`).

## Extended API surface

Everything below is on `BlackDuckClient` and reachable from the shell as
`python -m bd_svm bd <command>` or a `make bd-*` recipe. Commands that change
Black Duck need `--yes` / `YES=1`.

| Capability | Method | HTTP | Path key (`blackduck.paths.*`) | Make recipe |
|---|---|---|---|---|
| Current user / server version | `whoami`, `server_version` | GET | `current_user`, `current_version` | `bd-whoami` |
| List projects | `list_projects` | GET | `projects` | `bd-projects` |
| Create project | `create_project` | POST | `projects` | `bd-create-project` |
| Delete project | `delete_project` | DELETE | `project` | `bd-delete-project` |
| List versions | `list_versions` | GET | `project_versions` | `bd-versions` |
| Create version | `create_version` | POST | `project_versions` | `bd-create-version` |
| Delete version | `delete_version` | DELETE | `project_version` | `bd-delete-version` |
| List BOM | `list_bom_components` | GET | `bom_components` | `bd-bom` |
| **Add** component | `add_component` | POST | `bom_components` | `bd-add` |
| **Update** BOM item (ignore, review status, …) | `update_bom_item`, `set_ignored` | PUT | item `_meta.href` | `bd-ignore`, `bd-unignore` |
| **Delete** component | `delete_component` | DELETE | item `_meta.href` | `bd-delete` |
| Vulnerable BOM components | `list_vulnerable_items` | GET | `vulnerable_bom_components` | `bd-vulns` |
| **Update** remediation (assessment) | `update_remediation` | PUT | `vulnerability_remediation` (or item `remediation` link) | `bd-remediate` |
| Search KB components | `search_components` | GET | `components_search` | `bd-search` |
| Component versions | `list_component_versions` | GET | `component_versions` | `bd-search VERSIONS=1` |
| Component vulnerabilities | `list_vulnerabilities` | GET | `component_version_vulnerabilities` | `bd-component-vulns` |
| Vulnerability details | `get_vulnerability` | GET | `vulnerability` | `bd-vuln` |
| Upgrade guidance | `upgrade_guidance` | GET | `upgrade_guidance` | `bd-upgrade` |
| Policy status | `policy_status` | GET | `policy_status` | `bd-policy` |
| Risk profile | `risk_profile` | GET | `risk_profile` | `bd-risk` |
| BOM status | `bom_status` | GET | `bom_status` | `bd-bom-status` |
| Code locations (scans) | `list_code_locations`, `delete_code_location` | GET / DELETE | `code_locations` | `bd-codelocations` |
| **Anything else** | `raw(method, path, body=…)` | any | – | `bd-api` |

`bd-api` is the catch-all for endpoints without a dedicated method, e.g.
`make bd-api METHOD=GET API_PATH=/api/notifications`.

Update semantics: `update_bom_item` does GET → merge your changes → PUT of the
BOM item (dropping `_meta`), which is how Black Duck expects edits.
`update_remediation` sends `{"remediationStatus": …, "comment": …}`; valid
statuses: `NEW NEEDS_REVIEW REMEDIATION_REQUIRED REMEDIATION_COMPLETE
MITIGATED PATCHED IGNORED DUPLICATE`.

> The extended endpoints (remediation, risk profile, policy status, upgrade
> guidance, code locations, bom-status) follow the Hub REST API but are the
> least-verified part of this client — confirm them against
> `<base_url>/api-doc/public.html` and adjust `paths.*` if your release differs.

## Assessment inside the test flow

Two ways a remediation status ("assessment") is applied during a cycle, always
after Black Duck reports the vulnerability for the added component:

- per candidate: `scenario: remediation` with `status: IGNORED` (etc.) — the
  status is also asserted in SVM when `svm.api.fields.remediation_status` is
  mapped;
- globally: `blackduck.assessment.enabled: true` applies `status` to every
  non-negative item.

The applied status is recorded on the item (`remediation_status`). Default is
off so the target BOM's reporting is not changed unexpectedly.

## Selection and safety

`select_components` resolves each configured candidate through the KB
(`components_search` → `component_versions` →
`component_version_vulnerabilities`), skips anything already in the target
BOM, and enforces the scenario's vulnerability requirement (`negative` needs
none). `delete_component` only touches the exact component version href a run
recorded and refuses non-manual BOM items; `sweep` additionally limits itself
to configured candidate names in the test BOM.
