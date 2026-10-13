"""PHASE 1 - setup (12 steps, GitHub Actions cron 08:00 UTC).

Add a vulnerable component to the Black Duck BOM, verify it, reset and update
its review state, remediate the CVE, verify the remediation persisted, then
write state.json for phase 2.

Steps depend on each other: the first failure aborts the phase (the remaining
steps are skipped) and a component we already added is removed again so no
test data is left behind.
"""
import pytest

from config import settings
from utils import auth, reporter, state
from utils.api_client import last_segment

pytestmark = pytest.mark.sequential


def _ids(ctx):
    return {k: ctx[k] for k in ("project_id", "version_id", "component_id", "comp_ver_id")}


@pytest.fixture(scope="module")
def ctx(client):
    c = {"added": False, "passed": False}
    yield c
    if c["added"] and not c["passed"]:                      # phase failed after the add: clean up
        try:
            client.delete("bom_component_version", path_vars=_ids(c))
            reporter.note("cleanup: phase 1 failed after the add - test component removed from BOM")
        except Exception as exc:                            # surface it, never mask the real failure
            reporter.note(f"cleanup FAILED - remove {settings.BD_COMPONENT_NAME} manually: {exc}")


def test_01_auth_fresh_bearer_token():
    token = auth.get_token(force=True)
    assert token, "no bearer token returned"


def test_02_find_project_by_name(client, ctx):
    project = client.find_project(settings.BD_PROJECT_NAME)
    assert project, f"project '{settings.BD_PROJECT_NAME}' not found"
    ctx["project_id"] = last_segment(project["_meta"]["href"])


def test_03_find_project_version(client, ctx):
    version = client.find_version(ctx["project_id"], settings.BD_PROJECT_VERSION)
    assert version, f"version '{settings.BD_PROJECT_VERSION}' not found in '{settings.BD_PROJECT_NAME}'"
    ctx["version_id"] = last_segment(version["_meta"]["href"])


def test_04_find_kb_component(client, ctx):
    found = client.find_kb_component(settings.BD_COMPONENT_NAME, settings.BD_COMPONENT_VERSION)
    assert found, f"{settings.BD_COMPONENT_NAME} {settings.BD_COMPONENT_VERSION} not found in the KB"
    ctx.update(found)
    reporter.note(f"COMPONENT_ID={found['component_id']} COMP_VER_ID={found['comp_ver_id']}")


def test_05_baseline_count_then_add_component(client, ctx):
    ids = _ids(ctx)
    ctx["bom_count_before"] = client.bom_count(ids["project_id"], ids["version_id"])      # baseline = N
    assert client.find_bom_item(**ids) is None, (
        f"{settings.BD_COMPONENT_NAME} {settings.BD_COMPONENT_VERSION} is already in the BOM; "
        "remove it or choose another component (BD_COMPONENT_NAME/BD_COMPONENT_VERSION)")
    resp = client.post("bom_components", path_vars={k: ids[k] for k in ("project_id", "version_id")},
                       json={"component": ctx["comp_ver_href"]}, content="bom")
    assert resp.status_code in (200, 201), f"unexpected status {resp.status_code}"
    ctx["added"] = True


def test_06_verify_count_n_plus_1_and_manual(client, ctx):
    ids = _ids(ctx)
    after = client.bom_count(ids["project_id"], ids["version_id"])
    assert after == ctx["bom_count_before"] + 1, f"BOM count {after}, expected {ctx['bom_count_before'] + 1}"
    ctx["bom_count_after"] = after
    item = client.find_bom_item(**ids)
    assert item, "added component not found in the BOM list"
    assert "MANUAL_BOM_COMPONENT" in (item.get("matchTypes") or []), f"matchTypes={item.get('matchTypes')}"


def test_07_reset_remediation_to_needs_review(client, ctx):
    found = client.wait_for_vulnerability(_ids(ctx), settings.BD_VULN_ID)
    assert settings.BD_VULN_ID in found, f"{settings.BD_VULN_ID} not reported for the component (saw {sorted(found)})"
    resp = client.set_remediation(_ids(ctx), settings.BD_VULN_ID, settings.BD_RESET_STATUS,
                                  settings.BD_REMEDIATION_COMMENT)
    assert resp.status_code in (200, 202, 204)


def test_08_update_usage_and_review_status(client, ctx):
    ids = _ids(ctx)
    item = client.find_bom_item(**ids)
    assert item, "component missing from BOM"
    body = {k: v for k, v in item.items() if k != "_meta"}
    body.update(usages=[settings.BD_USAGE], reviewStatus=settings.BD_REVIEW_STATUS)
    resp = client.put("bom_component_version", path_vars=ids, json=body, content="bom")
    assert resp.status_code in (200, 202, 204)


def test_09_verify_update_persisted(client, ctx):
    item = client.find_bom_item(**_ids(ctx))
    assert item, "component missing from BOM"
    assert settings.BD_USAGE in (item.get("usages") or []), f"usages={item.get('usages')}"
    assert item.get("reviewStatus") == settings.BD_REVIEW_STATUS, f"reviewStatus={item.get('reviewStatus')}"


def test_10_list_all_vulnerabilities(client, ctx):
    found = client.vulnerability_status(**_ids(ctx))
    reporter.note(f"{len(found)} vulnerabilities: " + ", ".join(f"{k}={v}" for k, v in sorted(found.items())))
    assert settings.BD_VULN_ID in found, f"{settings.BD_VULN_ID} missing (saw {sorted(found)})"
    assert found[settings.BD_VULN_ID] == settings.BD_RESET_STATUS, (
        f"expected {settings.BD_RESET_STATUS} after reset, got {found[settings.BD_VULN_ID]}")


def test_11_remediate_cve(client, ctx):
    resp = client.set_remediation(_ids(ctx), settings.BD_VULN_ID, settings.BD_REMEDIATION_STATUS,
                                  settings.BD_REMEDIATION_COMMENT)
    assert resp.status_code in (200, 202, 204)


def test_12_verify_remediation_and_write_state(client, ctx):
    found = client.vulnerability_status(**_ids(ctx))
    assert found.get(settings.BD_VULN_ID) == settings.BD_REMEDIATION_STATUS, (
        f"expected {settings.BD_REMEDIATION_STATUS}, got {found.get(settings.BD_VULN_ID)}")
    data = {"run_id": state.new_run_id(), "project_id": ctx["project_id"], "version_id": ctx["version_id"],
            "component_id": ctx["component_id"], "comp_ver_id": ctx["comp_ver_id"],
            "vuln_id": settings.BD_VULN_ID, "bom_count_before": ctx["bom_count_before"],
            "bom_count_after": ctx["bom_count_after"]}
    path = state.save_state(data)
    ctx["passed"] = True
    reporter.note(f"count audit: baseline {data['bom_count_before']} -> after add {data['bom_count_after']} "
                  f"(state written to {path.name})")
