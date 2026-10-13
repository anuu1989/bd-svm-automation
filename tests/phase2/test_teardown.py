"""PHASE 2 - teardown (5 steps, GitHub Actions cron 12:00 UTC = 4 hours after phase 1).

Re-authenticate (the phase 1 token has expired), load state.json, confirm the
component is still in the BOM, delete it, and verify the BOM count is back to
the phase 1 baseline.
"""
import pytest

from utils import auth, reporter, state

pytestmark = pytest.mark.sequential


@pytest.fixture(scope="module")
def ctx():
    return {}


def _ids(ctx):
    return {k: ctx[k] for k in ("project_id", "version_id", "component_id", "comp_ver_id")}


def test_01_auth_fresh_bearer_token_expired():
    assert auth.get_token(force=True), "no bearer token returned"


def test_02_load_state_json_show_ids_and_phase1_counts(ctx):
    data = state.load_state()
    ctx.update(data)
    for key in state.REQUIRED_KEYS:
        reporter.note(f"{key} = {data[key]}")
    assert data["bom_count_after"] == data["bom_count_before"] + 1, "phase 1 counts are inconsistent"


def test_03_verify_bom_count_still_n_plus_1(client, ctx):
    count = client.bom_count(ctx["project_id"], ctx["version_id"])
    assert count == ctx["bom_count_after"], (
        f"BOM count is {count}, phase 1 left {ctx['bom_count_after']} - "
        "the BOM changed in between (or the component was removed)")
    assert client.find_bom_item(**_ids(ctx)), "component no longer in the BOM after 4 hours"


def test_04_delete_component_from_bom_204(client, ctx):
    resp = client.delete("bom_component_version", path_vars=_ids(ctx))
    assert resp.status_code == 204, f"expected 204, got {resp.status_code}"


def test_05_verify_count_back_to_baseline(client, ctx):
    count = client.bom_count(ctx["project_id"], ctx["version_id"])
    assert count == ctx["bom_count_before"], (
        f"BOM count is {count}, expected baseline {ctx['bom_count_before']}")
    assert client.find_bom_item(**_ids(ctx)) is None, "component still listed in the BOM"
    reporter.note(f"count audit: baseline {ctx['bom_count_before']} -> +1 = {ctx['bom_count_after']} "
                  f"-> -1 = {count} (baseline restored)")
