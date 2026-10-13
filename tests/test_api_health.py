"""Smoke test: connectivity, credentials and the objects the phases rely on.
Read-only - safe to run any time (`make health`)."""
import pytest


def test_auth_returns_bearer_token(settings):
    from utils import auth
    assert auth.get_token(force=True)


def test_server_version_endpoint(client):
    assert client.get("current_version").status_code == 200


@pytest.fixture(scope="module")
def project(client, settings):
    found = client.find_project(settings.BD_PROJECT_NAME)
    assert found, f"project '{settings.BD_PROJECT_NAME}' not found"
    return found


def test_project_exists(project):
    assert project["name"]


def test_project_version_exists(client, settings, project):
    from utils.api_client import last_segment
    pid = last_segment(project["_meta"]["href"])
    assert client.find_version(pid, settings.BD_PROJECT_VERSION), \
        f"version '{settings.BD_PROJECT_VERSION}' not found"


def test_kb_component_resolvable(client, settings):
    found = client.find_kb_component(settings.BD_COMPONENT_NAME, settings.BD_COMPONENT_VERSION)
    assert found, f"{settings.BD_COMPONENT_NAME} {settings.BD_COMPONENT_VERSION} not found in the KB"
