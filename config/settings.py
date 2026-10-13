"""Central settings: environment variables (and a local .env) -> constants.

Every Black Duck URL and API path is configurable here, so the suite can be
pointed at any Black Duck instance / API revision without touching test code:

    BD_HOST                    https://blackduck.example.com
    BD_PATH_<NAME>             override one path template (see DEFAULT_PATHS)
    BD_MEDIA_<NAME>            override one media type (see DEFAULT_MEDIA)

See docs/SETTINGS.md for the full list.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class SettingsError(Exception):
    pass


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader. Never overrides variables that are already set."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_dotenv(ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


# --- Black Duck connection ------------------------------------------------------
BD_HOST = _env("BD_HOST").rstrip("/")
BD_API_KEY = _env("BD_API_KEY")
BD_VERIFY_SSL = _bool("BD_VERIFY_SSL", True)
BD_TIMEOUT = int(_env("BD_TIMEOUT", "60"))
BD_HTTP_RETRIES = int(_env("BD_HTTP_RETRIES", "3"))

# --- What the tests operate on ----------------------------------------------------
BD_PROJECT_NAME = _env("BD_PROJECT_NAME", "svm-e2e-test")      # use a DEDICATED project
BD_PROJECT_VERSION = _env("BD_PROJECT_VERSION", "main")
BD_COMPONENT_NAME = _env("BD_COMPONENT_NAME", "commons-text")
BD_COMPONENT_VERSION = _env("BD_COMPONENT_VERSION", "1.9")
BD_VULN_ID = _env("BD_VULN_ID", "CVE-2022-42889")

# --- Assessment values (phase 1) ----------------------------------------------------
BD_RESET_STATUS = _env("BD_RESET_STATUS", "NEEDS_REVIEW")
BD_REMEDIATION_STATUS = _env("BD_REMEDIATION_STATUS", "NOT_AFFECTED")
BD_REMEDIATION_COMMENT = _env("BD_REMEDIATION_COMMENT", "api-automation e2e test")
BD_USAGE = _env("BD_USAGE", "DYNAMICALLY_LINKED")
BD_REVIEW_STATUS = _env("BD_REVIEW_STATUS", "REVIEWED")
BD_VULN_WAIT_SECONDS = int(_env("BD_VULN_WAIT_SECONDS", "180"))   # BD computes vulns async

# --- State hand-off between phases ----------------------------------------------------
STATE_FILE = Path(_env("STATE_FILE", str(ROOT / "state.json")))
WAIT_HOURS = float(_env("WAIT_HOURS", "4"))                       # used by `make cycle`

# --- API paths (templates) ---------------------------------------------------------------
DEFAULT_PATHS = {
    "authenticate": "/api/tokens/authenticate",
    "current_version": "/api/current-version",
    "projects": "/api/projects",
    "project_versions": "/api/projects/{project_id}/versions",
    "components_search": "/api/components",
    "component_versions": "/api/components/{component_id}/versions",
    "bom_components": "/api/projects/{project_id}/versions/{version_id}/components",
    "bom_component_version": "/api/projects/{project_id}/versions/{version_id}"
                             "/components/{component_id}/versions/{comp_ver_id}",
    "vulnerable_bom_components": "/api/projects/{project_id}/versions/{version_id}/vulnerable-bom-components",
    "vulnerability_remediation": "/api/projects/{project_id}/versions/{version_id}"
                                 "/components/{component_id}/versions/{comp_ver_id}"
                                 "/vulnerabilities/{vuln_id}/remediation",
}
PATHS = {k: _env(f"BD_PATH_{k.upper()}", v) for k, v in DEFAULT_PATHS.items()}

# --- Media types (see utils/bd_headers.py) -------------------------------------------------
DEFAULT_MEDIA = {
    "default": "application/json",
    "auth": "application/vnd.blackducksoftware.user-4+json",
    "project": "application/vnd.blackducksoftware.project-detail-4+json",
    "bom": "application/vnd.blackducksoftware.bill-of-materials-6+json",
    "vulnerability": "application/vnd.blackducksoftware.vulnerability-4+json",
}
MEDIA = {k: _env(f"BD_MEDIA_{k.upper()}", v) for k, v in DEFAULT_MEDIA.items()}


def require(*names: str) -> None:
    """Fail fast with a helpful message when mandatory settings are missing."""
    missing = [n for n in names if not globals().get(n)]
    if missing:
        raise SettingsError(
            "missing required setting(s): " + ", ".join(missing)
            + " - set them as environment variables or in .env (see .env.example)")
