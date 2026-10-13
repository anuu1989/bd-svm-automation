"""Configuration loading: YAML file + ${ENV} expansion + .env support.

Every Black Duck URL / API path / media type lives in configuration so the
tool can be pointed at any Black Duck instance or API version without code
changes. See docs/CONFIGURATION.md.
"""
from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(Exception):
    pass


class AttrDict(dict):
    """dict with attribute access (missing keys -> None)."""

    def __init__(self, data: dict | None = None):
        super().__init__()
        for key, value in (data or {}).items():
            self[key] = AttrDict(value) if isinstance(value, dict) else value

    def __getattr__(self, item: str) -> Any:
        return self.get(item)


DEFAULTS: dict[str, Any] = {
    "blackduck": {
        "base_url": "${BLACKDUCK_URL}",
        "api_token": "${BLACKDUCK_API_TOKEN}",
        "verify_ssl": True,
        "timeout_seconds": 60,
        "page_size": 100,
        # Target BOM that test components are added to / removed from.
        # Use a DEDICATED project version - the tool mutates its BOM.
        "project_name": "${BLACKDUCK_PROJECT:-svm-e2e-test}",
        "project_version": "${BLACKDUCK_PROJECT_VERSION:-main}",
        # All API paths are templates. {placeholders} are filled at runtime.
        "paths": {
            "authenticate": "/api/tokens/authenticate",
            "projects": "/api/projects",
            "project_versions": "/api/projects/{project_id}/versions",
            "bom_components": "/api/projects/{project_id}/versions/{version_id}/components",
            "vulnerable_bom_components": "/api/projects/{project_id}/versions/{version_id}/vulnerable-bom-components",
            "components_search": "/api/components",
            "component_versions": "{component_href}/versions",
            "component_version_vulnerabilities": "{component_version_href}/vulnerabilities",
            "current_user": "/api/current-user",
            "current_version": "/api/current-version",
            "project": "/api/projects/{project_id}",
            "project_version": "/api/projects/{project_id}/versions/{version_id}",
            "policy_status": "/api/projects/{project_id}/versions/{version_id}/policy-status",
            "risk_profile": "/api/projects/{project_id}/versions/{version_id}/risk-profile",
            "bom_status": "/api/projects/{project_id}/versions/{version_id}/bom-status",
            "vulnerability": "/api/vulnerabilities/{vuln_id}",
            "vulnerability_remediation": "/api/projects/{project_id}/versions/{version_id}/components/{component_id}/versions/{component_version_id}/vulnerabilities/{vuln_id}/remediation",
            "upgrade_guidance": "{component_version_href}/upgrade-guidance",
            "code_locations": "/api/codelocations",
        },
        "search_query": "name:{name}",
        "media_types": {
            "authenticate": "application/vnd.blackducksoftware.user-4+json",
            "default": "application/json",
            "bom": "application/vnd.blackducksoftware.bill-of-materials-6+json",
            "vulnerability": "application/vnd.blackducksoftware.vulnerability-4+json",
        },
        # Candidate components used to find "a vulnerable component".
        "candidates": [
            {"name": "log4j-core", "version": "2.14.1"},
            {"name": "jackson-databind", "version": "2.9.8"},
            {"name": "commons-text", "version": "1.9"},
        ],
        # Only accept vulnerabilities of these severities ([] = any).
        "vulnerability_severities": [],
        # Optional "assessment": set a remediation status on the test
        # vulnerability right after the component is added.
        # status: NEW NEEDS_REVIEW REMEDIATION_REQUIRED REMEDIATION_COMPLETE
        #         MITIGATED PATCHED IGNORED DUPLICATE
        "assessment": {"enabled": False, "status": "IGNORED", "comment": "bd-svm e2e test"},
        # Refuse to delete BOM items that are not flagged as manually added.
        "require_manual_match_type": True,
    },
    "svm": {
        # API check (diagram: "SVM API check"). Disabled until configured.
        "api": {
            "enabled": False,
            "base_url": "${SVM_URL:-}",
            "token": "${SVM_API_TOKEN:-}",
            "auth_header": "Authorization",
            "auth_scheme": "Bearer",  # "" sends the raw token
            "verify_ssl": True,
            "timeout_seconds": 60,
            "method": "GET",
            # Path template; {component_name} {component_version} {vuln_id} {project_name}
            "path": "/api/vulnerabilities",
            "params": {"component": "{component_name}"},
            "list_key": "",  # dotted key of the record list, "" = auto-detect
            "match_version": True,
        },
        # UI check (diagram: "SVM UI check"). Needs: pip install selenium
        "ui": {
            "enabled": False,
            "url": "${SVM_UI_URL:-}",
            "headless": True,
            "login": {
                "url": "",
                "username": "${SVM_UI_USER:-}",
                "password": "${SVM_UI_PASSWORD:-}",
                "username_selector": "input[name=username]",
                "password_selector": "input[name=password]",
                "submit_selector": "button[type=submit]",
            },
            "search_url": "{ui_url}/components?search={component_name}",
            "row_selector": "",  # CSS selector of result rows; "" = whole <body>
            "wait_selector": "body",
            "wait_seconds": 30,
            "match_version": True,
        },
        # "all" = every enabled check must agree, "any" = one is enough.
        "require": "all",
    },
    "pipeline": {
        # gitlab | webhook | command | none
        "type": "none",
        "wait_for_completion": True,
        "timeout_seconds": 3600,
        "poll_seconds": 30,
        "gitlab": {
            "base_url": "${GITLAB_URL:-https://gitlab.com}",
            "project_id": "${GITLAB_PROJECT_ID:-}",
            "trigger_token": "${GITLAB_TRIGGER_TOKEN:-}",
            "access_token": "${GITLAB_ACCESS_TOKEN:-}",  # needed to poll status
            "ref": "main",
            "variables": {},
            "verify_ssl": True,
        },
        "webhook": {"url": "", "method": "POST", "headers": {}, "body": {}},
        "command": {"argv": []},
    },
    "test": {
        "wait_hours": 8,
        "state_db": "data/state.db",
        "max_attempts": 5,  # retries per step on transient errors
        "poll_seconds": 300,  # `loop` sleep interval
        "retry_seconds": 600,  # delay before retrying a failed step
        "assessment_timeout_seconds": 180,  # wait for BD to compute vulns after add
        "run_prefix": "bd-svm",
    },
}


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_dotenv(path: str | Path = ".env") -> None:
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip("'\""))


def load_config(path: str | Path | None = None, overrides: dict | None = None) -> AttrDict:
    load_dotenv()
    data: dict[str, Any] = {}
    cfg_path = path or os.environ.get("BD_SVM_CONFIG") or "config/config.yaml"
    p = Path(cfg_path)
    if p.is_file():
        data = yaml.safe_load(p.read_text()) or {}
    elif path:
        raise ConfigError(f"config file not found: {p}")
    merged = _merge(DEFAULTS, data)
    if overrides:
        merged = _merge(merged, overrides)
    return AttrDict(_expand(merged))


def validate(cfg: AttrDict) -> list[str]:
    """Return a list of human-readable problems (empty = OK)."""
    problems = []
    bd = cfg.blackduck
    if not bd.base_url:
        problems.append("blackduck.base_url is empty (set BLACKDUCK_URL)")
    if not bd.api_token:
        problems.append("blackduck.api_token is empty (set BLACKDUCK_API_TOKEN)")
    if not (bd.project_name and bd.project_version):
        problems.append("blackduck.project_name / project_version must be set")
    if not bd.candidates:
        problems.append("blackduck.candidates must list at least one component")
    if not (cfg.svm.api.enabled or cfg.svm.ui.enabled):
        problems.append("enable at least one of svm.api / svm.ui, otherwise nothing is verified")
    if cfg.svm.api.enabled and not cfg.svm.api.base_url:
        problems.append("svm.api.base_url is empty (set SVM_URL)")
    if cfg.svm.ui.enabled and not cfg.svm.ui.url:
        problems.append("svm.ui.url is empty (set SVM_UI_URL)")
    ptype = cfg.pipeline.type
    if ptype not in ("gitlab", "webhook", "command", "none"):
        problems.append(f"pipeline.type '{ptype}' is not one of gitlab|webhook|command|none")
    if ptype == "gitlab" and not (cfg.pipeline.gitlab.project_id and cfg.pipeline.gitlab.trigger_token):
        problems.append("pipeline.gitlab.project_id and trigger_token are required")
    if ptype == "webhook" and not cfg.pipeline.webhook.url:
        problems.append("pipeline.webhook.url is required")
    if ptype == "command" and not cfg.pipeline.command.argv:
        problems.append("pipeline.command.argv is required")
    return problems
