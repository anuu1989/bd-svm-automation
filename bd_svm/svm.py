"""SVM verification: API check and (optional) Selenium UI check.

A check answers "is this component (+ vulnerability) shown in SVM?" and, for
the API check, optionally "are the field values right?" (severity,
remediation status). Each result carries `evidence` that is stored with the run.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .http import make_session

log = logging.getLogger(__name__)


@dataclass
class CheckResult:
    name: str                       # "api" | "ui"
    found: bool | None              # None = check errored / skipped
    detail: str = ""
    error: str = ""
    fields_ok: bool | None = None   # None = no field expectations / not applicable
    field_issues: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"name": self.name, "found": self.found, "detail": self.detail, "error": self.error,
                "fields_ok": self.fields_ok, "field_issues": self.field_issues,
                "evidence": self.evidence}


@dataclass
class Subject:
    """What we look for in SVM."""
    component_name: str
    component_version: str
    vuln_id: str
    project_name: str = ""
    expected: dict = field(default_factory=dict)  # severity, remediation_status
    extra: dict = field(default_factory=dict)     # evidence_prefix, max_records

    def fmt(self) -> dict:
        return {"component_name": self.component_name, "component_version": self.component_version,
                "vuln_id": self.vuln_id, "project_name": self.project_name}


def extract_records(payload: Any, list_key: str = "") -> list:
    if list_key:
        for part in list_key.split("."):
            payload = payload.get(part, []) if isinstance(payload, dict) else []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
        return [payload]
    return []


def record_matches(record: Any, subject: Subject, match_version: bool = True) -> bool:
    """A record matches when component, (version) and vuln id co-occur in it."""
    text = json.dumps(record, default=str).lower() if not isinstance(record, str) else record.lower()
    if subject.component_name.lower() not in text:
        return False
    if subject.vuln_id and subject.vuln_id.lower() not in text:
        return False
    if match_version and subject.component_version and subject.component_version.lower() not in text:
        return False
    return True


def dig(obj: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def check_fields(record: Any, expected: dict, mapping: dict) -> list[str]:
    """Compare expected values with the record. Unmapped / empty expectations are skipped."""
    issues = []
    for key, want in (expected or {}).items():
        path = (mapping or {}).get(key)
        if not path or want in (None, ""):
            continue
        got = dig(record, path)
        if str(got).strip().lower() != str(want).strip().lower():
            issues.append(f"{key}: expected {want}, got {got}")
    return issues


class SvmApiCheck:
    name = "api"

    def __init__(self, cfg, session=None):
        self.cfg = cfg
        self.http = session or make_session(int(cfg.retries or 0))

    def check(self, subject: Subject) -> CheckResult:
        c, f = self.cfg, subject.fmt()
        headers = {"Accept": "application/json"}
        if c.token:
            headers[c.auth_header] = f"{c.auth_scheme} {c.token}".strip()
        url = c.base_url.rstrip("/") + "/" + c.path.format(**f).lstrip("/")
        params = {k: str(v).format(**f) for k, v in (c.params or {}).items()}
        try:
            resp = self.http.request(c.method, url, headers=headers, params=params,
                                     verify=bool(c.verify_ssl), timeout=c.timeout_seconds)
            resp.raise_for_status()
            records = extract_records(resp.json(), c.list_key or "")
        except Exception as exc:  # network / HTTP / JSON
            return CheckResult(self.name, None, error=f"{type(exc).__name__}: {exc}")
        hits = [r for r in records if record_matches(r, subject, bool(c.match_version))]
        keep = int(subject.extra.get("max_records", 5))
        result = CheckResult(self.name, bool(hits), f"{len(hits)}/{len(records)} records match",
                             evidence={"url": url, "http_status": resp.status_code,
                                       "records_total": len(records), "matched": hits[:keep]})
        if hits and c.fields and subject.expected:
            per_hit = [check_fields(h, subject.expected, c.fields) for h in hits]
            result.fields_ok = any(not issues for issues in per_hit)
            if not result.fields_ok:
                result.field_issues = per_hit[0]
        return result


class SvmUiCheck:
    name = "ui"

    def __init__(self, cfg):
        self.cfg = cfg

    def check(self, subject: Subject) -> CheckResult:
        try:
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.support.ui import WebDriverWait
        except ImportError:
            return CheckResult(self.name, None, error="selenium not installed (make install-ui)")
        c = self.cfg
        opts = webdriver.ChromeOptions()
        if c.headless:
            opts.add_argument("--headless=new")
        driver = webdriver.Chrome(options=opts)
        evidence: dict = {}
        try:
            if c.login.url:
                driver.get(c.login.url)
                driver.find_element(By.CSS_SELECTOR, c.login.username_selector).send_keys(c.login.username)
                driver.find_element(By.CSS_SELECTOR, c.login.password_selector).send_keys(c.login.password)
                driver.find_element(By.CSS_SELECTOR, c.login.submit_selector).click()
            url = c.search_url.format(ui_url=c.url.rstrip("/"), **subject.fmt())
            driver.get(url)
            evidence["url"] = url
            WebDriverWait(driver, c.wait_seconds).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, c.wait_selector)))
            if c.row_selector:
                rows = [r.text for r in driver.find_elements(By.CSS_SELECTOR, c.row_selector)]
            else:
                rows = [driver.find_element(By.TAG_NAME, "body").text]
            prefix = subject.extra.get("evidence_prefix")
            if prefix:
                shot = Path(f"{prefix}-ui.png")
                shot.parent.mkdir(parents=True, exist_ok=True)
                driver.save_screenshot(str(shot))
                evidence["screenshot"] = str(shot)
            hits = [r for r in rows if record_matches(r, subject, bool(c.match_version))]
            keep = int(subject.extra.get("max_records", 5))
            evidence["matched_rows"] = [h[:300] for h in hits[:keep]]
            return CheckResult(self.name, bool(hits), f"{len(hits)}/{len(rows)} UI rows match",
                               evidence=evidence)
        except Exception as exc:
            return CheckResult(self.name, None, error=f"{type(exc).__name__}: {exc}", evidence=evidence)
        finally:
            driver.quit()


def build_checks(svm_cfg) -> list:
    checks = []
    if svm_cfg.api.enabled:
        checks.append(SvmApiCheck(svm_cfg.api))
    if svm_cfg.ui.enabled:
        checks.append(SvmUiCheck(svm_cfg.ui))
    return checks


def evaluate(results: list[CheckResult], expect_present: bool, require: str = "all") -> tuple[bool, str]:
    """Diamond node: ADD TEST (expect present) / DELETE TEST (expect absent)."""
    if not results:
        return False, "no SVM checks enabled"
    if any(r.found is None for r in results):
        errs = "; ".join(f"{r.name}: {r.error}" for r in results if r.found is None)
        return False, f"check error ({errs})"

    def good(r: CheckResult) -> bool:
        return bool(r.found and r.fields_ok is not False) if expect_present else not r.found

    verdicts = [good(r) for r in results]
    ok = all(verdicts) if require == "all" else any(verdicts)
    want = "present" if expect_present else "absent"
    parts = []
    for r in results:
        part = f"{r.name}={'found' if r.found else 'not found'}"
        if r.field_issues:
            part += " [" + "; ".join(r.field_issues) + "]"
        parts.append(part)
    return ok, f"expected {want}; " + ", ".join(parts)
