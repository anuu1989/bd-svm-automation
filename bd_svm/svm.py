"""SVM verification: API check and (optional) Selenium UI check."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import requests

log = logging.getLogger(__name__)


@dataclass
class CheckResult:
    name: str            # "api" | "ui"
    found: bool | None   # None = check errored / skipped
    detail: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "found": self.found, "detail": self.detail, "error": self.error}


@dataclass
class Subject:
    """What we look for in SVM."""
    component_name: str
    component_version: str
    vuln_id: str
    project_name: str = ""
    extra: dict = field(default_factory=dict)

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


class SvmApiCheck:
    name = "api"

    def __init__(self, cfg):
        self.cfg = cfg

    def check(self, subject: Subject) -> CheckResult:
        c, f = self.cfg, subject.fmt()
        headers = {"Accept": "application/json"}
        if c.token:
            headers[c.auth_header] = f"{c.auth_scheme} {c.token}".strip()
        url = c.base_url.rstrip("/") + "/" + c.path.format(**f).lstrip("/")
        params = {k: str(v).format(**f) for k, v in (c.params or {}).items()}
        try:
            resp = requests.request(c.method, url, headers=headers, params=params,
                                    verify=bool(c.verify_ssl), timeout=c.timeout_seconds)
            resp.raise_for_status()
            records = extract_records(resp.json(), c.list_key or "")
        except Exception as exc:  # network / HTTP / JSON
            return CheckResult(self.name, None, error=f"{type(exc).__name__}: {exc}")
        hits = [r for r in records if record_matches(r, subject, bool(c.match_version))]
        return CheckResult(self.name, bool(hits), f"{len(hits)}/{len(records)} records match")


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
        try:
            if c.login.url:
                driver.get(c.login.url)
                driver.find_element(By.CSS_SELECTOR, c.login.username_selector).send_keys(c.login.username)
                driver.find_element(By.CSS_SELECTOR, c.login.password_selector).send_keys(c.login.password)
                driver.find_element(By.CSS_SELECTOR, c.login.submit_selector).click()
            url = c.search_url.format(ui_url=c.url.rstrip("/"), **subject.fmt())
            driver.get(url)
            WebDriverWait(driver, c.wait_seconds).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, c.wait_selector)))
            if c.row_selector:
                rows = [r.text for r in driver.find_elements(By.CSS_SELECTOR, c.row_selector)]
            else:
                rows = [driver.find_element(By.TAG_NAME, "body").text]
            hits = [r for r in rows if record_matches(r, subject, bool(c.match_version))]
            return CheckResult(self.name, bool(hits), f"{len(hits)}/{len(rows)} UI rows match")
        except Exception as exc:
            return CheckResult(self.name, None, error=f"{type(exc).__name__}: {exc}")
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
    verdicts = [r.found == expect_present for r in results]
    ok = all(verdicts) if require == "all" else any(verdicts)
    want = "present" if expect_present else "absent"
    return ok, f"expected {want}; " + ", ".join(f"{r.name}={'found' if r.found else 'not found'}" for r in results)
