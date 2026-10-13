"""Thin Black Duck REST client: GET / POST / PUT / DELETE plus the BOM helpers
the phases need. Every call is recorded for the HTML report.
"""
from __future__ import annotations

import time
from typing import Any, Iterator
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import settings
from utils import auth, bd_headers, reporter


class ApiError(Exception):
    def __init__(self, method: str, url: str, status: int, body: str):
        super().__init__(f"{method} {url} -> HTTP {status}: {body[:300]}")
        self.status = status


def last_segment(href: str) -> str:
    return urlparse(href).path.rstrip("/").rsplit("/", 1)[-1]


def _make_session() -> requests.Session:
    s = requests.Session()
    s.verify = settings.BD_VERIFY_SSL
    n = settings.BD_HTTP_RETRIES
    if n > 0:  # idempotent calls only; POST is never retried (could add twice)
        retry = Retry(total=n, connect=n, read=n, status=n, backoff_factor=1.0,
                      status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS"}),
                      respect_retry_after_header=True, raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


class BDClient:
    def __init__(self, session: requests.Session | None = None):
        self.http = session or _make_session()

    # ------------------------------------------------------------------ core
    @staticmethod
    def url(path: str, **path_vars: str) -> str:
        """`path` is a key of settings.PATHS, a path template, or a full URL."""
        template = settings.PATHS.get(path, path)
        if path_vars:
            template = template.format(**path_vars)
        if template.startswith(("http://", "https://")):
            return template
        return settings.BD_HOST + "/" + template.lstrip("/")

    def request(self, method: str, path: str, *, path_vars: dict | None = None, params: dict | None = None,
                json: Any = None, accept: str = "default", content: str | None = None,
                raise_for_status: bool = True) -> requests.Response:
        settings.require("BD_HOST")
        url = self.url(path, **(path_vars or {}))
        resp = None
        for attempt in (1, 2):               # 2nd attempt only after a 401 (expired token)
            headers = bd_headers.build(auth.get_token(force=attempt == 2), accept,
                                       content if json is not None else None)
            started = time.time()
            resp = self.http.request(method, url, headers=headers, params=params, json=json,
                                     timeout=settings.BD_TIMEOUT)
            reporter.record_call(method, resp.url, resp.status_code, json, resp.text,
                                 int((time.time() - started) * 1000))
            if resp.status_code != 401:
                break
        if raise_for_status and resp.status_code >= 400:
            raise ApiError(method, url, resp.status_code, resp.text)
        return resp

    def get(self, path: str, **kw) -> requests.Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> requests.Response:
        return self.request("POST", path, **kw)

    def put(self, path: str, **kw) -> requests.Response:
        return self.request("PUT", path, **kw)

    def delete(self, path: str, **kw) -> requests.Response:
        return self.request("DELETE", path, **kw)

    def paginate(self, path: str, *, path_vars: dict | None = None, params: dict | None = None,
                 accept: str = "default", page_size: int = 100) -> Iterator[dict]:
        offset = 0
        while True:
            page = self.get(path, path_vars=path_vars, accept=accept,
                            params={**(params or {}), "offset": offset, "limit": page_size}).json()
            items = page.get("items", [])
            yield from items
            offset += page_size
            if not items or offset >= page.get("totalCount", 0):
                return

    # --------------------------------------------------------- lookups (KB/project)
    def find_project(self, name: str) -> dict | None:
        return next((p for p in self.paginate("projects", params={"q": f"name:{name}"},
                                              accept="project") if p.get("name") == name), None)

    def find_version(self, project_id: str, version_name: str) -> dict | None:
        items = self.paginate("project_versions", path_vars={"project_id": project_id},
                              params={"q": f"versionName:{version_name}"})
        return next((v for v in items if v.get("versionName") == version_name), None)

    def find_kb_component(self, name: str, version: str) -> dict | None:
        """Returns {component_id, comp_ver_id, comp_ver_href} or None."""
        comps = list(self.paginate("components_search", params={"q": f"name:{name}"}))
        comps.sort(key=lambda c: c.get("name", "").lower() != name.lower())
        for comp in comps[:5]:
            cid = last_segment(comp["_meta"]["href"])
            for cv in self.paginate("component_versions", path_vars={"component_id": cid}):
                if cv.get("versionName") == version:
                    return {"component_id": cid, "comp_ver_id": last_segment(cv["_meta"]["href"]),
                            "comp_ver_href": cv["_meta"]["href"]}
        return None

    # ------------------------------------------------------------------ BOM helpers
    def bom_count(self, project_id: str, version_id: str) -> int:
        r = self.get("bom_components", path_vars={"project_id": project_id, "version_id": version_id},
                     params={"limit": 1})
        return int(r.json()["totalCount"])

    def find_bom_item(self, project_id: str, version_id: str, component_id: str, comp_ver_id: str) -> dict | None:
        suffix = f"/components/{component_id}/versions/{comp_ver_id}"
        items = self.paginate("bom_components", path_vars={"project_id": project_id, "version_id": version_id},
                              accept="bom")
        return next((i for i in items if str(i.get("componentVersion", "")).endswith(suffix)), None)

    def vulnerability_status(self, project_id: str, version_id: str, component_id: str,
                             comp_ver_id: str) -> dict[str, str]:
        """{vuln_id: remediationStatus} for one component in the BOM."""
        suffix = f"/components/{component_id}/versions/{comp_ver_id}"
        items = self.paginate("vulnerable_bom_components",
                              path_vars={"project_id": project_id, "version_id": version_id}, accept="bom")
        out = {}
        for item in items:
            if str(item.get("componentVersion", "")).endswith(suffix):
                v = item.get("vulnerabilityWithRemediation") or {}
                if v.get("vulnerabilityName"):
                    out[v["vulnerabilityName"]] = v.get("remediationStatus", "")
        return out

    def wait_for_vulnerability(self, ids: dict, vuln_id: str, timeout_s: int | None = None) -> dict[str, str]:
        """Black Duck computes vulnerabilities asynchronously after an add."""
        deadline = time.time() + (settings.BD_VULN_WAIT_SECONDS if timeout_s is None else timeout_s)
        while True:
            found = self.vulnerability_status(ids["project_id"], ids["version_id"],
                                              ids["component_id"], ids["comp_ver_id"])
            if vuln_id in found or time.time() >= deadline:
                return found
            time.sleep(5)

    def set_remediation(self, ids: dict, vuln_id: str, status: str, comment: str = "") -> requests.Response:
        return self.put("vulnerability_remediation", path_vars={**ids, "vuln_id": vuln_id},
                        json={"remediationStatus": status, "comment": comment}, content="default")
