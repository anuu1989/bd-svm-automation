"""Black Duck REST client. Every URL, path and media type comes from config."""
from __future__ import annotations

import logging
from typing import Any, Iterator
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

MANUAL_MATCH_TYPE = "MANUAL_BOM_COMPONENT"


class BlackDuckError(Exception):
    pass


def _last_segment(href: str) -> str:
    return urlparse(href).path.rstrip("/").rsplit("/", 1)[-1]


def href_of(item: dict) -> str:
    return (item.get("_meta") or {}).get("href", "")


class BlackDuckClient:
    def __init__(self, cfg, session: requests.Session | None = None):
        self.cfg = cfg
        self.base = cfg.base_url.rstrip("/")
        self.paths = cfg.paths
        self.media = cfg.media_types
        self.http = session or requests.Session()
        self.http.verify = bool(cfg.verify_ssl)
        self._bearer: str | None = None

    # ------------------------------------------------------------------ http
    def url(self, path_or_url: str, **fmt: str) -> str:
        path = path_or_url.format(**fmt) if fmt else path_or_url
        if path.startswith(("http://", "https://")):
            return path
        return self.base + "/" + path.lstrip("/")

    def authenticate(self) -> None:
        resp = self.http.post(
            self.url(self.paths.authenticate),
            headers={
                "Authorization": f"token {self.cfg.api_token}",
                "Accept": self.media.authenticate,
            },
            timeout=self.cfg.timeout_seconds,
        )
        if resp.status_code >= 400:
            raise BlackDuckError(f"authentication failed: HTTP {resp.status_code} {resp.text[:200]}")
        self._bearer = resp.json()["bearerToken"]

    def _request(self, method: str, url: str, *, accept: str | None = None,
                 content_type: str | None = None, retry: bool = True, **kw) -> requests.Response:
        if not self._bearer:
            self.authenticate()
        headers = {"Authorization": f"Bearer {self._bearer}", "Accept": accept or self.media.default}
        if content_type:
            headers["Content-Type"] = content_type
        resp = self.http.request(method, url, headers=headers, timeout=self.cfg.timeout_seconds, **kw)
        if resp.status_code == 401 and retry:
            self._bearer = None
            return self._request(method, url, accept=accept, content_type=content_type, retry=False, **kw)
        if resp.status_code >= 400:
            raise BlackDuckError(f"{method} {url} -> HTTP {resp.status_code}: {resp.text[:300]}")
        return resp

    def _paginate(self, url: str, params: dict | None = None, accept: str | None = None) -> Iterator[dict]:
        offset, limit = 0, int(self.cfg.page_size)
        while True:
            page = self._request(
                "GET", url, accept=accept, params={**(params or {}), "offset": offset, "limit": limit}
            ).json()
            items = page.get("items", [])
            yield from items
            offset += limit
            if not items or offset >= page.get("totalCount", 0):
                return

    # --------------------------------------------------------------- project
    def get_project_version(self) -> dict[str, str]:
        name, vname = self.cfg.project_name, self.cfg.project_version
        projects = self._paginate(self.url(self.paths.projects), {"q": f"name:{name}"})
        project = next((p for p in projects if p.get("name") == name), None)
        if not project:
            raise BlackDuckError(f"project '{name}' not found")
        pid = _last_segment(href_of(project))
        versions = self._paginate(self.url(self.paths.project_versions, project_id=pid),
                                  {"q": f"versionName:{vname}"})
        version = next((v for v in versions if v.get("versionName") == vname), None)
        if not version:
            raise BlackDuckError(f"version '{vname}' not found in project '{name}'")
        return {"project_id": pid, "version_id": _last_segment(href_of(version)),
                "version_href": href_of(version)}

    # ------------------------------------------------------------ components
    def resolve_component_version(self, name: str, version: str) -> dict[str, str] | None:
        query = self.cfg.search_query.format(name=name)
        comps = list(self._paginate(self.url(self.paths.components_search), {"q": query}))
        comps.sort(key=lambda c: c.get("name", "").lower() != name.lower())
        for comp in comps[:5]:
            vurl = self.url(self.paths.component_versions, component_href=href_of(comp))
            for cv in self._paginate(vurl):
                if cv.get("versionName") == version:
                    return {"name": comp.get("name", name), "version": version,
                            "component_version_href": href_of(cv)}
        return None

    def list_vulnerabilities(self, component_version_href: str) -> list[dict]:
        url = self.url(self.paths.component_version_vulnerabilities,
                       component_version_href=component_version_href)
        return list(self._paginate(url, accept=self.media.vulnerability))

    def find_vulnerable_component(self, bom: dict[str, str]) -> dict[str, Any]:
        """Walk configured candidates; return the first one that has a
        vulnerability and is not already in the target BOM."""
        in_bom = {i.get("componentVersion") for i in self.list_bom_components(bom)}
        allowed = {s.upper() for s in (self.cfg.vulnerability_severities or [])}
        for cand in self.cfg.candidates:
            resolved = self.resolve_component_version(cand["name"], cand["version"])
            if not resolved:
                log.info("candidate %s %s not found in Black Duck KB", cand["name"], cand["version"])
                continue
            if resolved["component_version_href"] in in_bom:
                log.info("candidate %s %s already in BOM - skipping", cand["name"], cand["version"])
                continue
            vulns = [v for v in self.list_vulnerabilities(resolved["component_version_href"])
                     if not allowed or str(v.get("severity", "")).upper() in allowed]
            if vulns:
                resolved["vuln_id"] = vulns[0]["name"]
                resolved["vuln_count"] = len(vulns)
                return resolved
        raise BlackDuckError("no vulnerable, not-yet-in-BOM candidate component found; "
                             "extend blackduck.candidates")

    # ------------------------------------------------------------------- BOM
    def list_bom_components(self, bom: dict[str, str]) -> list[dict]:
        url = self.url(self.paths.bom_components, project_id=bom["project_id"], version_id=bom["version_id"])
        return list(self._paginate(url))

    def find_bom_item(self, bom: dict[str, str], component_version_href: str) -> dict | None:
        return next((i for i in self.list_bom_components(bom)
                     if i.get("componentVersion") == component_version_href), None)

    def add_component(self, bom: dict[str, str], component_version_href: str) -> dict:
        url = self.url(self.paths.bom_components, project_id=bom["project_id"], version_id=bom["version_id"])
        self._request("POST", url, content_type=self.media.bom, json={"component": component_version_href})
        item = self.find_bom_item(bom, component_version_href)
        if not item:
            raise BlackDuckError("component POST succeeded but item not visible in BOM")
        return item

    def delete_component(self, bom: dict[str, str], component_version_href: str) -> bool:
        """Delete our manually-added item. Returns False if nothing to delete."""
        item = self.find_bom_item(bom, component_version_href)
        if not item:
            return False
        match_types = item.get("matchTypes")
        if self.cfg.require_manual_match_type and match_types is not None \
                and MANUAL_MATCH_TYPE not in match_types:
            raise BlackDuckError(
                f"refusing to delete non-manual BOM item (matchTypes={match_types})")
        self._request("DELETE", href_of(item))
        return True

    # ------------------------------------------------------- assessment view
    def vulnerability_assessment(self, bom: dict[str, str], component_version_href: str) -> list[str]:
        """Vulnerability ids Black Duck reports for this component in the BOM."""
        url = self.url(self.paths.vulnerable_bom_components,
                       project_id=bom["project_id"], version_id=bom["version_id"])
        out = []
        for item in self._paginate(url):
            if item.get("componentVersion") == component_version_href:
                vid = (item.get("vulnerabilityWithRemediation") or {}).get("vulnerabilityName")
                if vid:
                    out.append(vid)
        return out

    # =====================================================================
    # Extended API surface (used by `python -m bd_svm bd ...` / make bd-*)
    # =====================================================================
    @staticmethod
    def _cv_ids(component_version_href: str) -> dict[str, str]:
        """.../components/{cid}/versions/{cvid} -> ids."""
        parts = urlparse(component_version_href).path.strip("/").split("/")
        try:
            i = parts.index("components")
            return {"component_id": parts[i + 1], "component_version_id": parts[i + 3]}
        except (ValueError, IndexError):
            raise BlackDuckError(f"not a component version href: {component_version_href}")

    @staticmethod
    def _strip_meta(body: dict) -> dict:
        return {k: v for k, v in body.items() if k != "_meta"}

    def raw(self, method: str, path: str, *, params: dict | None = None, body: Any = None,
            accept: str | None = None, content_type: str | None = None) -> Any:
        """Escape hatch: call any Black Duck endpoint (path or full URL)."""
        kw: dict = {"params": params} if params else {}
        if body is not None:
            kw["json"] = body
            content_type = content_type or "application/json"
        resp = self._request(method.upper(), self.url(path), accept=accept,
                             content_type=content_type, **kw)
        if not resp.content:
            return {"status": resp.status_code}
        try:
            return resp.json()
        except ValueError:
            return {"status": resp.status_code, "text": resp.text}

    # ---- server / user ------------------------------------------------------
    def whoami(self) -> dict:
        return self._request("GET", self.url(self.paths.current_user)).json()

    def server_version(self) -> dict:
        return self._request("GET", self.url(self.paths.current_version)).json()

    # ---- projects & versions ---------------------------------------------------
    def list_projects(self, name: str | None = None) -> list[dict]:
        return list(self._paginate(self.url(self.paths.projects), {"q": f"name:{name}"} if name else None))

    def create_project(self, name: str, description: str = "") -> dict:
        body = {"name": name, "description": description, "projectLevelAdjustments": True}
        resp = self._request("POST", self.url(self.paths.projects), json=body,
                             content_type="application/json")
        return {"name": name, "href": resp.headers.get("Location", "")}

    def delete_project(self, project_id: str) -> None:
        self._request("DELETE", self.url(self.paths.project, project_id=project_id))

    def list_versions(self, project_id: str) -> list[dict]:
        return list(self._paginate(self.url(self.paths.project_versions, project_id=project_id)))

    def create_version(self, project_id: str, version_name: str, phase: str = "DEVELOPMENT",
                       distribution: str = "EXTERNAL") -> dict:
        body = {"versionName": version_name, "phase": phase, "distribution": distribution}
        resp = self._request("POST", self.url(self.paths.project_versions, project_id=project_id),
                             json=body, content_type="application/json")
        return {"versionName": version_name, "href": resp.headers.get("Location", "")}

    def delete_version(self, project_id: str, version_id: str) -> None:
        self._request("DELETE", self.url(self.paths.project_version,
                                         project_id=project_id, version_id=version_id))

    def policy_status(self, bom: dict[str, str]) -> dict:
        return self._request("GET", self.url(self.paths.policy_status, **self._bom_ids(bom))).json()

    def risk_profile(self, bom: dict[str, str]) -> dict:
        return self._request("GET", self.url(self.paths.risk_profile, **self._bom_ids(bom))).json()

    def bom_status(self, bom: dict[str, str]) -> dict:
        return self._request("GET", self.url(self.paths.bom_status, **self._bom_ids(bom))).json()

    @staticmethod
    def _bom_ids(bom: dict[str, str]) -> dict[str, str]:
        return {"project_id": bom["project_id"], "version_id": bom["version_id"]}

    # ---- component knowledge base ------------------------------------------------
    def search_components(self, name: str) -> list[dict]:
        return list(self._paginate(self.url(self.paths.components_search),
                                   {"q": self.cfg.search_query.format(name=name)}))

    def list_component_versions(self, component_href: str) -> list[dict]:
        return list(self._paginate(self.url(self.paths.component_versions, component_href=component_href)))

    def get_vulnerability(self, vuln_id: str) -> dict:
        return self._request("GET", self.url(self.paths.vulnerability, vuln_id=vuln_id),
                             accept=self.media.vulnerability).json()

    def upgrade_guidance(self, component_version_href: str) -> dict:
        return self._request("GET", self.url(self.paths.upgrade_guidance,
                                             component_version_href=component_version_href)).json()

    # ---- BOM ---------------------------------------------------------------------
    def list_vulnerable_items(self, bom: dict[str, str]) -> list[dict]:
        return list(self._paginate(self.url(self.paths.vulnerable_bom_components, **self._bom_ids(bom))))

    def update_bom_item(self, bom: dict[str, str], component_version_href: str, changes: dict) -> dict:
        """GET-modify-PUT a BOM item, e.g. {"ignored": True} / {"reviewStatus": "REVIEWED"}."""
        item = self.find_bom_item(bom, component_version_href)
        if not item:
            raise BlackDuckError("component not in BOM")
        body = {**self._strip_meta(item), **changes}
        self._request("PUT", href_of(item), json=body, content_type=self.media.bom)
        return self.find_bom_item(bom, component_version_href) or body

    def set_ignored(self, bom: dict[str, str], component_version_href: str, ignored: bool) -> dict:
        return self.update_bom_item(bom, component_version_href, {"ignored": ignored})

    def update_remediation(self, bom: dict[str, str], component_version_href: str,
                           vuln_id: str, status: str, comment: str = "") -> dict:
        """Set remediation status (the Black Duck 'assessment') for one vulnerability."""
        link = None
        for item in self.list_vulnerable_items(bom):
            v = item.get("vulnerabilityWithRemediation") or {}
            if item.get("componentVersion") == component_version_href and v.get("vulnerabilityName") == vuln_id:
                for lk in (item.get("_meta") or {}).get("links", []):
                    if lk.get("rel") == "remediation":
                        link = lk["href"]
                break
        url = link or self.url(self.paths.vulnerability_remediation, **self._bom_ids(bom),
                               **self._cv_ids(component_version_href), vuln_id=vuln_id)
        body = {"remediationStatus": status, "comment": comment}
        self._request("PUT", url, json=body, content_type="application/json")
        return {"vuln_id": vuln_id, **body}

    # ---- scans -------------------------------------------------------------------
    def list_code_locations(self) -> list[dict]:
        return list(self._paginate(self.url(self.paths.code_locations)))

    def delete_code_location(self, href: str) -> None:
        self._request("DELETE", href)
