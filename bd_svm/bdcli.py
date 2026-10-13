"""Ad-hoc Black Duck / SVM / pipeline commands (`python -m bd_svm bd <cmd>`).

Read commands print JSON. Commands that change Black Duck require --yes so a
typo in a make recipe can't mutate or delete anything by accident.
"""
from __future__ import annotations

import json
import sys

from .blackduck import BlackDuckClient, BlackDuckError, href_of
from .pipeline import PipelineTrigger
from .svm import Subject, build_checks, evaluate


def _out(obj) -> int:
    print(json.dumps(obj, indent=2, default=str))
    return 0


def _need_yes(args) -> bool:
    if not getattr(args, "yes", False):
        print("refusing: this changes Black Duck. Re-run with --yes (make: YES=1).", file=sys.stderr)
        return False
    return True


def _client(cfg, args):
    if not (cfg.blackduck.base_url and cfg.blackduck.api_token):
        raise BlackDuckError("set BLACKDUCK_URL and BLACKDUCK_API_TOKEN (see .env.example)")
    if getattr(args, "project", None):
        cfg.blackduck["project_name"] = args.project
    if getattr(args, "version", None):
        cfg.blackduck["project_version"] = args.version
    return BlackDuckClient(cfg.blackduck)


def _bom(bd):
    return bd.get_project_version()


def _cv(bd, args) -> str:
    """Resolve --name/--component-version to a component version href."""
    if getattr(args, "href", None):
        return args.href
    if not (args.name and args.component_version):
        raise BlackDuckError("give --name and --component-version (or --href)")
    r = bd.resolve_component_version(args.name, args.component_version)
    if not r:
        raise BlackDuckError(f"{args.name} {args.component_version} not found in Black Duck KB")
    return r["component_version_href"]


def _slim(items, *keys):
    return [{k: i.get(k) for k in keys} | {"href": href_of(i)} for i in items]


# ------------------------------------------------------------------ handlers
def h_whoami(cfg, a):
    bd = _client(cfg, a)
    return _out({"user": bd.whoami().get("userName"), "server": bd.server_version()})


def h_projects(cfg, a):
    return _out(_slim(_client(cfg, a).list_projects(a.name), "name", "projectTier", "createdAt"))


def h_versions(cfg, a):
    bd = _client(cfg, a)
    pid = _bom(bd)["project_id"]
    return _out(_slim(bd.list_versions(pid), "versionName", "phase", "distribution", "createdAt"))


def h_bom(cfg, a):
    bd = _client(cfg, a)
    items = bd.list_bom_components(_bom(bd))
    return _out([{"component": i.get("componentName"), "version": i.get("componentVersionName"),
                  "ignored": i.get("ignored"), "matchTypes": i.get("matchTypes"),
                  "componentVersion": i.get("componentVersion")} for i in items])


def h_vulns(cfg, a):
    bd = _client(cfg, a)
    out = []
    for i in bd.list_vulnerable_items(_bom(bd)):
        v = i.get("vulnerabilityWithRemediation") or {}
        out.append({"component": i.get("componentName"), "version": i.get("componentVersionName"),
                    "vuln": v.get("vulnerabilityName"), "severity": v.get("severity"),
                    "remediation": v.get("remediationStatus")})
    return _out(out)


def h_search(cfg, a):
    bd = _client(cfg, a)
    comps = bd.search_components(a.name)
    if a.versions:
        return _out([{"name": c.get("name"), "href": href_of(c),
                      "versions": [v.get("versionName") for v in bd.list_component_versions(href_of(c))]}
                     for c in comps[:5]])
    return _out(_slim(comps, "name"))


def h_component_vulns(cfg, a):
    bd = _client(cfg, a)
    vulns = bd.list_vulnerabilities(_cv(bd, a))
    return _out([{"name": v.get("name"), "severity": v.get("severity"),
                  "score": (v.get("cvss3") or v.get("cvss2") or {}).get("baseScore")} for v in vulns])


def h_vuln(cfg, a):
    return _out(_client(cfg, a).get_vulnerability(a.vuln_id))


def h_upgrade(cfg, a):
    bd = _client(cfg, a)
    return _out(bd.upgrade_guidance(_cv(bd, a)))


def h_policy(cfg, a):
    bd = _client(cfg, a)
    return _out(bd.policy_status(_bom(bd)))


def h_risk(cfg, a):
    bd = _client(cfg, a)
    return _out(bd.risk_profile(_bom(bd)))


def h_bomstatus(cfg, a):
    bd = _client(cfg, a)
    return _out(bd.bom_status(_bom(bd)))


def h_codelocations(cfg, a):
    return _out(_slim(_client(cfg, a).list_code_locations(), "name", "createdAt", "updatedAt"))


def h_add(cfg, a):
    if not _need_yes(a):
        return 2
    bd = _client(cfg, a)
    item = bd.add_component(_bom(bd), _cv(bd, a))
    return _out({"added": item.get("componentName"), "href": href_of(item)})


def h_delete(cfg, a):
    if not _need_yes(a):
        return 2
    bd = _client(cfg, a)
    return _out({"deleted": bd.delete_component(_bom(bd), _cv(bd, a))})


def h_ignore(cfg, a):
    if not _need_yes(a):
        return 2
    bd = _client(cfg, a)
    bd.set_ignored(_bom(bd), _cv(bd, a), not a.undo)
    return _out({"ignored": not a.undo})


def h_remediate(cfg, a):
    if not _need_yes(a):
        return 2
    bd = _client(cfg, a)
    return _out(bd.update_remediation(_bom(bd), _cv(bd, a), a.vuln_id, a.status, a.comment))


def h_create_project(cfg, a):
    if not _need_yes(a):
        return 2
    return _out(_client(cfg, a).create_project(a.name, a.description))


def h_create_version(cfg, a):
    if not _need_yes(a):
        return 2
    bd = _client(cfg, a)
    pid = _bom_project_id(bd, a.project_name)
    return _out(bd.create_version(pid, a.version_name, a.phase, a.distribution))


def _bom_project_id(bd, name):
    for p in bd.list_projects(name):
        if p.get("name") == name:
            return href_of(p).rstrip("/").rsplit("/", 1)[-1]
    raise BlackDuckError(f"project '{name}' not found")


def h_delete_version(cfg, a):
    if not _need_yes(a):
        return 2
    bd = _client(cfg, a)
    b = _bom(bd)
    bd.delete_version(b["project_id"], b["version_id"])
    return _out({"deleted_version": cfg.blackduck.project_version})


def h_delete_project(cfg, a):
    if not _need_yes(a):
        return 2
    bd = _client(cfg, a)
    pid = _bom_project_id(bd, a.name)
    bd.delete_project(pid)
    return _out({"deleted_project": a.name})


def h_api(cfg, a):
    bd = _client(cfg, a)
    if a.method.upper() != "GET" and not _need_yes(a):
        return 2
    body = json.loads(a.data) if a.data else None
    return _out(bd.raw(a.method, a.path, body=body))


def h_svm_check(cfg, a):
    subject = Subject(a.name, a.component_version, a.vuln_id or "", cfg.blackduck.project_name)
    results = [c.check(subject) for c in build_checks(cfg.svm)]
    ok, detail = evaluate(results, not a.expect_absent, cfg.svm.require)
    _out({"passed": ok, "detail": detail, "checks": [r.as_dict() for r in results]})
    return 0 if ok else 1


def h_pipeline(cfg, a):
    return _out(PipelineTrigger(cfg.pipeline).trigger(a.run_id))


# ------------------------------------------------------------------ parsers
def register(sub) -> None:
    def common(p):
        p.add_argument("--project", help="override blackduck.project_name")
        p.add_argument("--version", help="override blackduck.project_version")

    def comp(p):
        p.add_argument("--name", help="component name, e.g. log4j-core")
        p.add_argument("--component-version", help="component version, e.g. 2.14.1")
        p.add_argument("--href", help="component version URL (alternative to name+version)")

    def yes(p):
        p.add_argument("--yes", action="store_true", help="confirm a change to Black Duck")

    bd = sub.add_parser("bd", help="ad-hoc Black Duck API commands").add_subparsers(
        dest="bd_command", required=True)
    # read-only
    add_ = lambda *a, **k: _add_to(bd, common, comp, yes, *a, **k)  # noqa: E731
    add_("whoami", h_whoami, "current user + server version")
    p = add_("projects", h_projects, "list projects"); p.add_argument("--name")
    add_("versions", h_versions, "list versions of the configured project")
    add_("bom", h_bom, "list BOM components of the configured version")
    add_("vulns", h_vulns, "list vulnerable BOM components")
    p = add_("search", h_search, "search KB components by name"); p.add_argument("name")
    p.add_argument("--versions", action="store_true", help="include versions")
    add_("component-vulns", h_component_vulns, "vulnerabilities of a component version", comp_=True)
    p = add_("vuln", h_vuln, "vulnerability details (CVE/BDSA id)"); p.add_argument("vuln_id")
    add_("upgrade-guidance", h_upgrade, "upgrade guidance for a component version", comp_=True)
    add_("policy", h_policy, "policy status of the version")
    add_("risk", h_risk, "risk profile of the version")
    add_("bom-status", h_bomstatus, "BOM processing status")
    add_("codelocations", h_codelocations, "list code locations (scans)")
    # mutating
    add_("add", h_add, "add a component to the BOM", comp_=True, yes_=True)
    add_("delete", h_delete, "delete a component from the BOM", comp_=True, yes_=True)
    p = add_("ignore", h_ignore, "ignore/unignore a BOM component", comp_=True, yes_=True)
    p.add_argument("--undo", action="store_true", help="un-ignore")
    p = add_("remediate", h_remediate, "set remediation status (assessment)", comp_=True, yes_=True)
    p.add_argument("--vuln-id", required=True)
    p.add_argument("--status", default="IGNORED")
    p.add_argument("--comment", default="")
    p = add_("create-project", h_create_project, "create a project", yes_=True)
    p.add_argument("name"); p.add_argument("--description", default="")
    p = add_("create-version", h_create_version, "create a project version", yes_=True)
    p.add_argument("project_name"); p.add_argument("version_name")
    p.add_argument("--phase", default="DEVELOPMENT"); p.add_argument("--distribution", default="EXTERNAL")
    add_("delete-version", h_delete_version, "delete configured project version", yes_=True)
    p = add_("delete-project", h_delete_project, "delete a project", yes_=True); p.add_argument("name")
    # escape hatch
    p = add_("api", h_api, "call any endpoint: api GET /api/...", yes_=True)
    p.add_argument("method"); p.add_argument("path"); p.add_argument("--data", help="JSON body")

    # svm / pipeline (top-level)
    p = sub.add_parser("svm-check", help="run the SVM API/UI checks for one component")
    p.add_argument("--name", required=True); p.add_argument("--component-version", required=True)
    p.add_argument("--vuln-id", default="")
    p.add_argument("--expect-absent", action="store_true", help="pass when NOT found (delete test)")
    p.set_defaults(fn=h_svm_check)
    p = sub.add_parser("pipeline-trigger", help="trigger the verification pipeline now")
    p.add_argument("--run-id", default="manual")
    p.set_defaults(fn=h_pipeline)


def _add_to(group, common, comp, yes, name, fn, help_, *, comp_=False, yes_=False):
    p = group.add_parser(name, help=help_)
    common(p)
    if comp_:
        comp(p)
    if yes_:
        yes(p)
    p.set_defaults(fn=fn)
    return p
