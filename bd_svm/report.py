"""Reports: Markdown, JUnit XML (CI test tabs) and a JSON summary."""
from __future__ import annotations

import json
import math
import xml.etree.ElementTree as ET
from datetime import datetime


def _ts(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"


def _lat(test) -> str:
    return _fmt_s(test["latency_s"]) if test and test.get("latency_s") is not None else "-"


def _verdict(test) -> str:
    return "-" if not test else ("PASS" if test["passed"] else "FAIL")


def _latencies(runs: list[dict], test: str) -> list[int]:
    return [i["tests"][test]["latency_s"] for r in runs for i in r["data"].get("items", [])
            if i.get("tests", {}).get(test, {}).get("latency_s") is not None]


def latency_stats(values: list[int]) -> dict:
    if not values:
        return {}
    vals = sorted(values)
    p95 = vals[min(len(vals) - 1, math.ceil(0.95 * len(vals)) - 1)]
    return {"count": len(vals), "min": vals[0], "avg": round(sum(vals) / len(vals)),
            "p95": p95, "max": vals[-1]}


def _fmt_s(seconds) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"


def summary(runs: list[dict]) -> dict:
    return {
        "runs": len(runs),
        "passed": sum(r["status"] == "PASSED" for r in runs),
        "failed": sum(r["status"] == "FAILED" for r in runs),
        "active": sum(r["status"] == "ACTIVE" for r in runs),
        "sync_latency_seconds": {"add": latency_stats(_latencies(runs, "add")),
                                 "delete": latency_stats(_latencies(runs, "delete"))},
        "runs_detail": [{
            "run_id": r["run_id"], "status": r["status"], "phase": r["phase"],
            "failure": r["data"].get("failure"), "cleanup_error": r["data"].get("cleanup_error"),
            "items": [{"name": i["name"], "version": i["version"], "scenario": i.get("scenario"),
                       "vuln_id": i.get("vuln_id"),
                       "add": {k: i.get("tests", {}).get("add", {}).get(k) for k in ("passed", "latency_s", "detail")},
                       "delete": {k: i.get("tests", {}).get("delete", {}).get(k)
                                  for k in ("passed", "latency_s", "detail")}} for i in r["data"].get("items", [])],
        } for r in runs],
    }


def render_json(runs: list[dict]) -> str:
    return json.dumps(summary(runs), indent=2)


def render_markdown(runs: list[dict]) -> str:
    s = summary(runs)
    lines = ["# Black Duck → SVM sync test report", "",
             f"Runs: {s['runs']}  |  passed: {s['passed']}  |  failed: {s['failed']}  |  "
             f"active: {s['active']}", ""]
    stats = s["sync_latency_seconds"]
    if stats["add"] or stats["delete"]:
        lines += ["## Sync latency (Black Duck change → visible in SVM)", "",
                  "| Direction | Samples | Min | Avg | p95 | Max |", "|---|---|---|---|---|---|"]
        for name, label in (("add", "Add"), ("delete", "Delete")):
            st = stats[name]
            if st:
                lines.append(f"| {label} | {st['count']} | {_fmt_s(st['min'])} | {_fmt_s(st['avg'])} | "
                             f"{_fmt_s(st['p95'])} | {_fmt_s(st['max'])} |")
        lines.append("")
    lines += ["## Runs", "", "| Run | Status | Items | Started |", "|---|---|---|---|"]
    for r in runs:
        names = ", ".join(i["name"] for i in r["data"].get("items", [])) or "?"
        lines.append(f"| {r['run_id']} | {r['status']} | {names} | {_ts(r['created_at'])} |")
    lines += ["", "## Items", "",
              "| Run | Component | Scenario | Vulnerability | ADD | add latency | DELETE | delete latency |",
              "|---|---|---|---|---|---|---|---|"]
    for r in runs:
        for i in r["data"].get("items", []):
            t = i.get("tests", {})
            lines.append(f"| {r['run_id']} | {i['name']} {i['version']} | {i.get('scenario', 'standard')} | "
                         f"{i.get('vuln_id') or '-'} | {_verdict(t.get('add'))} | {_lat(t.get('add'))} | "
                         f"{_verdict(t.get('delete'))} | {_lat(t.get('delete'))} |")
    failures = [r for r in runs if r["status"] == "FAILED"]
    if failures:
        lines += ["", "## Failures", ""]
        for r in failures:
            lines.append(f"- **{r['run_id']}**: {r['data'].get('failure', 'unknown')}")
            if r["data"].get("cleanup_error"):
                lines.append(f"  - ⚠ manual cleanup needed: {r['data']['cleanup_error']}")
    return "\n".join(lines) + "\n"


def render_junit(runs: list[dict]) -> str:
    """One testcase per run × item × (add|delete); failed runs also report setup errors."""
    suite = ET.Element("testsuite", name="bd-svm-sync")
    total = failures = 0
    for r in runs:
        if r["status"] == "ACTIVE":
            continue
        items = r["data"].get("items", [])
        if not items and r["status"] == "FAILED":
            items = [{"name": "setup", "version": "", "tests": {}}]
        for item in items:
            for test in ("add", "delete"):
                res = item.get("tests", {}).get(test)
                if res is None and r["status"] == "PASSED":
                    continue
                total += 1
                case = ET.SubElement(suite, "testcase", classname=r["run_id"],
                                     name=f"{item['name']} {item['version']} {test}".strip(),
                                     time=str(res.get("latency_s") or 0) if res else "0")
                if res is None or not res["passed"]:
                    failures += 1
                    msg = (res or {}).get("detail") or r["data"].get("failure") or "not executed"
                    ET.SubElement(case, "failure", message=msg[:300]).text = msg
    suite.set("tests", str(total))
    suite.set("failures", str(failures))
    return ET.tostring(ET.ElementTree(suite).getroot(), encoding="unicode", xml_declaration=False)
