"""Markdown report of test runs."""
from __future__ import annotations

from datetime import datetime


def _ts(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"


def render_markdown(runs: list[dict]) -> str:
    passed = sum(r["status"] == "PASSED" for r in runs)
    failed = sum(r["status"] == "FAILED" for r in runs)
    lines = ["# Black Duck → SVM sync test report", "",
             f"Runs: {len(runs)}  |  passed: {passed}  |  failed: {failed}  |  "
             f"active: {len(runs) - passed - failed}", "",
             "| Run | Status | Component | Vulnerability | ADD test | DELETE test | Started |",
             "|---|---|---|---|---|---|---|"]

    def verdict(test):
        return "-" if not test else ("PASS" if test["passed"] else "FAIL")

    for r in runs:
        d = r["data"]
        c = d.get("component", {})
        lines.append(f"| {r['run_id']} | {r['status']} | {c.get('name', '?')} {c.get('version', '')} | "
                     f"{c.get('vuln_id', '?')} | {verdict(d.get('add_test'))} | "
                     f"{verdict(d.get('delete_test'))} | {_ts(r['created_at'])} |")
    failures = [r for r in runs if r["status"] == "FAILED"]
    if failures:
        lines += ["", "## Failures", ""]
        for r in failures:
            lines.append(f"- **{r['run_id']}**: {r['data'].get('failure', 'unknown')}")
            if r["data"].get("cleanup_error"):
                lines.append(f"  - ⚠ manual cleanup needed: {r['data']['cleanup_error']}")
    return "\n".join(lines) + "\n"
