"""Webhook notifications (Slack / Teams / generic JSON). Never raises."""
from __future__ import annotations

import logging

import requests

log = logging.getLogger(__name__)


def summarize(run: dict) -> str:
    data = run["data"]
    lines = [f"Black Duck→SVM sync test {run['run_id']}: {run['status']}"]
    if data.get("failure"):
        lines.append(f"Reason: {data['failure']}")
    for item in data.get("items", []):
        t = item.get("tests", {})
        add, dele = t.get("add"), t.get("delete")
        lat = f", add latency {add['latency_s']}s" if add and add.get("latency_s") is not None else ""
        lines.append(f"- {item['name']} {item['version']} [{item.get('scenario', 'standard')}] "
                     f"add={'PASS' if add and add['passed'] else 'FAIL' if add else '-'} "
                     f"delete={'PASS' if dele and dele['passed'] else 'FAIL' if dele else '-'}{lat}")
    if data.get("cleanup_error"):
        lines.append(f"MANUAL CLEANUP NEEDED: {data['cleanup_error']}")
    return "\n".join(lines)


class Notifier:
    def __init__(self, cfg):
        self.cfg = cfg

    @property
    def enabled(self) -> bool:
        return bool(self.cfg and self.cfg.webhook_url)

    def notify(self, event: str, run: dict) -> bool:
        """event: passed | failed | cleanup_failed | test"""
        if not self.enabled or (event != "test" and event not in (self.cfg.on or [])):
            return False
        text = f"{self.cfg.prefix or ''}{summarize(run)}"
        fmt = self.cfg.format
        if fmt == "teams":
            body = {"@type": "MessageCard", "@context": "http://schema.org/extensions",
                    "summary": f"{run['run_id']} {run['status']}", "text": text.replace("\n", "<br>")}
        elif fmt == "generic":
            body = {"event": event, "run_id": run["run_id"], "status": run["status"],
                    "message": text, "data": run["data"].get("items", [])}
        else:
            body = {"text": text}
        try:
            requests.post(self.cfg.webhook_url, json=body, timeout=15).raise_for_status()
            return True
        except Exception as exc:
            log.warning("notification failed: %s", exc)
            return False
