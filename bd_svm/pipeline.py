"""Trigger the pipeline that syncs Black Duck -> SVM ("Trigger verification pipeline")."""
from __future__ import annotations

import logging
import subprocess
import time

import requests

log = logging.getLogger(__name__)


class PipelineError(Exception):
    pass


class PipelineTrigger:
    def __init__(self, cfg):
        self.cfg = cfg

    def trigger(self, run_id: str) -> dict:
        kind = self.cfg.type
        if kind == "none":
            log.warning("pipeline.type=none: not triggering anything")
            return {"type": "none"}
        if kind == "gitlab":
            return self._gitlab(run_id)
        if kind == "webhook":
            return self._webhook(run_id)
        if kind == "command":
            return self._command(run_id)
        raise PipelineError(f"unknown pipeline.type {kind}")

    # --------------------------------------------------------------- gitlab
    def _gitlab(self, run_id: str) -> dict:
        g = self.cfg.gitlab
        base = g.base_url.rstrip("/")
        form = {"token": g.trigger_token, "ref": g.ref}
        for k, v in (g.variables or {}).items():
            form[f"variables[{k}]"] = str(v)
        form["variables[BD_SVM_RUN_ID]"] = run_id
        r = requests.post(f"{base}/api/v4/projects/{g.project_id}/trigger/pipeline",
                          data=form, verify=bool(g.verify_ssl), timeout=60)
        if r.status_code >= 400:
            raise PipelineError(f"GitLab trigger failed: HTTP {r.status_code} {r.text[:200]}")
        pipe = r.json()
        info = {"type": "gitlab", "pipeline_id": pipe["id"], "web_url": pipe.get("web_url")}
        if self.cfg.wait_for_completion:
            info["status"] = self._gitlab_wait(g, base, pipe["id"])
            if info["status"] != "success":
                raise PipelineError(f"pipeline {pipe['id']} finished with status {info['status']}")
        return info

    def _gitlab_wait(self, g, base: str, pipeline_id: int) -> str:
        deadline = time.time() + self.cfg.timeout_seconds
        headers = {"PRIVATE-TOKEN": g.access_token} if g.access_token else {}
        while time.time() < deadline:
            r = requests.get(f"{base}/api/v4/projects/{g.project_id}/pipelines/{pipeline_id}",
                             headers=headers, verify=bool(g.verify_ssl), timeout=60)
            if r.status_code >= 400:
                raise PipelineError(f"cannot poll pipeline (set pipeline.gitlab.access_token): HTTP {r.status_code}")
            status = r.json()["status"]
            if status in ("success", "failed", "canceled", "skipped"):
                return status
            time.sleep(self.cfg.poll_seconds)
        raise PipelineError(f"pipeline {pipeline_id} did not finish within {self.cfg.timeout_seconds}s")

    # -------------------------------------------------------------- webhook
    def _webhook(self, run_id: str) -> dict:
        w = self.cfg.webhook
        body = {**(w.body or {}), "run_id": run_id}
        r = requests.request(w.method, w.url, json=body, headers=w.headers or {}, timeout=60)
        if r.status_code >= 400:
            raise PipelineError(f"webhook failed: HTTP {r.status_code} {r.text[:200]}")
        return {"type": "webhook", "http_status": r.status_code}

    # -------------------------------------------------------------- command
    def _command(self, run_id: str) -> dict:
        argv = [a.replace("{run_id}", run_id) for a in self.cfg.command.argv]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.cfg.timeout_seconds)
        if proc.returncode != 0:
            raise PipelineError(f"command exited {proc.returncode}: {proc.stderr[-300:]}")
        return {"type": "command", "returncode": 0}
