"""Test orchestrator: the flow from the design diagram as a resumable state machine.

    start_cycle():  find vulnerable component -> add to Black Duck -> verify BD
                    assessment -> save transaction -> phase ADD_WAIT (due +8h)
    ADD_WAIT:       trigger pipeline -> SVM API+UI checks -> ADD TEST
                    pass -> delete from BD -> verify BD deleted -> DELETE_WAIT (due +8h)
                    fail -> best-effort cleanup, run FAILED
    DELETE_WAIT:    trigger pipeline -> SVM API+UI checks -> DELETE TEST
                    pass -> run PASSED   (loop() then starts the next cycle)
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from .blackduck import BlackDuckClient
from .pipeline import PipelineError, PipelineTrigger
from .store import Store
from .svm import Subject, evaluate

log = logging.getLogger(__name__)

ADD_WAIT, DELETE_WAIT, DONE = "ADD_WAIT", "DELETE_WAIT", "DONE"


class TransientError(Exception):
    """Step could not be completed (e.g. SVM unreachable); retry later."""


class Orchestrator:
    def __init__(self, cfg, bd: BlackDuckClient, checks: list, pipeline: PipelineTrigger,
                 store: Store, clock=time.time, sleep=time.sleep):
        self.cfg, self.bd, self.checks = cfg, bd, checks
        self.pipeline, self.store = pipeline, store
        self.clock, self.sleep = clock, sleep
        self.wait_s = float(cfg.test.wait_hours) * 3600

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _event(data: dict, msg: str) -> None:
        log.info(msg)
        data.setdefault("events", []).append(
            {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "msg": msg})

    def _subject(self, data: dict) -> Subject:
        c = data["component"]
        return Subject(c["name"], c["version"], c["vuln_id"], self.cfg.blackduck.project_name)

    def _wait_for_assessment(self, bom: dict, cv_href: str, vuln_id: str) -> list[str]:
        """Black Duck computes vulnerabilities asynchronously; poll briefly."""
        timeout = float(self.cfg.test.assessment_timeout_seconds)
        deadline = self.clock() + timeout
        while True:
            seen = self.bd.vulnerability_assessment(bom, cv_href)
            if vuln_id in seen or self.clock() >= deadline:
                return seen
            self.sleep(min(10, max(deadline - self.clock(), 0.1)))

    # -------------------------------------------------------------- phase 1
    def start_cycle(self) -> str:
        run_id = f"{self.cfg.test.run_prefix}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
        data: dict = {"events": [], "pipeline": {}}
        bom = self.bd.get_project_version()
        comp = self.bd.find_vulnerable_component(bom)
        data.update(bom=bom, component=comp)
        self._event(data, f"selected {comp['name']} {comp['version']} / {comp['vuln_id']}")

        item = self.bd.add_component(bom, comp["component_version_href"])
        data["bom_item_href"] = (item.get("_meta") or {}).get("href", "")
        self._event(data, "component added to Black Duck BOM")

        seen = self._wait_for_assessment(bom, comp["component_version_href"], comp["vuln_id"])
        if comp["vuln_id"] not in seen:
            data["bd_assessment"] = seen
            self.store.create(run_id, DONE, 0, data)
            self._fail(run_id, f"Black Duck assessment missing {comp['vuln_id']} (saw {seen})")
            return run_id
        data["bd_assessment"] = seen
        self._event(data, f"Black Duck assessment verified ({len(seen)} vulnerabilities)")

        assess = self.cfg.blackduck.assessment
        if assess and assess.enabled:
            self.bd.update_remediation(bom, comp["component_version_href"], comp["vuln_id"],
                                       assess.status, assess.comment or "")
            data["remediation_status"] = assess.status
            self._event(data, f"remediation status set to {assess.status}")

        due = self.clock() + self.wait_s
        self.store.create(run_id, ADD_WAIT, due, data)
        self._event(data, f"transaction saved; waiting {self.cfg.test.wait_hours}h")
        self.store.update(run_id, data=data)
        return run_id

    # --------------------------------------------------------- phases 2 / 3
    def tick(self) -> list[dict]:
        """Advance every due run by one step. Returns the runs touched."""
        touched = []
        for run in self.store.active():
            if run["due_at"] is not None and run["due_at"] > self.clock():
                continue
            self._step(run["run_id"])
            touched.append(self.store.get(run["run_id"]))
        return touched

    def _step(self, run_id: str) -> None:
        run = self.store.get(run_id)
        data, phase = run["data"], run["phase"]
        try:
            if phase == ADD_WAIT:
                self._verify_added(run_id, data)
            elif phase == DELETE_WAIT:
                self._verify_deleted(run_id, data)
        except Exception as exc:  # TransientError, Black Duck or unexpected errors
            self._retry(run_id, data, f"{type(exc).__name__}: {exc}")

    def _retry(self, run_id: str, data: dict, msg: str) -> None:
        attempts = data.get("attempts", 0) + 1
        data["attempts"] = attempts
        self._event(data, f"error ({attempts}/{self.cfg.test.max_attempts}): {msg}")
        self.store.update(run_id, data=data, due_at=self.clock() + float(self.cfg.test.retry_seconds))
        if attempts >= int(self.cfg.test.max_attempts):
            self._fail(run_id, f"gave up after {attempts} attempts: {msg}")

    def _trigger_and_check(self, run_id: str, data: dict, phase: str, expect_present: bool):
        """Shared by ADD and DELETE tests: pipeline -> SVM API/UI -> diamond."""
        if phase not in data["pipeline"]:   # don't re-trigger on a retry
            try:
                data["pipeline"][phase] = self.pipeline.trigger(f"{run_id}:{phase}")
            except PipelineError as exc:
                data["pipeline"][phase] = {"error": str(exc)}
                self._event(data, f"pipeline failed: {exc}")
                return False, f"pipeline failed: {exc}", []
            self.store.update(run_id, data=data)
        subject = self._subject(data)
        results = [c.check(subject) for c in self.checks]
        if any(r.found is None for r in results):
            errs = "; ".join(f"{r.name}: {r.error}" for r in results if r.found is None)
            raise TransientError(errs)
        ok, detail = evaluate(results, expect_present, self.cfg.svm.require)
        return ok, detail, [r.as_dict() for r in results]

    def _verify_added(self, run_id: str, data: dict) -> None:
        ok, detail, results = self._trigger_and_check(run_id, data, ADD_WAIT, expect_present=True)
        data["add_test"] = {"passed": ok, "detail": detail, "checks": results}
        if not ok:
            self.store.update(run_id, data=data)
            self._fail(run_id, f"ADD TEST failed: {detail}")
            return
        self._event(data, f"ADD TEST = PASS ({detail})")
        href = data["component"]["component_version_href"]
        self.bd.delete_component(data["bom"], href)
        if self.bd.find_bom_item(data["bom"], href):
            raise TransientError("component still in Black Duck BOM after delete")
        data["attempts"] = 0
        self._event(data, "component deleted from Black Duck and verified; waiting for SVM sync")
        self.store.update(run_id, phase=DELETE_WAIT, due_at=self.clock() + self.wait_s, data=data)

    def _verify_deleted(self, run_id: str, data: dict) -> None:
        ok, detail, results = self._trigger_and_check(run_id, data, DELETE_WAIT, expect_present=False)
        data["delete_test"] = {"passed": ok, "detail": detail, "checks": results}
        if not ok:
            self.store.update(run_id, data=data)
            self._fail(run_id, f"DELETE TEST failed: {detail}")
            return
        self._event(data, f"DELETE TEST = PASS ({detail})")
        self.store.update(run_id, status="PASSED", phase=DONE, data=data)

    # ----------------------------------------------------------------- misc
    def _fail(self, run_id: str, reason: str) -> None:
        """Mark FAILED and make sure no test component is left in Black Duck."""
        run = self.store.get(run_id)
        data = run["data"]
        data["failure"] = reason
        self._event(data, f"FAILED: {reason}")
        try:
            href = data["component"]["component_version_href"]
            if self.bd.delete_component(data["bom"], href):
                self._event(data, "cleanup: test component removed from Black Duck")
        except Exception as exc:
            data["cleanup_error"] = str(exc)
            self._event(data, f"cleanup FAILED, remove manually: {exc}")
        self.store.update(run_id, status="FAILED", phase=DONE, data=data)

    def abort(self, run_id: str) -> None:
        self._fail(run_id, "aborted by operator")
