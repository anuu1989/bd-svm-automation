"""Test orchestrator: the flow from the design diagram as a resumable state machine.

A *run* is one cycle and covers a batch of components ("items"):

    start_cycle():  select candidates -> add each to Black Duck -> verify BD
                    assessment (+ optional remediation) -> save transaction
                    -> phase ADD_WAIT
    ADD_WAIT:       trigger pipeline (coalesced) -> poll SVM API+UI until every
                    item matches (or the deadline passes) -> ADD TEST
                    pass -> delete items from BD (upgrade scenario: swap to the
                    fixed version) -> verify BD -> phase DELETE_WAIT
                    fail -> best-effort cleanup, run FAILED
    DELETE_WAIT:    trigger pipeline -> poll until items are gone -> DELETE TEST
                    pass -> remove upgrade leftovers -> run PASSED

Scenarios (per candidate):
    standard     vulnerability appears in SVM, then disappears after delete
    remediation  as standard + remediation status set in BD must show in SVM
    upgrade      after delete the component is swapped to a fixed version;
                 the old version's vulnerability must disappear
    negative     component with no vulnerabilities must NOT show a record
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .blackduck import MANUAL_MATCH_TYPE, BlackDuckClient
from .notify import Notifier
from .pipeline import PipelineError, PipelineTrigger
from .store import Store
from .svm import Subject, evaluate

log = logging.getLogger(__name__)

ADD_WAIT, DELETE_WAIT, DONE = "ADD_WAIT", "DELETE_WAIT", "DONE"


class TransientError(Exception):
    """Step could not be completed (e.g. SVM unreachable); retry later."""


def expects_vulnerability(item: dict) -> bool:
    return item.get("scenario") != "negative"


class Orchestrator:
    def __init__(self, cfg, bd: BlackDuckClient, checks: list, pipeline: PipelineTrigger,
                 store: Store, notifier: Notifier | None = None, clock=time.time, sleep=time.sleep):
        self.cfg, self.bd, self.checks = cfg, bd, checks
        self.pipeline, self.store = pipeline, store
        self.notifier = notifier or Notifier(None)
        self.clock, self.sleep = clock, sleep
        self.wait_s = float(cfg.test.wait_hours) * 3600
        self.poll = cfg.test.mode == "poll"

    # ---------------------------------------------------------------- helpers
    def _event(self, data: dict, msg: str) -> None:
        log.info(msg)
        data.setdefault("events", []).append(
            {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "msg": msg})

    def _first_due(self, base: float) -> float:
        """When the first SVM check happens after an add/delete at `base`."""
        if self.poll:
            return base + min(float(self.cfg.test.first_check_seconds), self.wait_s)
        return base + self.wait_s

    def _wait_for_assessment(self, bom: dict, cv_href: str, want: str) -> list[str]:
        """Black Duck computes vulnerabilities asynchronously; poll briefly."""
        deadline = self.clock() + float(self.cfg.test.assessment_timeout_seconds)
        while True:
            seen = self.bd.vulnerability_assessment(bom, cv_href)
            if not want or want in seen or self.clock() >= deadline:
                return seen
            self.sleep(min(10, max(deadline - self.clock(), 0.1)))

    def _cleanup_items(self, data: dict) -> list[str]:
        """Remove every test component we may have left in Black Duck."""
        errors = []
        for item in data.get("items", []):
            hrefs = [item["component_version_href"]]
            if item.get("upgrade_to") and item.get("upgrade_added"):
                hrefs.append(item["upgrade_to"]["component_version_href"])
            for href in hrefs:
                try:
                    if self.bd.delete_component(data["bom"], href):
                        self._event(data, f"cleanup: removed {item['name']} from Black Duck")
                except Exception as exc:
                    errors.append(f"{item['name']}: {exc}")
        return errors

    # -------------------------------------------------------------- phase 1
    def can_start(self) -> bool:
        active = self.store.active()
        if len(active) >= int(self.cfg.test.max_active_runs):
            return False
        gap = float(self.cfg.test.start_interval_minutes) * 60
        if gap and active:
            newest = max(r["created_at"] for r in active)
            if self.clock() - newest < gap:
                return False
        return True

    def maybe_start(self) -> str | None:
        return self.start_cycle() if self.can_start() else None

    def start_cycle(self) -> str:
        run_id = (f"{self.cfg.test.run_prefix}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
                  f"-{uuid.uuid4().hex[:4]}")
        data: dict = {"events": [], "pipeline": {}, "items": []}
        bom = self.bd.get_project_version()
        data["bom"] = bom
        items = self.bd.select_components(bom, int(self.cfg.test.batch_size))
        for item in items:
            item["tests"] = {}
        data["items"] = items
        self._event(data, "selected " + ", ".join(
            f"{i['name']} {i['version']} [{i['scenario']}]" for i in items))
        try:
            self._add_and_verify(data)
        except Exception:
            self._cleanup_items(data)
            raise
        if data.get("failure"):
            reason = data.pop("failure")
            self.store.create(run_id, DONE, 0, data)
            self._fail(run_id, reason)
            return run_id

        now = self.clock()
        data["added_at"] = now
        data["deadline_at"] = now + self.wait_s
        first = (f"{int(self.cfg.test.first_check_seconds)}s" if self.poll
                 else f"{self.cfg.test.wait_hours}h")
        self._event(data, f"transaction saved; first SVM check in {first}")
        self.store.create(run_id, ADD_WAIT, self._first_due(now), data)
        return run_id

    def _add_and_verify(self, data: dict) -> None:
        bom, assess = data["bom"], self.cfg.blackduck.assessment
        for item in data["items"]:
            added = self.bd.add_component(bom, item["component_version_href"])
            item["bom_item_href"] = (added.get("_meta") or {}).get("href", "")
            self._event(data, f"added {item['name']} {item['version']} to Black Duck BOM")
        for item in data["items"]:
            seen = self._wait_for_assessment(bom, item["component_version_href"], item["vuln_id"])
            item["bd_assessment"] = seen
            if expects_vulnerability(item) and item["vuln_id"] not in seen:
                data["failure"] = (f"Black Duck assessment missing {item['vuln_id']} "
                                   f"for {item['name']} (saw {seen})")
                return
            if not expects_vulnerability(item) and seen:
                data["failure"] = f"negative component {item['name']} unexpectedly has {seen}"
                return
            self._event(data, f"Black Duck assessment verified for {item['name']} "
                              f"({len(seen)} vulnerabilities)")
            status = item.get("status") if item["scenario"] == "remediation" else None
            if not status and assess and assess.enabled and expects_vulnerability(item):
                status = assess.status
            if status and item["vuln_id"]:
                self.bd.update_remediation(bom, item["component_version_href"], item["vuln_id"],
                                           status, (assess.comment if assess else "") or "")
                item["remediation_status"] = status
                self._event(data, f"remediation status of {item['vuln_id']} set to {status}")

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

    def _ensure_pipeline(self, run_id: str, data: dict, phase: str, since: float) -> None:
        """Trigger the pipeline once per phase (optionally re-trigger), coalescing
        with a trigger that already happened after `since` (add/delete time)."""
        info = data["pipeline"].get(phase)
        every = float(self.cfg.pipeline.retrigger_every_seconds or 0)
        if info and "error" not in info and not (every and self.clock() - info["at"] >= every):
            return
        last = self.store.get_meta("pipeline_last_trigger")
        # Only reuse a trigger that STARTED strictly after the BD change: a
        # pipeline that began earlier may have read the BOM before it.
        if self.cfg.pipeline.coalesce and last and last["at"] > since:
            info = {**last["info"], "coalesced": True, "at": last["at"]}
            self._event(data, f"{phase}: reusing pipeline trigger from "
                              f"{int(self.clock() - last['at'])}s ago")
        else:
            started = self.clock()
            try:
                info = {**self.pipeline.trigger(f"{run_id}:{phase}"), "at": started}
            except PipelineError as exc:
                data["pipeline"][phase] = {"error": str(exc), "at": started}
                raise
            self.store.set_meta("pipeline_last_trigger", {"at": info["at"], "info": info})
            self._event(data, f"{phase}: verification pipeline triggered")
        data["pipeline"][phase] = info
        self.store.update(run_id, data=data)

    def _subject(self, run_id: str, item: dict, phase: str, with_fields: bool) -> Subject:
        expected = {}
        if with_fields and expects_vulnerability(item):
            expected = {"severity": item.get("severity"),
                        "remediation_status": item.get("remediation_status")}
        prefix = Path(self.cfg.evidence.dir) / run_id / f"{phase}-{item['name']}"
        return Subject(item["name"], item["version"], item.get("vuln_id", ""),
                       self.cfg.blackduck.project_name, expected,
                       {"evidence_prefix": str(prefix),
                        "max_records": int(self.cfg.evidence.max_records)})

    def _check_item(self, run_id: str, item: dict, phase: str, expect_present: bool) -> dict:
        subject = self._subject(run_id, item, phase, with_fields=expect_present)
        results = [c.check(subject) for c in self.checks]
        if any(r.found is None for r in results):
            raise TransientError("; ".join(f"{item['name']} {r.name}: {r.error}"
                                           for r in results if r.found is None))
        ok, detail = evaluate(results, expect_present, self.cfg.svm.require)
        return {"passed": ok, "detail": detail, "checks": [r.as_dict() for r in results]}

    def _poll_round(self, run_id: str, data: dict, test: str, phase: str, since: float,
                    expect_present) -> list[dict]:
        """Check all not-yet-passed items once. Returns the items still failing."""
        now = self.clock()
        for item in data["items"]:
            if item["tests"].get(test, {}).get("passed"):
                continue
            res = self._check_item(run_id, item, phase, expect_present(item))
            res["latency_s"] = round(now - since) if res["passed"] else None
            res["checked_at"] = now
            item["tests"][test] = res
            if res["passed"]:
                self._event(data, f"{test.upper()} TEST pass for {item['name']} after "
                                  f"{res['latency_s']}s ({res['detail']})")
        data["attempts"] = 0
        return [i for i in data["items"] if not i["tests"][test]["passed"]]

    def _still_waiting(self, run_id: str, data: dict, test: str, failing: list[dict],
                       deadline: float) -> bool:
        """Poll mode: reschedule instead of failing until the deadline."""
        now = self.clock()
        if not (self.poll and now < deadline):
            return False
        due = min(now + float(self.cfg.test.check_interval_seconds), deadline)
        self._event(data, f"{test.upper()} TEST: {len(failing)}/{len(data['items'])} items not yet "
                          f"as expected in SVM; next check in {int(due - now)}s")
        self.store.update(run_id, data=data, due_at=due)
        return True

    @staticmethod
    def _failure_text(test: str, failing: list[dict]) -> str:
        return f"{test.upper()} TEST failed: " + "; ".join(
            f"{i['name']} {i['version']}: {i['tests'][test]['detail']}" for i in failing)

    def _verify_added(self, run_id: str, data: dict) -> None:
        try:
            self._ensure_pipeline(run_id, data, ADD_WAIT, since=data["added_at"])
        except PipelineError as exc:
            self._fail(run_id, f"pipeline failed: {exc}", data)
            return
        failing = self._poll_round(run_id, data, "add", ADD_WAIT, data["added_at"], expects_vulnerability)
        if failing:
            if self._still_waiting(run_id, data, "add", failing, data["deadline_at"]):
                return
            self._fail(run_id, self._failure_text("add", failing), data)
            return
        self._event(data, "ADD TEST = PASS for all items")
        self._swap_in_bd(data)
        now = self.clock()
        data["deleted_at"] = now
        data["delete_deadline_at"] = now + self.wait_s
        self._event(data, "components deleted from Black Duck and verified; waiting for SVM sync")
        self.store.update(run_id, phase=DELETE_WAIT, due_at=self._first_due(now), data=data)

    def _swap_in_bd(self, data: dict) -> None:
        """Delete the items (idempotent); upgrade scenario also adds the fixed version."""
        bom = data["bom"]
        for item in data["items"]:
            href = item["component_version_href"]
            self.bd.delete_component(bom, href)
            if self.bd.find_bom_item(bom, href):
                raise TransientError(f"{item['name']} still in Black Duck BOM after delete")
            if item.get("upgrade_to") and not item.get("upgrade_added"):
                self.bd.add_component(bom, item["upgrade_to"]["component_version_href"])
                item["upgrade_added"] = True
                self._event(data, f"{item['name']} upgraded to {item['upgrade_to']['version']} in BOM")

    def _verify_deleted(self, run_id: str, data: dict) -> None:
        try:
            self._ensure_pipeline(run_id, data, DELETE_WAIT, since=data["deleted_at"])
        except PipelineError as exc:
            self._fail(run_id, f"pipeline failed: {exc}", data)
            return
        failing = self._poll_round(run_id, data, "delete", DELETE_WAIT, data["deleted_at"],
                                   lambda item: False)
        if failing:
            if self._still_waiting(run_id, data, "delete", failing, data["delete_deadline_at"]):
                return
            self._fail(run_id, self._failure_text("delete", failing), data)
            return
        self._event(data, "DELETE TEST = PASS for all items")
        errors = self._cleanup_items(data)     # removes upgrade leftovers
        if errors:
            data["cleanup_error"] = "; ".join(errors)
        self.store.update(run_id, status="PASSED", phase=DONE, data=data)
        self.notifier.notify("cleanup_failed" if errors else "passed", self.store.get(run_id))

    # ----------------------------------------------------------------- misc
    def _fail(self, run_id: str, reason: str, data: dict | None = None) -> None:
        """Mark FAILED and make sure no test component is left in Black Duck."""
        data = data if data is not None else self.store.get(run_id)["data"]
        data["failure"] = reason
        self._event(data, f"FAILED: {reason}")
        errors = self._cleanup_items(data)
        if errors:
            data["cleanup_error"] = "; ".join(errors)
            self._event(data, f"cleanup FAILED, remove manually: {data['cleanup_error']}")
        self.store.update(run_id, status="FAILED", phase=DONE, data=data)
        run = self.store.get(run_id)
        self.notifier.notify("failed", run)
        if errors:
            self.notifier.notify("cleanup_failed", run)

    def abort(self, run_id: str) -> None:
        self._fail(run_id, "aborted by operator")

    def sweep(self, apply: bool = False) -> list[dict]:
        """Find (and optionally delete) orphaned test components.

        Orphan = manually-added BOM item in the test project version, whose
        name is one of the configured candidates, and that no ACTIVE run owns.
        """
        bom = self.bd.get_project_version()
        protected = set()
        for run in self.store.active():
            for item in run["data"].get("items", []):
                protected.add(item["component_version_href"])
                if item.get("upgrade_to"):
                    protected.add(item["upgrade_to"]["component_version_href"])
        names = {c["name"].lower() for c in self.cfg.blackduck.candidates}
        orphans = []
        for item in self.bd.list_bom_components(bom):
            types = item.get("matchTypes")
            manual = MANUAL_MATCH_TYPE in (types or []) or \
                (types is None and not self.cfg.blackduck.require_manual_match_type)
            if manual and (item.get("componentName") or "").lower() in names \
                    and item.get("componentVersion") not in protected:
                orphans.append({"component": item.get("componentName"),
                                "version": item.get("componentVersionName"),
                                "componentVersion": item.get("componentVersion"), "deleted": False})
        if apply:
            for o in orphans:
                o["deleted"] = self.bd.delete_component(bom, o["componentVersion"])
        return orphans
