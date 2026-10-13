"""Orchestrator tests with fake Black Duck / SVM / pipeline (no network).

The fake pipeline snapshots the fake Black Duck BOM into the fake SVM, like a
real sync, so ordering bugs (trigger before add, stale snapshots) show up.
"""
import copy
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET

import bd_svm.notify as notify_mod
from bd_svm.blackduck import BlackDuckClient, BlackDuckError
from bd_svm.config import AttrDict, load_config, validate
from bd_svm.notify import Notifier
from bd_svm.orchestrator import Orchestrator
from bd_svm.pipeline import PipelineError
from bd_svm.report import render_json, render_junit, render_markdown
from bd_svm.store import Store
from bd_svm.svm import CheckResult, Subject, check_fields, evaluate, extract_records, record_matches

H = "https://bd/api/components/{n}/versions/{v}"


def item(name, version, vuln="CVE-1", scenario="standard", **kw):
    d = {"name": name, "version": version, "component_version_href": H.format(n=name, v=version),
         "vuln_id": vuln, "vuln_count": 1 if vuln else 0, "severity": "CRITICAL" if vuln else "",
         "scenario": scenario, "status": kw.pop("status", None)}
    d.update(kw)
    return d


class FakeBD:
    def __init__(self, candidates=None):
        self.candidates = candidates or [item("log4j-core", "2.14.1", "CVE-2021-44228")]
        self.bom_items, self.vulns, self.deleted = {}, {}, 0
        self.remediation = []
        for c in self.candidates + [c["upgrade_to"] for c in self.candidates if c.get("upgrade_to")]:
            self.vulns[c["component_version_href"]] = [c["vuln_id"]] if c.get("vuln_id") else []

    def get_project_version(self):
        return {"project_id": "p", "version_id": "v", "version_href": "h"}

    def select_components(self, bom, count=1):
        return copy.deepcopy(self.candidates[:count])

    def add_component(self, bom, href):
        name = href.split("/")[-3]
        self.bom_items[href] = {"_meta": {"href": href + "/bom"}, "componentVersion": href,
                                "componentName": name, "componentVersionName": href.split("/")[-1],
                                "matchTypes": ["MANUAL_BOM_COMPONENT"]}
        return self.bom_items[href]

    def vulnerability_assessment(self, bom, href):
        return list(self.vulns.get(href, [])) if href in self.bom_items else []

    def find_bom_item(self, bom, href):
        return self.bom_items.get(href)

    def list_bom_components(self, bom):
        return list(self.bom_items.values())

    def update_remediation(self, bom, href, vuln_id, status, comment=""):
        self.remediation.append((vuln_id, status))

    def delete_component(self, bom, href):
        if href in self.bom_items:
            del self.bom_items[href]
            self.deleted += 1
            return True
        return False


class FakeSvm:
    """SVM that mirrors the BOM as of the last pipeline trigger."""

    def __init__(self, bd):
        self.bd, self.snapshot = bd, set()
        self.sync_enabled, self.error, self.field_issue = True, False, False

    def sync(self):
        if self.sync_enabled:
            self.snapshot = {(i["componentName"], i["componentVersionName"])
                             for h, i in self.bd.bom_items.items() if self.bd.vulns.get(h)}


class FakeCheck:
    def __init__(self, name, svm):
        self.name, self.svm = name, svm

    def check(self, subject):
        if self.svm.error:
            return CheckResult(self.name, None, error="svm down")
        found = (subject.component_name, subject.component_version) in self.svm.snapshot
        r = CheckResult(self.name, found, "fake")
        if found and subject.expected:
            r.fields_ok = not self.svm.field_issue
            r.field_issues = ["severity: expected X, got Y"] if self.svm.field_issue else []
        return r


class FakePipeline:
    def __init__(self, svm, fail=False):
        self.svm, self.calls, self.fail = svm, [], fail

    def trigger(self, run_id):
        self.calls.append(run_id)
        if self.fail:
            raise PipelineError("boom")
        self.svm.sync()
        return {"type": "fake"}


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class FakeNotifier:
    enabled = True

    def __init__(self):
        self.events = []

    def notify(self, event, run):
        self.events.append((event, run["run_id"], run["status"]))


class Base(unittest.TestCase):
    OVERRIDES: dict = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        test = {"state_db": os.path.join(self.tmp.name, "s.db"), "wait_hours": 8, "mode": "fixed",
                "assessment_timeout_seconds": 0, "max_attempts": 2, "retry_seconds": 60,
                "first_check_seconds": 100, "check_interval_seconds": 600}
        test.update(self.OVERRIDES.get("test", {}))
        self.cfg = load_config(overrides={"test": test, "evidence": {"dir": self.tmp.name}})
        self.clock = Clock()
        self.notifier = FakeNotifier()

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, candidates=None, pipeline_fail=False):
        self.bd = FakeBD(candidates)
        self.svm = FakeSvm(self.bd)
        self.pipe = FakePipeline(self.svm, pipeline_fail)
        store = Store(self.cfg.test.state_db, clock=self.clock)
        return Orchestrator(self.cfg, self.bd, [FakeCheck("api", self.svm), FakeCheck("ui", self.svm)],
                            self.pipe, store, notifier=self.notifier, clock=self.clock, sleep=lambda s: None)

    def advance(self, seconds):
        self.clock.now += seconds


class FixedModeTest(Base):
    def test_full_cycle_passes(self):
        o = self.make()
        run_id = o.start_cycle()
        self.assertEqual(o.store.get(run_id)["phase"], "ADD_WAIT")
        self.assertEqual(o.tick(), [])                      # 8h not elapsed
        self.advance(8 * 3600)
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual((run["status"], run["phase"]), ("ACTIVE", "DELETE_WAIT"))
        self.assertEqual(self.bd.bom_items, {})
        self.advance(8 * 3600)
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual((run["status"], run["phase"]), ("PASSED", "DONE"))
        self.assertEqual(len(self.pipe.calls), 2)
        self.assertEqual(self.notifier.events, [("passed", run_id, "PASSED")])

    def test_add_failure_cleans_up_and_notifies(self):
        o = self.make()
        run_id = o.start_cycle()
        self.svm.sync_enabled = False                       # SVM never gets the component
        self.advance(8 * 3600)
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "FAILED")
        self.assertIn("ADD TEST failed", run["data"]["failure"])
        self.assertEqual(self.bd.bom_items, {})
        self.assertEqual(self.notifier.events[0][0], "failed")

    def test_delete_failure(self):
        o = self.make()
        run_id = o.start_cycle()
        self.advance(8 * 3600)
        o.tick()
        self.svm.sync_enabled = False                       # SVM keeps the stale record
        self.advance(8 * 3600)
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "FAILED")
        self.assertIn("DELETE TEST failed", run["data"]["failure"])

    def test_svm_outage_retries_then_gives_up_without_retrigger(self):
        o = self.make()
        run_id = o.start_cycle()
        self.svm.error = True
        self.advance(8 * 3600)
        o.tick()
        self.assertEqual(o.store.get(run_id)["status"], "ACTIVE")
        self.advance(60)
        o.tick()
        self.assertEqual(len(self.pipe.calls), 1)
        self.assertEqual(o.store.get(run_id)["status"], "FAILED")
        self.assertEqual(self.bd.bom_items, {})

    def test_pipeline_failure_fails_test(self):
        o = self.make(pipeline_fail=True)
        run_id = o.start_cycle()
        self.advance(8 * 3600)
        o.tick()
        self.assertEqual(o.store.get(run_id)["status"], "FAILED")
        self.assertIn("pipeline failed", o.store.get(run_id)["data"]["failure"])

    def test_bd_assessment_missing_fails_and_cleans_up(self):
        o = self.make()
        self.bd.vulns = {k: [] for k in self.bd.vulns}
        run_id = o.start_cycle()
        self.assertEqual(o.store.get(run_id)["status"], "FAILED")
        self.assertEqual(self.bd.bom_items, {})

    def test_field_mismatch_fails_add_test(self):
        o = self.make()
        run_id = o.start_cycle()
        self.svm.field_issue = True
        self.advance(8 * 3600)
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "FAILED")
        self.assertIn("severity", run["data"]["failure"])


class ScenarioTest(Base):
    def test_remediation_scenario_sets_status(self):
        o = self.make([item("jackson-databind", "2.9.8", "CVE-2", scenario="remediation", status="IGNORED")])
        run_id = o.start_cycle()
        self.assertEqual(self.bd.remediation, [("CVE-2", "IGNORED")])
        self.assertEqual(o.store.get(run_id)["data"]["items"][0]["remediation_status"], "IGNORED")

    def test_global_assessment_applies_to_standard(self):
        self.cfg.blackduck["assessment"] = AttrDict({"enabled": True, "status": "MITIGATED", "comment": "c"})
        o = self.make()
        o.start_cycle()
        self.assertEqual(self.bd.remediation, [("CVE-2021-44228", "MITIGATED")])

    def test_negative_scenario_expects_absent(self):
        o = self.make([item("left-pad", "1.3.0", "", scenario="negative")])
        run_id = o.start_cycle()
        self.advance(8 * 3600)
        o.tick()
        self.assertEqual(o.store.get(run_id)["phase"], "DELETE_WAIT")
        self.advance(8 * 3600)
        o.tick()
        self.assertEqual(o.store.get(run_id)["status"], "PASSED")

    def test_upgrade_scenario_swaps_then_cleans_up(self):
        up = item("commons-text", "1.10.0", "")
        o = self.make([item("commons-text", "1.9", "CVE-3", scenario="upgrade", upgrade_to=up)])
        run_id = o.start_cycle()
        self.advance(8 * 3600)
        o.tick()
        self.assertEqual(list(self.bd.bom_items), [up["component_version_href"]])   # swapped
        self.advance(8 * 3600)
        o.tick()
        self.assertEqual(o.store.get(run_id)["status"], "PASSED")
        self.assertEqual(self.bd.bom_items, {})                                     # leftovers removed

    def test_batch_all_items_must_pass(self):
        cands = [item("a", "1", "CVE-A"), item("b", "1", "CVE-B")]
        self.cfg.test["batch_size"] = 2
        o = self.make(cands)
        run_id = o.start_cycle()
        self.assertEqual(len(o.store.get(run_id)["data"]["items"]), 2)
        self.advance(8 * 3600)
        o.tick()
        self.advance(8 * 3600)
        o.tick()
        self.assertEqual(o.store.get(run_id)["status"], "PASSED")
        self.assertEqual(len(self.pipe.calls), 2)            # one trigger per phase, not per item


class PollModeTest(Base):
    OVERRIDES = {"test": {"mode": "poll"}}

    def test_passes_as_soon_as_visible_and_records_latency(self):
        o = self.make()
        run_id = o.start_cycle()
        self.svm.sync_enabled = False
        self.advance(100)                                    # first check
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual((run["status"], run["phase"]), ("ACTIVE", "ADD_WAIT"))
        self.assertEqual(run["due_at"], self.clock.now + 600)
        self.svm.sync_enabled = True
        self.advance(600)
        self.svm.sync()                                      # SVM catches up
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual(run["phase"], "DELETE_WAIT")
        self.assertEqual(run["data"]["items"][0]["tests"]["add"]["latency_s"], 700)

    def test_times_out_at_deadline(self):
        o = self.make()
        run_id = o.start_cycle()
        self.svm.sync_enabled = False
        for _ in range(60):
            self.advance(600)
            o.tick()
            if o.store.get(run_id)["status"] != "ACTIVE":
                break
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "FAILED")
        self.assertGreaterEqual(self.clock.now, 1_000_000 + 8 * 3600)
        self.assertEqual(self.bd.bom_items, {})


class OverlapAndCoalesceTest(Base):
    OVERRIDES = {"test": {"mode": "poll", "max_active_runs": 2, "start_interval_minutes": 30}}

    def test_capacity_and_spacing(self):
        o = self.make()
        self.assertTrue(o.can_start())
        o.start_cycle()
        self.assertFalse(o.can_start())                      # spacing not elapsed
        self.advance(31 * 60)
        self.assertTrue(o.can_start())
        o.start_cycle()
        self.advance(31 * 60)
        self.assertFalse(o.can_start())                      # max_active_runs reached

    def test_one_trigger_serves_two_runs(self):
        o = self.make()
        o.start_cycle()
        self.advance(31 * 60)
        o.start_cycle()
        self.advance(120)                                    # both are due
        o.tick()
        self.assertEqual(len(self.pipe.calls), 1)            # second run reused the trigger


class SweepTest(Base):
    def test_sweep_dry_run_and_apply_protect_active_runs(self):
        o = self.make([item("log4j-core", "2.14.1", "CVE-1")])
        run_id = o.start_cycle()                             # active run owns log4j-core 2.14.1
        orphan_href = H.format(n="log4j-core", v="2.0")
        self.bd.bom_items[orphan_href] = {"_meta": {"href": "x"}, "componentVersion": orphan_href,
                                          "componentName": "log4j-core", "componentVersionName": "2.0",
                                          "matchTypes": ["MANUAL_BOM_COMPONENT"]}
        unrelated = H.format(n="real-product-lib", v="1")
        self.bd.bom_items[unrelated] = {"_meta": {"href": "y"}, "componentVersion": unrelated,
                                        "componentName": "real-product-lib", "componentVersionName": "1",
                                        "matchTypes": ["MANUAL_BOM_COMPONENT"]}
        found = o.sweep()
        self.assertEqual([f["version"] for f in found], ["2.0"])
        self.assertIn(orphan_href, self.bd.bom_items)        # dry run
        o.sweep(apply=True)
        self.assertNotIn(orphan_href, self.bd.bom_items)
        self.assertIn(unrelated, self.bd.bom_items)          # not a candidate -> untouched
        self.assertEqual(o.store.get(run_id)["status"], "ACTIVE")


class ReportTest(Base):
    def test_reports_render(self):
        o = self.make()
        run_id = o.start_cycle()
        self.advance(8 * 3600)
        o.tick()
        self.advance(8 * 3600)
        o.tick()
        runs = o.store.all()
        md = render_markdown(runs)
        self.assertIn("log4j-core", md)
        self.assertIn("PASSED", md)
        self.assertEqual(json.loads(render_json(runs))["passed"], 1)
        suite = ET.fromstring(render_junit(runs))
        self.assertEqual(suite.get("tests"), "2")
        self.assertEqual(suite.get("failures"), "0")
        self.assertEqual(runs[0]["run_id"], run_id)

    def test_junit_marks_failures(self):
        o = self.make()
        o.start_cycle()
        self.svm.sync_enabled = False
        self.advance(8 * 3600)
        o.tick()
        suite = ET.fromstring(render_junit(o.store.all()))
        self.assertGreaterEqual(int(suite.get("failures")), 1)


class UnitTest(unittest.TestCase):
    def test_record_matching(self):
        s = Subject("log4j-core", "2.14.1", "CVE-2021-44228")
        self.assertTrue(record_matches({"component": "Log4j-Core 2.14.1", "id": "cve-2021-44228"}, s))
        self.assertFalse(record_matches({"component": "log4j-core 2.15.0", "id": "CVE-2021-44228"}, s))
        self.assertFalse(record_matches({"component": "other", "id": "CVE-2021-44228"}, s))

    def test_extract_records(self):
        self.assertEqual(extract_records({"data": {"items": [1, 2]}}, "data.items"), [1, 2])
        self.assertEqual(extract_records({"items": [{"a": 1}]}), [{"a": 1}])

    def test_check_fields(self):
        rec = {"sev": "critical", "meta": {"status": "IGNORED"}}
        mapping = {"severity": "sev", "remediation_status": "meta.status"}
        self.assertEqual(check_fields(rec, {"severity": "CRITICAL", "remediation_status": "IGNORED"}, mapping), [])
        self.assertEqual(len(check_fields(rec, {"severity": "HIGH"}, mapping)), 1)
        self.assertEqual(check_fields(rec, {"severity": "HIGH"}, {}), [])      # no mapping -> skipped
        self.assertEqual(check_fields(rec, {"severity": ""}, mapping), [])     # no expectation -> skipped

    def test_evaluate(self):
        found = [CheckResult("api", True), CheckResult("ui", False)]
        self.assertFalse(evaluate(found, True, "all")[0])
        self.assertTrue(evaluate(found, True, "any")[0])
        self.assertFalse(evaluate([CheckResult("api", None, error="x")], True)[0])
        bad_fields = [CheckResult("api", True, fields_ok=False, field_issues=["severity: expected A, got B"])]
        ok, detail = evaluate(bad_fields, True)
        self.assertFalse(ok)
        self.assertIn("severity", detail)

    def test_config_env_expansion_and_paths(self):
        os.environ["BLACKDUCK_URL"] = "https://bd.example"
        cfg = load_config(overrides={"blackduck": {"paths": {"projects": "/custom/projects"}}})
        self.assertEqual(cfg.blackduck.base_url, "https://bd.example")
        bd = BlackDuckClient(cfg.blackduck)
        self.assertEqual(bd.url(cfg.blackduck.paths.projects), "https://bd.example/custom/projects")
        self.assertTrue(validate(cfg))                      # no SVM check enabled -> problem

    def test_refuses_to_delete_non_manual_item(self):
        cfg = load_config(overrides={"blackduck": {"base_url": "https://bd", "api_token": "t"}})
        bd = BlackDuckClient(cfg.blackduck)
        bd.find_bom_item = lambda bom, href: {"_meta": {"href": "x"}, "matchTypes": ["FILE_EXACT"]}
        with self.assertRaises(BlackDuckError):
            bd.delete_component({}, "href")

    def test_notifier_formats_and_filters(self):
        sent = []

        class R:
            def raise_for_status(self):
                pass

        original = notify_mod.requests.post
        notify_mod.requests.post = lambda url, json, timeout: sent.append(json) or R()
        try:
            cfg = AttrDict({"webhook_url": "http://hook", "format": "teams", "on": ["failed"], "prefix": ""})
            n = Notifier(cfg)
            run = {"run_id": "r1", "status": "FAILED", "data": {"failure": "boom", "items": []}}
            self.assertFalse(n.notify("passed", run))            # filtered out
            self.assertTrue(n.notify("failed", run))
            self.assertEqual(sent[0]["@type"], "MessageCard")
            self.assertFalse(Notifier(AttrDict({"webhook_url": ""})).notify("failed", run))
        finally:
            notify_mod.requests.post = original


class FakeResp:
    def __init__(self, payload=None, status=200, headers=None):
        self.payload, self.status_code, self.headers = payload, status, headers or {}
        self.content = b"x" if payload is not None else b""
        self.text = str(payload)

    def json(self):
        return self.payload


class FakeSession:
    """Records requests; replies from a {(METHOD, url-suffix): payload} map."""

    def __init__(self, routes):
        self.routes, self.calls, self.verify = routes, [], True

    def post(self, url, **kw):
        return FakeResp({"bearerToken": "tok"})

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw.get("json"), kw.get("headers", {}).get("Content-Type")))
        for (m, suffix), payload in self.routes.items():
            if m == method and url.endswith(suffix):
                return FakeResp(payload, headers={"Location": url + "/new"})
        return FakeResp({"items": [], "totalCount": 0})


class ExtendedApiTest(unittest.TestCase):
    BOM = {"project_id": "p1", "version_id": "v1"}
    CVH = "https://bd/api/components/c1/versions/cv1"

    def client(self, routes):
        cfg = load_config(overrides={"blackduck": {"base_url": "https://bd", "api_token": "t"}})
        self.sess = FakeSession(routes)
        return BlackDuckClient(cfg.blackduck, session=self.sess)

    def test_paths_and_payloads(self):
        bd = self.client({})
        bd.create_project("proj", "d")
        bd.create_version("p1", "1.0")
        bd.delete_version("p1", "v1")
        bd.delete_project("p1")
        bd.raw("GET", "/api/foo", params={"a": 1})
        got = [(m, u.replace("https://bd", "")) for m, u, *_ in self.sess.calls]
        self.assertEqual(got, [("POST", "/api/projects"), ("POST", "/api/projects/p1/versions"),
                               ("DELETE", "/api/projects/p1/versions/v1"),
                               ("DELETE", "/api/projects/p1"), ("GET", "/api/foo")])
        self.assertEqual(self.sess.calls[0][2]["name"], "proj")

    def test_remediation_url_built_from_ids(self):
        bd = self.client({})
        bd.update_remediation(self.BOM, self.CVH, "CVE-1", "IGNORED", "why")
        method, url, body, _ = self.sess.calls[-1]
        self.assertEqual(method, "PUT")
        self.assertTrue(url.endswith("/api/projects/p1/versions/v1/components/c1/versions/cv1"
                                     "/vulnerabilities/CVE-1/remediation"))
        self.assertEqual(body, {"remediationStatus": "IGNORED", "comment": "why"})

    def test_update_bom_item_puts_modified_item(self):
        item_ = {"_meta": {"href": "https://bd/bom/item"}, "componentVersion": self.CVH, "ignored": False}
        bd = self.client({("GET", "/components"): {"items": [item_], "totalCount": 1}})
        bd.set_ignored(self.BOM, self.CVH, True)
        put = next(c for c in self.sess.calls if c[0] == "PUT")
        self.assertEqual(put[1], "https://bd/bom/item")
        self.assertEqual(put[2]["ignored"], True)
        self.assertNotIn("_meta", put[2])


if __name__ == "__main__":
    unittest.main()
