"""End-to-end lifecycle tests with fake Black Duck / SVM / pipeline (no network)."""
import os
import tempfile
import unittest

from bd_svm.blackduck import BlackDuckClient, BlackDuckError
from bd_svm.config import AttrDict, load_config, validate
from bd_svm.orchestrator import Orchestrator
from bd_svm.pipeline import PipelineError
from bd_svm.store import Store
from bd_svm.svm import CheckResult, Subject, evaluate, extract_records, record_matches

CV = "https://bd/api/components/c1/versions/v1"


class FakeBD:
    def __init__(self, vulns=("CVE-2021-44228",), manual=True):
        self.bom_items, self.vulns, self.manual = {}, list(vulns), manual
        self.deleted = 0

    def get_project_version(self):
        return {"project_id": "p", "version_id": "v", "version_href": "h"}

    def find_vulnerable_component(self, bom):
        return {"name": "log4j-core", "version": "2.14.1", "component_version_href": CV,
                "vuln_id": "CVE-2021-44228", "vuln_count": 1}

    def add_component(self, bom, href):
        self.bom_items[href] = {"_meta": {"href": href + "/bom"}, "componentVersion": href}
        return self.bom_items[href]

    def vulnerability_assessment(self, bom, href):
        return list(self.vulns) if href in self.bom_items else []

    def find_bom_item(self, bom, href):
        return self.bom_items.get(href)

    def update_remediation(self, bom, href, vuln_id, status, comment=""):
        self.remediation = (vuln_id, status, comment)

    def delete_component(self, bom, href):
        if href in self.bom_items:
            del self.bom_items[href]
            self.deleted += 1
            return True
        return False


class FakeCheck:
    def __init__(self, name, svm):
        self.name, self.svm = name, svm

    def check(self, subject):
        if self.svm.error:
            return CheckResult(self.name, None, error="svm down")
        return CheckResult(self.name, self.svm.present, "fake")


class FakeSvm:
    present, error = True, False


class FakePipeline:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def trigger(self, run_id):
        self.calls.append(run_id)
        if self.fail:
            raise PipelineError("boom")
        return {"type": "fake"}


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = load_config(overrides={
            "test": {"state_db": os.path.join(self.tmp.name, "s.db"), "wait_hours": 8,
                     "assessment_timeout_seconds": 0, "max_attempts": 2, "retry_seconds": 60},
        })
        self.clock, self.bd, self.svm = Clock(), FakeBD(), FakeSvm()
        self.pipe = FakePipeline()

    def tearDown(self):
        self.tmp.cleanup()

    def orch(self):
        return Orchestrator(self.cfg, self.bd, [FakeCheck("api", self.svm), FakeCheck("ui", self.svm)],
                            self.pipe, Store(self.cfg.test.state_db), clock=self.clock, sleep=lambda s: None)

    def test_full_cycle_passes(self):
        o = self.orch()
        run_id = o.start_cycle()
        self.assertEqual(o.store.get(run_id)["phase"], "ADD_WAIT")
        self.assertEqual(o.tick(), [])                      # not due yet
        self.clock.now += 8 * 3600
        o.tick()                                            # ADD test, delete in BD
        run = o.store.get(run_id)
        self.assertEqual((run["status"], run["phase"]), ("ACTIVE", "DELETE_WAIT"))
        self.assertEqual(self.bd.bom_items, {})
        self.svm.present = False                            # SVM synced the deletion
        self.clock.now += 8 * 3600
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual((run["status"], run["phase"]), ("PASSED", "DONE"))
        self.assertEqual(len(self.pipe.calls), 2)

    def test_add_test_failure_cleans_up(self):
        o = self.orch()
        run_id = o.start_cycle()
        self.svm.present = False                            # SVM never got the component
        self.clock.now += 8 * 3600
        o.tick()
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "FAILED")
        self.assertIn("ADD TEST failed", run["data"]["failure"])
        self.assertEqual(self.bd.bom_items, {})             # nothing left behind

    def test_delete_test_failure(self):
        o = self.orch()
        run_id = o.start_cycle()
        self.clock.now += 8 * 3600
        o.tick()
        self.clock.now += 8 * 3600
        o.tick()                                            # SVM still shows component
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "FAILED")
        self.assertIn("DELETE TEST failed", run["data"]["failure"])

    def test_svm_outage_retries_then_gives_up(self):
        o = self.orch()
        run_id = o.start_cycle()
        self.svm.error = True
        self.clock.now += 8 * 3600
        o.tick()
        self.assertEqual(o.store.get(run_id)["status"], "ACTIVE")
        self.assertEqual(len(self.pipe.calls), 1)
        self.clock.now += 60
        o.tick()
        self.assertEqual(len(self.pipe.calls), 1)           # pipeline not re-triggered on retry
        self.assertEqual(o.store.get(run_id)["status"], "FAILED")
        self.assertEqual(self.bd.bom_items, {})

    def test_pipeline_failure_fails_test(self):
        self.pipe.fail = True
        o = self.orch()
        run_id = o.start_cycle()
        self.clock.now += 8 * 3600
        o.tick()
        self.assertEqual(o.store.get(run_id)["status"], "FAILED")

    def test_assessment_sets_remediation_when_enabled(self):
        self.cfg.blackduck["assessment"] = AttrDict({"enabled": True, "status": "IGNORED", "comment": "c"})
        o = self.orch()
        run_id = o.start_cycle()
        self.assertEqual(self.bd.remediation, ("CVE-2021-44228", "IGNORED", "c"))
        self.assertEqual(o.store.get(run_id)["data"]["remediation_status"], "IGNORED")

    def test_bd_assessment_missing_fails_and_cleans_up(self):
        self.bd.vulns = []
        o = self.orch()
        run_id = o.start_cycle()
        self.assertEqual(o.store.get(run_id)["status"], "FAILED")
        self.assertEqual(self.bd.bom_items, {})


class UnitTest(unittest.TestCase):
    def test_record_matching(self):
        s = Subject("log4j-core", "2.14.1", "CVE-2021-44228")
        self.assertTrue(record_matches({"component": "Log4j-Core 2.14.1", "id": "cve-2021-44228"}, s))
        self.assertFalse(record_matches({"component": "log4j-core 2.15.0", "id": "CVE-2021-44228"}, s))
        self.assertFalse(record_matches({"component": "other", "id": "CVE-2021-44228"}, s))

    def test_extract_records(self):
        self.assertEqual(extract_records({"data": {"items": [1, 2]}}, "data.items"), [1, 2])
        self.assertEqual(extract_records({"items": [{"a": 1}]}), [{"a": 1}])

    def test_evaluate(self):
        found = [CheckResult("api", True), CheckResult("ui", False)]
        self.assertFalse(evaluate(found, True, "all")[0])
        self.assertTrue(evaluate(found, True, "any")[0])
        self.assertFalse(evaluate([CheckResult("api", None, error="x")], True)[0])

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
        item = {"_meta": {"href": "https://bd/bom/item"}, "componentVersion": self.CVH, "ignored": False}
        bd = self.client({("GET", "/components"): {"items": [item], "totalCount": 1}})
        bd.set_ignored(self.BOM, self.CVH, True)
        put = next(c for c in self.sess.calls if c[0] == "PUT")
        self.assertEqual(put[1], "https://bd/bom/item")
        self.assertEqual(put[2]["ignored"], True)
        self.assertNotIn("_meta", put[2])


if __name__ == "__main__":
    unittest.main()
