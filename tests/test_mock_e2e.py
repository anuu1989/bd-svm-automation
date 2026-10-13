"""Integration: the real client/orchestrator over HTTP against bd_svm.mock_server."""
import os
import tempfile
import time
import unittest

import requests

from bd_svm.blackduck import BlackDuckClient
from bd_svm.config import load_config
from bd_svm.mock_server import MockServer
from bd_svm.notify import Notifier
from bd_svm.orchestrator import Orchestrator
from bd_svm.pipeline import PipelineTrigger
from bd_svm.store import Store
from bd_svm.svm import build_checks


class MockE2ETest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.srv = MockServer().start()

    def tearDown(self):
        self.srv.stop()
        self.tmp.cleanup()

    def orch(self, candidates, **test):
        t = {"mode": "poll", "first_check_seconds": 0, "check_interval_seconds": 0, "wait_hours": 0.01,
             "assessment_timeout_seconds": 1, "batch_size": len(candidates), "max_attempts": 3,
             "retry_seconds": 0, "state_db": os.path.join(self.tmp.name, "s.db")}
        t.update(test)
        cfg = load_config(overrides={
            "blackduck": {"base_url": self.srv.base, "api_token": "t", "candidates": candidates,
                          "http_retries": 0},
            "svm": {"api": {"enabled": True, "base_url": self.srv.base, "path": "/svm/api/vulnerabilities",
                            "params": {"component": "{component_name}"}, "list_key": "data.items",
                            "fields": {"severity": "severity", "remediation_status": "status"},
                            "retries": 0}},
            "pipeline": {"type": "webhook", "webhook": {"url": self.srv.base + "/pipeline/trigger"}},
            "test": t, "evidence": {"dir": self.tmp.name}})
        return Orchestrator(cfg, BlackDuckClient(cfg.blackduck), build_checks(cfg.svm),
                            PipelineTrigger(cfg.pipeline), Store(cfg.test.state_db),
                            notifier=Notifier(cfg.notify))

    def drain(self, o, limit=20):
        for _ in range(limit):
            if not o.store.active():
                return
            o.tick()
            time.sleep(0.02)

    ALL = [{"name": "log4j-core", "version": "2.14.1"},
           {"name": "jackson-databind", "version": "2.9.8", "scenario": "remediation", "status": "IGNORED"},
           {"name": "commons-text", "version": "1.9", "scenario": "upgrade", "upgrade_to": "1.10.0"},
           {"name": "left-pad", "version": "1.3.0", "scenario": "negative"}]

    def test_all_scenarios_pass_over_http(self):
        o = self.orch(self.ALL)
        run_id = o.start_cycle()
        self.drain(o)
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "PASSED", run["data"].get("failure"))
        state = requests.get(self.srv.base + "/mock/state").json()
        self.assertEqual(state["bom"], [])                    # nothing left behind
        self.assertEqual(state["triggers"], 2)                # 1 per phase for the whole batch

    def test_sync_lag_is_polled_until_visible(self):
        self.srv.state.sync_delay = 1.0
        o = self.orch([self.ALL[0]], first_check_seconds=0, wait_hours=0.02)
        run_id = o.start_cycle()
        self.drain(o, limit=200)
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "PASSED", run["data"].get("failure"))

    def test_svm_never_syncs_fails_and_cleans_up(self):
        self.srv.state.sync_delay = 3600                      # sync effectively never happens
        o = self.orch([self.ALL[0]], wait_hours=0.0003)       # ~1s deadline
        run_id = o.start_cycle()
        time.sleep(1.2)
        self.drain(o)
        run = o.store.get(run_id)
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(requests.get(self.srv.base + "/mock/state").json()["bom"], [])

    def test_svm_503_is_retried(self):
        o = self.orch([self.ALL[0]])
        run_id = o.start_cycle()
        requests.post(self.srv.base + "/mock/fail-next?count=2")
        self.drain(o)
        self.assertEqual(o.store.get(run_id)["status"], "PASSED")


if __name__ == "__main__":
    unittest.main()
