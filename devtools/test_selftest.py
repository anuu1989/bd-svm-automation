"""Self-tests for the framework (run with `make selftest`): state handling,
token cache, and the phases end-to-end against the mock Black Duck - including
the failure paths (abort, cleanup, missing state, count drift)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import requests

from devtools.mock_blackduck import MockServer

ROOT = Path(__file__).resolve().parent.parent


class StateTest(unittest.TestCase):
    def test_roundtrip_and_validation(self):
        from utils import state
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "state.json"
            with self.assertRaises(state.StateError):
                state.load_state(p)                              # missing
            with self.assertRaises(state.StateError):
                state.save_state({"run_id": "x"}, p)             # incomplete
            data = {k: 1 for k in state.REQUIRED_KEYS}
            state.save_state(data, p)
            self.assertEqual(state.load_state(p), data)
            p.write_text(json.dumps({"run_id": "x"}))
            with self.assertRaises(state.StateError):
                state.load_state(p)                              # corrupted

    def test_run_id_uses_github_run_id(self):
        from utils import state
        os.environ["GITHUB_RUN_ID"] = "12345"
        try:
            self.assertEqual(state.new_run_id(), "12345")
        finally:
            del os.environ["GITHUB_RUN_ID"]
        self.assertTrue(state.new_run_id().startswith("local-"))


class AuthCacheTest(unittest.TestCase):
    def test_cached_until_forced(self):
        from config import settings
        from utils import auth

        class Resp:
            status_code = 200
            text = ""

            def json(self):
                return {"bearerToken": f"t{len(calls)}", "expiresInMilliseconds": 3_600_000}

        calls = []

        class Http:
            def post(self, *a, **k):
                calls.append(1)
                return Resp()

        settings.BD_HOST, settings.BD_API_KEY = "http://x", "k"
        auth.clear_cache()
        h = Http()
        first = auth.get_token(session=h)
        self.assertEqual(auth.get_token(session=h), first)       # cached
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(auth.get_token(force=True, session=h), first)
        auth.clear_cache()


class PhasesAgainstMockTest(unittest.TestCase):
    def setUp(self):
        self.srv = MockServer().start()
        self.tmp = tempfile.TemporaryDirectory()
        self.state_file = Path(self.tmp.name) / "state.json"

    def tearDown(self):
        self.srv.stop()
        self.tmp.cleanup()

    def run_pytest(self, *args, **env):
        e = {**os.environ, "BD_HOST": self.srv.base, "BD_API_KEY": "mock", "BD_HTTP_RETRIES": "0",
             "BD_VULN_WAIT_SECONDS": "1", "STATE_FILE": str(self.state_file), **env}
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args],
                              cwd=ROOT, env=e, capture_output=True, text=True)

    def bom_count(self):
        return requests.get(self.srv.base + "/mock/state").json()["count"]

    def test_full_cycle_restores_baseline(self):
        r = self.run_pytest("tests/test_api_health.py", "tests/phase1")
        self.assertEqual(r.returncode, 0, r.stdout[-1500:])
        state = json.loads(self.state_file.read_text())
        self.assertEqual((state["bom_count_before"], state["bom_count_after"]), (10, 11))
        self.assertEqual(self.bom_count(), 11)
        r = self.run_pytest("tests/phase2")
        self.assertEqual(r.returncode, 0, r.stdout[-1500:])
        self.assertIn("5 passed", r.stdout)
        self.assertEqual(self.bom_count(), 10)

    def test_phase1_failure_aborts_and_cleans_up(self):
        r = self.run_pytest("tests/phase1", BD_VULN_ID="CVE-0000-0000")   # fails at step 07, after the add
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("1 failed", r.stdout)
        self.assertIn("5 skipped", r.stdout)                              # steps 08-12 aborted
        self.assertEqual(self.bom_count(), 10)                            # component removed again
        self.assertFalse(self.state_file.exists())

    def test_phase2_without_state_fails_cleanly(self):
        r = self.run_pytest("tests/phase2")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("phase 1 has not run", r.stdout)
        self.assertEqual(self.bom_count(), 10)

    def test_phase2_detects_count_drift_and_keeps_component(self):
        self.assertEqual(self.run_pytest("tests/phase1").returncode, 0)
        self.srv.state.bom[("extra-lib", "1.0")] = {"matchTypes": ["FILE_EXACT"], "usages": [],
                                                    "reviewStatus": "NOT_REVIEWED", "remediation": {}}
        r = self.run_pytest("tests/phase2")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BOM count is 12", r.stdout)
        self.assertEqual(self.bom_count(), 12)                            # nothing deleted on drift


if __name__ == "__main__":
    unittest.main()
