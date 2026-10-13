"""In-memory fake Black Duck + SVM + pipeline webhook for demos and tests.

    python -m bd_svm.mock_server --port 8099          (make mock-server)

* Black Duck: the subset of the Hub REST API this tool uses (auth, projects,
  versions, KB components/versions/vulnerabilities, BOM add/list/update/delete,
  vulnerable-bom-components, remediation).
* SVM: GET /svm/api/vulnerabilities?component=<name> returns a *snapshot* of
  the BOM taken at the last pipeline trigger, like a real sync would.
* Pipeline: POST /pipeline/trigger takes that snapshot.
  `--sync-delay N` makes the snapshot lag N seconds to exercise polling.
* Fault injection: POST /mock/fail-next?count=2 makes the next N SVM calls
  return HTTP 503.

It is a model of the API as this tool understands it - passing against it
proves the orchestration, not compatibility with your Black Duck release.
"""
from __future__ import annotations

import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CATALOG = {
    "log4j-core": {"2.14.1": [("CVE-2021-44228", "CRITICAL"), ("CVE-2021-45046", "CRITICAL")],
                   "2.17.1": []},
    "jackson-databind": {"2.9.8": [("CVE-2019-12384", "HIGH")], "2.13.4": []},
    "commons-text": {"1.9": [("CVE-2022-42889", "CRITICAL")], "1.10.0": []},
    "left-pad": {"1.3.0": []},
}
PROJECT, VERSION = "svm-e2e-test", "main"


class State:
    def __init__(self, sync_delay: float = 0.0):
        self.lock = threading.Lock()
        self.bom: dict[tuple[str, str], dict] = {}     # (name, ver) -> {"ignored", "remediation"}
        self.snapshot: list[dict] = []
        self.pending: list[tuple[float, list[dict]]] = []
        self.sync_delay = sync_delay
        self.fail_next = 0
        self.triggers = 0

    def take_snapshot(self) -> list[dict]:
        rows = []
        for (name, ver), meta in self.bom.items():
            for vuln, sev in CATALOG[name][ver]:
                rows.append({"component": name, "version": ver, "vulnerability": vuln, "severity": sev,
                             "status": meta["remediation"].get(vuln, "NEW")})
        return rows

    def current_snapshot(self) -> list[dict]:
        now = time.time()
        while self.pending and self.pending[0][0] <= now:
            self.snapshot = self.pending.pop(0)[1]
        return self.snapshot


def make_handler(state: State, base: str):
    ver_href = lambda n, v: f"{base}/api/components/{n}/versions/{v}"  # noqa: E731
    item_href = lambda n, v: f"{base}/api/projects/p1/versions/v1/components/{n}/versions/{v}"  # noqa: E731

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # quiet
            pass

        # -------------------------------------------------------- plumbing
        def _send(self, code=200, payload=None, headers=None):
            body = b"" if payload is None else json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}") if n else {}

        @staticmethod
        def _page(items, qs):
            return {"items": items if int(qs.get("offset", ["0"])[0]) == 0 else [],
                    "totalCount": len(items)}

        @staticmethod
        def _q(qs, field):
            q = qs.get("q", [""])[0]
            return q.split(":", 1)[1] if q.startswith(field + ":") else ""

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

        def do_PUT(self):
            self._route("PUT")

        def do_DELETE(self):
            self._route("DELETE")

        def _route(self, method):
            url = urlparse(self.path)
            path, qs = url.path, parse_qs(url.query)
            try:
                with state.lock:
                    self._dispatch(method, path, qs)
            except Exception as exc:  # pragma: no cover - debugging aid
                self._send(500, {"error": repr(exc)})

        # --------------------------------------------------------- routes
        def _dispatch(self, method, path, qs):
            m = re.fullmatch
            if method == "POST" and path == "/api/tokens/authenticate":
                return self._send(200, {"bearerToken": "mock-bearer"})
            if path == "/api/current-user":
                return self._send(200, {"userName": "mock-user"})
            if path == "/api/current-version":
                return self._send(200, {"version": "mock-2024.1"})
            if path == "/api/projects":
                if method == "POST":
                    return self._send(201, None, {"Location": f"{base}/api/projects/p-new"})
                name = self._q(qs, "name")
                items = [{"name": PROJECT, "_meta": {"href": f"{base}/api/projects/p1"}}]
                return self._send(200, self._page([i for i in items if name in i["name"]], qs))
            if path == "/api/projects/p1/versions":
                vn = self._q(qs, "versionName")
                items = [{"versionName": VERSION, "_meta": {"href": f"{base}/api/projects/p1/versions/v1"}}]
                return self._send(200, self._page([i for i in items if vn in i["versionName"]], qs))
            if path == "/api/projects/p1/versions/v1/components":
                if method == "POST":
                    href = self._body().get("component", "")
                    mm = m(r".*/components/([^/]+)/versions/([^/]+)", href)
                    if not mm or mm.group(1) not in CATALOG:
                        return self._send(400, {"error": "unknown component"})
                    state.bom.setdefault((mm.group(1), mm.group(2)), {"ignored": False, "remediation": {}})
                    return self._send(201, None, {"Location": item_href(mm.group(1), mm.group(2))})
                items = [{"componentName": n, "componentVersionName": v, "ignored": meta["ignored"],
                          "componentVersion": ver_href(n, v), "matchTypes": ["MANUAL_BOM_COMPONENT"],
                          "_meta": {"href": item_href(n, v)}} for (n, v), meta in state.bom.items()]
                return self._send(200, self._page(items, qs))
            mm = m(r"/api/projects/p1/versions/v1/components/([^/]+)/versions/([^/]+)", path)
            if mm and method in ("PUT", "DELETE"):
                key = (mm.group(1), mm.group(2))
                if key not in state.bom:
                    return self._send(404, {"error": "not in BOM"})
                if method == "DELETE":
                    del state.bom[key]
                else:
                    state.bom[key]["ignored"] = bool(self._body().get("ignored", False))
                return self._send(204)
            if path == "/api/projects/p1/versions/v1/vulnerable-bom-components":
                items = []
                for (n, v), meta in state.bom.items():
                    for vuln, sev in CATALOG[n][v]:
                        items.append({"componentName": n, "componentVersionName": v,
                                      "componentVersion": ver_href(n, v),
                                      "vulnerabilityWithRemediation": {
                                          "vulnerabilityName": vuln, "severity": sev,
                                          "remediationStatus": meta["remediation"].get(vuln, "NEW")}})
                return self._send(200, self._page(items, qs))
            mm = m(r"/api/projects/p1/versions/v1/components/([^/]+)/versions/([^/]+)"
                   r"/vulnerabilities/([^/]+)/remediation", path)
            if mm and method == "PUT":
                key = (mm.group(1), mm.group(2))
                if key not in state.bom:
                    return self._send(404, {"error": "not in BOM"})
                state.bom[key]["remediation"][mm.group(3)] = self._body().get("remediationStatus", "NEW")
                return self._send(200, {})
            if path == "/api/components":
                name = self._q(qs, "name")
                items = [{"name": n, "_meta": {"href": f"{base}/api/components/{n}"}}
                         for n in CATALOG if name in n]
                return self._send(200, self._page(items, qs))
            mm = m(r"/api/components/([^/]+)/versions", path)
            if mm and mm.group(1) in CATALOG:
                n = mm.group(1)
                items = [{"versionName": v, "_meta": {"href": ver_href(n, v)}} for v in CATALOG[n]]
                return self._send(200, self._page(items, qs))
            mm = m(r"/api/components/([^/]+)/versions/([^/]+)/vulnerabilities", path)
            if mm and mm.group(1) in CATALOG:
                items = [{"name": vn, "severity": sev} for vn, sev in CATALOG[mm.group(1)].get(mm.group(2), [])]
                return self._send(200, self._page(items, qs))
            # ----------------------------- SVM + pipeline + fault injection
            if path == "/svm/api/vulnerabilities":
                if state.fail_next > 0:
                    state.fail_next -= 1
                    return self._send(503, {"error": "injected failure"})
                comp = qs.get("component", [""])[0].lower()
                rows = [r for r in state.current_snapshot() if comp in r["component"].lower()]
                return self._send(200, {"data": {"items": rows}})
            if method == "POST" and path == "/pipeline/trigger":
                state.triggers += 1
                state.pending.append((time.time() + state.sync_delay, state.take_snapshot()))
                state.current_snapshot()
                return self._send(200, {"id": state.triggers, "status": "success"})
            if method == "POST" and path == "/mock/fail-next":
                state.fail_next = int(qs.get("count", ["1"])[0])
                return self._send(200, {"fail_next": state.fail_next})
            if path == "/mock/state":
                return self._send(200, {"bom": [f"{n} {v}" for n, v in state.bom],
                                        "svm": state.current_snapshot(), "triggers": state.triggers})
            return self._send(404, {"error": f"no route {method} {path}"})

    return Handler


class MockServer:
    """Embeddable server (used by the integration test)."""

    def __init__(self, port: int = 0, sync_delay: float = 0.0):
        self.state = State(sync_delay)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.httpd.RequestHandlerClass = make_handler(self.state, self.base)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "MockServer":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--sync-delay", type=float, default=0.0, help="seconds SVM lags behind a pipeline trigger")
    args = ap.parse_args()
    srv = MockServer(args.port, args.sync_delay).start()
    print(f"mock Black Duck/SVM listening on {srv.base}", flush=True)
    try:
        srv.thread.join()
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()
