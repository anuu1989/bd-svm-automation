"""In-memory fake Black Duck for local runs and CI self-tests.

    python -m devtools.mock_blackduck --port 8099        (make mock-server)

Implements the endpoints the phases call: auth, projects, versions, KB search,
BOM list/add/update/delete (with a 10-item baseline), vulnerable BOM
components and remediation. It models the API as this suite understands it -
passing against it proves the test logic, not compatibility with your server.

Fault injection: POST /mock/fail-next?status=500&count=1 makes the next N
requests return that status.
"""
from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CATALOG = {
    "commons-text": {"1.9": [("CVE-2022-42889", "CRITICAL")], "1.10.0": []},
    "log4j-core": {"2.14.1": [("CVE-2021-44228", "CRITICAL")], "2.17.1": []},
}
PROJECT, VERSION, BASELINE = "svm-e2e-test", "main", 10


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.bom: dict[tuple[str, str], dict] = {}
        for i in range(1, BASELINE + 1):
            self.bom[(f"baseline-lib-{i}", "1.0")] = {"matchTypes": ["FILE_EXACT"], "usages": [],
                                                      "reviewStatus": "NOT_REVIEWED", "remediation": {}}
        self.fail_status, self.fail_count = 500, 0


def make_handler(state: State, base: str):
    ver = lambda n, v: f"{base}/api/components/{n}/versions/{v}"          # noqa: E731
    item_href = lambda n, v: f"{base}/api/projects/p1/versions/v1/components/{n}/versions/{v}"  # noqa: E731

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

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
            limit = int(qs.get("limit", ["100"])[0])
            off = int(qs.get("offset", ["0"])[0])
            return {"items": items[off:off + limit], "totalCount": len(items)}

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
            try:
                with state.lock:
                    self._dispatch(method, url.path, parse_qs(url.query))
            except Exception as exc:  # pragma: no cover
                self._send(500, {"error": repr(exc)})

        def _item(self, name, ver_, meta):
            return {"componentName": name, "componentVersionName": ver_, "componentVersion": ver(name, ver_),
                    "matchTypes": meta["matchTypes"], "usages": meta["usages"],
                    "reviewStatus": meta["reviewStatus"], "_meta": {"href": item_href(name, ver_)}}

        def _dispatch(self, method, path, qs):  # noqa: C901
            m = re.fullmatch
            if method == "POST" and path == "/mock/fail-next":
                state.fail_status = int(qs.get("status", ["500"])[0])
                state.fail_count = int(qs.get("count", ["1"])[0])
                return self._send(200, {"ok": True})
            if path == "/mock/state":
                return self._send(200, {"count": len(state.bom),
                                        "bom": sorted(f"{n} {v}" for n, v in state.bom)})
            if state.fail_count > 0 and path != "/api/tokens/authenticate":
                state.fail_count -= 1
                return self._send(state.fail_status, {"error": "injected"})
            if method == "POST" and path == "/api/tokens/authenticate":
                return self._send(200, {"bearerToken": "mock-bearer", "expiresInMilliseconds": 7200000})
            if path == "/api/current-version":
                return self._send(200, {"version": "mock"})
            if path == "/api/projects":
                name = self._q(qs, "name")
                items = [{"name": PROJECT, "_meta": {"href": f"{base}/api/projects/p1"}}]
                return self._send(200, self._page([i for i in items if name in i["name"]], qs))
            if path == "/api/projects/p1/versions":
                vn = self._q(qs, "versionName")
                items = [{"versionName": VERSION, "_meta": {"href": f"{base}/api/projects/p1/versions/v1"}}]
                return self._send(200, self._page([i for i in items if vn in i["versionName"]], qs))
            if path == "/api/projects/p1/versions/v1/components":
                if method == "POST":
                    mm = m(r".*/components/([^/]+)/versions/([^/]+)", self._body().get("component", ""))
                    if not mm or mm.group(1) not in CATALOG or mm.group(2) not in CATALOG[mm.group(1)]:
                        return self._send(400, {"error": "unknown component"})
                    state.bom[(mm.group(1), mm.group(2))] = {
                        "matchTypes": ["MANUAL_BOM_COMPONENT"], "usages": [],
                        "reviewStatus": "NOT_REVIEWED", "remediation": {}}
                    return self._send(201, None)
                items = [self._item(n, v, meta) for (n, v), meta in state.bom.items()]
                return self._send(200, self._page(items, qs))
            mm = m(r"/api/projects/p1/versions/v1/components/([^/]+)/versions/([^/]+)", path)
            if mm and method in ("PUT", "DELETE"):
                key = (mm.group(1), mm.group(2))
                if key not in state.bom:
                    return self._send(404, {"error": "not in BOM"})
                if method == "DELETE":
                    del state.bom[key]
                else:
                    body = self._body()
                    state.bom[key]["usages"] = body.get("usages", state.bom[key]["usages"])
                    state.bom[key]["reviewStatus"] = body.get("reviewStatus", state.bom[key]["reviewStatus"])
                return self._send(204)
            if path == "/api/projects/p1/versions/v1/vulnerable-bom-components":
                items = []
                for (n, v), meta in state.bom.items():
                    for vuln, sev in CATALOG.get(n, {}).get(v, []):
                        items.append({"componentName": n, "componentVersionName": v,
                                      "componentVersion": ver(n, v),
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
                items = [{"name": n, "_meta": {"href": f"{base}/api/components/{n}"}} for n in CATALOG if name in n]
                return self._send(200, self._page(items, qs))
            mm = m(r"/api/components/([^/]+)/versions", path)
            if mm and mm.group(1) in CATALOG:
                n = mm.group(1)
                return self._send(200, self._page(
                    [{"versionName": v, "_meta": {"href": ver(n, v)}} for v in CATALOG[n]], qs))
            return self._send(404, {"error": f"no route {method} {path}"})

    return H


class MockServer:
    def __init__(self, port: int = 0):
        self.state = State()
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
    srv = MockServer(ap.parse_args().port).start()
    print(f"mock Black Duck listening on {srv.base}", flush=True)
    try:
        srv.thread.join()
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()
