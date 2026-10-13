"""HTML report extras: every API call made by a test is attached to it in the
pytest-html report (request, status, response snippet), plus free-form notes
such as the BOM count audit.
"""
from __future__ import annotations

import json
import threading

_lock = threading.Lock()
_entries: list[dict] = []
_SNIPPET = 2000


def record_call(method: str, url: str, status: int | None, request_body, response_text: str,
                elapsed_ms: int) -> None:
    with _lock:
        _entries.append({"kind": "call", "method": method, "url": url, "status": status,
                         "request": request_body, "response": (response_text or "")[:_SNIPPET],
                         "elapsed_ms": elapsed_ms})


def note(text: str) -> None:
    print(text)
    with _lock:
        _entries.append({"kind": "note", "text": text})


def drain() -> list[dict]:
    with _lock:
        out, _entries[:] = list(_entries), []
    return out


def to_extras(entries: list[dict]) -> list:
    """Convert entries to pytest-html extras (empty if pytest-html is absent)."""
    try:
        from pytest_html import extras
    except ImportError:
        return []
    out = []
    for e in entries:
        if e["kind"] == "note":
            out.append(extras.text(e["text"], name="note"))
            continue
        text = f"{e['method']} {e['url']}\n-> HTTP {e['status']} in {e['elapsed_ms']} ms\n"
        if e["request"] is not None:
            text += "request: " + json.dumps(e["request"], default=str)[:_SNIPPET] + "\n"
        text += "response: " + e["response"]
        out.append(extras.text(text, name=f"{e['method']} {e['status']}"))
    return out
