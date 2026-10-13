"""Bearer token acquisition with an in-process cache.

Phase 2 runs hours after phase 1 and the token has expired by then, so each
phase's test_01 asks for a *fresh* token (force=True); everything else reuses
the cached one until shortly before it expires.
"""
from __future__ import annotations

import time

import requests

from config import settings
from utils import bd_headers, reporter

_SAFETY_MARGIN_S = 60
_cache: dict = {"token": None, "expires_at": 0.0}


class AuthError(Exception):
    pass


def clear_cache() -> None:
    _cache.update(token=None, expires_at=0.0)


def get_token(force: bool = False, session: requests.Session | None = None) -> str:
    if not force and _cache["token"] and time.time() < _cache["expires_at"]:
        return _cache["token"]
    settings.require("BD_HOST", "BD_API_KEY")
    http = session or requests
    url = settings.BD_HOST + settings.PATHS["authenticate"]
    started = time.time()
    resp = http.post(
        url,
        headers={"Authorization": f"token {settings.BD_API_KEY}", "Accept": bd_headers.media("auth")},
        verify=settings.BD_VERIFY_SSL, timeout=settings.BD_TIMEOUT)
    reporter.record_call("POST", url, resp.status_code, None,
                         "<token response redacted>" if resp.status_code == 200 else resp.text,
                         int((time.time() - started) * 1000))
    if resp.status_code != 200:
        raise AuthError(f"authentication failed: HTTP {resp.status_code} {resp.text[:200]}")
    body = resp.json()
    token = body.get("bearerToken")
    if not token:
        raise AuthError("authentication response has no bearerToken")
    ttl_s = float(body.get("expiresInMilliseconds", 7_200_000)) / 1000.0
    _cache.update(token=token, expires_at=time.time() + max(ttl_s - _SAFETY_MARGIN_S, 0))
    return token
