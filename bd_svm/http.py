"""Shared HTTP session factory: retries with backoff for idempotent calls."""
from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def make_session(retries: int = 3, backoff: float = 1.0) -> requests.Session:
    """Session that retries GET/PUT/DELETE on connection errors and 429/5xx.

    POST is deliberately not retried (not idempotent: could add twice).
    """
    session = requests.Session()
    if retries > 0:
        retry = Retry(total=retries, connect=retries, read=retries, status=retries,
                      backoff_factor=backoff, status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS"}),
                      respect_retry_after_header=True, raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session
