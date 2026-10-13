"""state.json: the hand-off between phase 1 (writes) and phase 2 (reads).

In CI it travels as a GitHub artifact (retention: 1 day). It holds only IDs and
counts - no secrets.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from config import settings

REQUIRED_KEYS = ("run_id", "project_id", "version_id", "component_id", "comp_ver_id",
                 "vuln_id", "bom_count_before", "bom_count_after")


class StateError(Exception):
    pass


def new_run_id() -> str:
    """GitHub run id in CI, otherwise local-<epoch>."""
    return os.environ.get("GITHUB_RUN_ID") or f"local-{int(time.time())}"


def save_state(data: dict, path: Path | None = None) -> Path:
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        raise StateError(f"refusing to write incomplete state, missing: {missing}")
    target = Path(path or settings.STATE_FILE)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".state-", suffix=".tmp")
    with os.fdopen(fd, "w") as fh:          # atomic: never leave a half-written file
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, target)
    return target


def load_state(path: Path | None = None) -> dict:
    target = Path(path or settings.STATE_FILE)
    if not target.is_file():
        raise StateError(
            f"{target} not found - phase 1 has not run (or its artifact expired). "
            "Run phase 1 first: make phase1")
    data = json.loads(target.read_text())
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        raise StateError(f"{target} is incomplete, missing keys: {missing}")
    return data
