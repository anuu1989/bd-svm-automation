"""SQLite persistence for test transactions (run_id / component_id / vuln_id).

The 8h waits make the workflow long-lived, so all state is persisted and the
orchestrator is resumable: any process can `tick` and pick up where the
previous one stopped.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS runs (
                 run_id TEXT PRIMARY KEY,
                 status TEXT NOT NULL,      -- ACTIVE | PASSED | FAILED
                 phase  TEXT NOT NULL,      -- ADD_WAIT | DELETE_WAIT | DONE
                 due_at REAL,               -- epoch seconds when next step may run
                 created_at REAL NOT NULL,
                 updated_at REAL NOT NULL,
                 data TEXT NOT NULL         -- JSON blob (component, vuln, results, events)
               )""")
        self.db.commit()

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["data"] = json.loads(d["data"])
        return d

    def create(self, run_id: str, phase: str, due_at: float, data: dict) -> None:
        now = time.time()
        self.db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?)",
                        (run_id, "ACTIVE", phase, due_at, now, now, json.dumps(data)))
        self.db.commit()

    def update(self, run_id: str, *, status: str | None = None, phase: str | None = None,
               due_at: float | None = None, data: dict | None = None) -> None:
        cur = self.get(run_id)
        self.db.execute(
            "UPDATE runs SET status=?, phase=?, due_at=?, updated_at=?, data=? WHERE run_id=?",
            (status or cur["status"], phase or cur["phase"],
             cur["due_at"] if due_at is None else due_at, time.time(),
             json.dumps(data if data is not None else cur["data"]), run_id))
        self.db.commit()

    def get(self, run_id: str) -> dict:
        row = self.db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            raise KeyError(run_id)
        return self._row(row)

    def active(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM runs WHERE status='ACTIVE' ORDER BY created_at").fetchall()
        return [self._row(r) for r in rows]

    def all(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(r) for r in rows]
