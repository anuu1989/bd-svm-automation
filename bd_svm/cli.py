"""Command line interface: python -m bd_svm <command>  (see `make help`)."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime

from . import bdcli
from .blackduck import BlackDuckClient, BlackDuckError
from .config import ConfigError, load_config, validate
from .orchestrator import Orchestrator
from .pipeline import PipelineTrigger
from .report import render_markdown
from .store import Store
from .svm import build_checks

log = logging.getLogger("bd_svm")


def build(cfg) -> Orchestrator:
    return Orchestrator(cfg, BlackDuckClient(cfg.blackduck), build_checks(cfg.svm),
                        PipelineTrigger(cfg.pipeline), Store(cfg.test.state_db))


def _fmt_ts(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"


def cmd_doctor(cfg, _args) -> int:
    problems = validate(cfg)
    for p in problems:
        print(f"CONFIG  ✗ {p}")
    if problems:
        return 2
    print("CONFIG  ✓ valid")
    bd = BlackDuckClient(cfg.blackduck)
    try:
        bd.authenticate()
        print("BLACKDUCK  ✓ authenticated")
        bom = bd.get_project_version()
        print(f"BLACKDUCK  ✓ project/version found {bom}")
    except Exception as exc:
        print(f"BLACKDUCK  ✗ {exc}")
        return 1
    print(f"SVM checks enabled: {[c.name for c in build_checks(cfg.svm)]}  pipeline: {cfg.pipeline.type}")
    return 0


def cmd_start(cfg, _args) -> int:
    run_id = build(cfg).start_cycle()
    print(run_id)
    return 0


def cmd_tick(cfg, args) -> int:
    orch = build(cfg)
    touched = orch.tick()
    if args.start_if_idle and not orch.store.active():
        print("idle -> starting new cycle:", orch.start_cycle())
    for run in touched:
        print(f"{run['run_id']}  {run['status']}  {run['phase']}")
    return 1 if any(r["status"] == "FAILED" for r in touched) else 0


def cmd_loop(cfg, args) -> int:
    orch = build(cfg)
    while True:
        try:
            touched = orch.tick()
            if args.stop_on_failure and any(r["status"] == "FAILED" for r in touched):
                print("a run failed; stopping (--stop-on-failure)")
                return 1
            if not orch.store.active():
                orch.start_cycle()
        except Exception:
            log.exception("loop iteration failed")
        time.sleep(float(cfg.test.poll_seconds))


def cmd_status(cfg, args) -> int:
    runs = Store(cfg.test.state_db).all(args.limit)
    if args.json:
        print(json.dumps(runs, indent=2, default=str))
        return 0
    print(f"{'RUN':<28}{'STATUS':<8}{'PHASE':<13}{'NEXT STEP DUE':<21}COMPONENT / VULN")
    for r in runs:
        c = r["data"].get("component", {})
        print(f"{r['run_id']:<28}{r['status']:<8}{r['phase']:<13}"
              f"{_fmt_ts(r['due_at']) if r['status'] == 'ACTIVE' else '-':<21}"
              f"{c.get('name', '?')} {c.get('version', '')} / {c.get('vuln_id', '?')}")
    return 0


def cmd_report(cfg, args) -> int:
    md = render_markdown(Store(cfg.test.state_db).all(args.limit))
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(md)
        print(f"wrote {args.output}")
    else:
        print(md)
    return 0


def cmd_cleanup(cfg, args) -> int:
    build(cfg).abort(args.run_id)
    print(f"{args.run_id} aborted and cleaned up")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bd_svm", description=__doc__)
    p.add_argument("-c", "--config", help="config file (default config/config.yaml)")
    p.add_argument("--wait-hours", type=float, help="override test.wait_hours (smoke tests)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="validate config + Black Duck connectivity").set_defaults(fn=cmd_doctor)
    sub.add_parser("start", help="begin a cycle: find, add, verify in Black Duck, save").set_defaults(fn=cmd_start)
    t = sub.add_parser("tick", help="advance all runs whose 8h wait has elapsed")
    t.add_argument("--start-if-idle", action="store_true", help="start a new cycle when nothing is active")
    t.set_defaults(fn=cmd_tick)
    lp = sub.add_parser("loop", help="run forever (tick + start new cycles)")
    lp.add_argument("--stop-on-failure", action="store_true")
    lp.set_defaults(fn=cmd_loop)
    s = sub.add_parser("status", help="list runs")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)
    r = sub.add_parser("report", help="markdown report of runs")
    r.add_argument("--limit", type=int, default=50)
    r.add_argument("-o", "--output")
    r.set_defaults(fn=cmd_report)
    c = sub.add_parser("cleanup", help="abort a run and remove its component from Black Duck")
    c.add_argument("run_id")
    c.set_defaults(fn=cmd_cleanup)
    bdcli.register(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    overrides = {"test": {"wait_hours": args.wait_hours}} if args.wait_hours is not None else None
    try:
        cfg = load_config(args.config, overrides)
        if args.command not in ("doctor", "status", "report", "bd", "svm-check", "pipeline-trigger"):
            problems = validate(cfg)
            if problems:
                print("Invalid configuration:\n  - " + "\n  - ".join(problems), file=sys.stderr)
                return 2
        return args.fn(cfg, args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except BlackDuckError as exc:
        print(f"Black Duck error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
