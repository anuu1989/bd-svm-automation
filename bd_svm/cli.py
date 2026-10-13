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
from .notify import Notifier
from .orchestrator import Orchestrator
from .pipeline import PipelineTrigger
from .report import render_json, render_junit, render_markdown
from .store import Store
from .svm import build_checks

log = logging.getLogger("bd_svm")


def build(cfg) -> Orchestrator:
    return Orchestrator(cfg, BlackDuckClient(cfg.blackduck), build_checks(cfg.svm),
                        PipelineTrigger(cfg.pipeline), Store(cfg.test.state_db),
                        notifier=Notifier(cfg.notify))


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
    if args.start_if_idle:
        run_id = orch.maybe_start()
        if run_id:
            print("capacity available -> started new cycle:", run_id)
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
            orch.maybe_start()
        except Exception:
            log.exception("loop iteration failed")
        time.sleep(float(cfg.test.poll_seconds))


def cmd_drain(cfg, args) -> int:
    """Tick until no run is active (demos, smoke tests, one-shot CI jobs)."""
    orch = build(cfg)
    deadline = time.time() + args.max_hours * 3600
    failed = False
    while orch.store.active():
        if time.time() > deadline:
            print("drain: --max-hours reached with runs still active", file=sys.stderr)
            return 3
        failed |= any(r["status"] == "FAILED" for r in orch.tick())
        if orch.store.active():
            time.sleep(min(float(cfg.test.poll_seconds), 5.0) if args.fast else float(cfg.test.poll_seconds))
    for run in orch.store.all(10):
        print(f"{run['run_id']}  {run['status']}")
    return 1 if failed else 0


def cmd_sweep(cfg, args) -> int:
    orphans = build(cfg).sweep(apply=args.apply)
    print(json.dumps(orphans, indent=2))
    if orphans and not args.apply:
        print(f"{len(orphans)} orphan(s) found (dry run). Re-run with --apply to delete.", file=sys.stderr)
    return 0


def cmd_notify_test(cfg, _args) -> int:
    n = Notifier(cfg.notify)
    if not n.enabled:
        print("notify.webhook_url is not set (NOTIFY_WEBHOOK_URL)", file=sys.stderr)
        return 2
    run = {"run_id": "notify-test", "status": "TEST", "data": {"items": []}}
    ok = n.notify("test", run)
    print("sent" if ok else "failed (see log)")
    return 0 if ok else 1


def cmd_status(cfg, args) -> int:
    runs = Store(cfg.test.state_db).all(args.limit)
    if args.json:
        print(json.dumps(runs, indent=2, default=str))
        return 0
    print(f"{'RUN':<34}{'STATUS':<8}{'PHASE':<13}{'NEXT STEP DUE':<21}ITEMS")
    for r in runs:
        items = ", ".join(f"{i['name']} {i['version']}" for i in r["data"].get("items", [])) or "?"
        print(f"{r['run_id']:<34}{r['status']:<8}{r['phase']:<13}"
              f"{_fmt_ts(r['due_at']) if r['status'] == 'ACTIVE' else '-':<21}{items}")
    return 0


def cmd_report(cfg, args) -> int:
    render = {"md": render_markdown, "junit": render_junit, "json": render_json}[args.format]
    md = render(Store(cfg.test.state_db).all(args.limit))
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
    p.add_argument("--batch", type=int, help="override test.batch_size (components per cycle)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="validate config + Black Duck connectivity").set_defaults(fn=cmd_doctor)
    sub.add_parser("start", help="begin a cycle: find, add, verify in Black Duck, save").set_defaults(fn=cmd_start)
    t = sub.add_parser("tick", help="advance all runs whose 8h wait has elapsed")
    t.add_argument("--start-if-idle", action="store_true",
                   help="also start a new cycle if capacity allows (test.max_active_runs, start_interval_minutes)")
    t.set_defaults(fn=cmd_tick)
    lp = sub.add_parser("loop", help="run forever (tick + start new cycles)")
    lp.add_argument("--stop-on-failure", action="store_true")
    lp.set_defaults(fn=cmd_loop)
    d = sub.add_parser("drain", help="tick until no run is active (demo / smoke / one-shot)")
    d.add_argument("--max-hours", type=float, default=24)
    d.add_argument("--fast", action="store_true", help="cap the sleep between ticks at 5s")
    d.set_defaults(fn=cmd_drain)
    sw = sub.add_parser("sweep", help="find (and with --apply delete) orphaned test components")
    sw.add_argument("--apply", action="store_true")
    sw.set_defaults(fn=cmd_sweep)
    sub.add_parser("notify-test", help="send a test notification").set_defaults(fn=cmd_notify_test)
    s = sub.add_parser("status", help="list runs")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)
    r = sub.add_parser("report", help="markdown report of runs")
    r.add_argument("--limit", type=int, default=50)
    r.add_argument("-o", "--output")
    r.add_argument("--format", choices=["md", "junit", "json"], default="md")
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
    test_over = {}
    if args.wait_hours is not None:
        test_over["wait_hours"] = args.wait_hours
    if args.batch is not None:
        test_over["batch_size"] = args.batch
    overrides = {"test": test_over} if test_over else None
    try:
        cfg = load_config(args.config, overrides)
        if args.command not in ("doctor", "status", "report", "bd", "svm-check", "pipeline-trigger", "notify-test"):
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
