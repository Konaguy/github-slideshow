"""`python3 -m phantom <command>` -- Phase 1 + Phase 2 MVP CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phantom.orchestrator import PhantomInstance
from phantom.policy import DEFAULT_DAILY_INTERVAL_SECONDS

DEFAULT_ROOT = Path("./phantom_state")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phantom", description="Project Phantom MVP")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="state directory (default: ./phantom_state)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the hardened baseline and spawn a fresh instance")

    p_write = sub.add_parser("write", help="simulate a user creating/editing a file")
    p_write.add_argument("relpath")
    p_write.add_argument("content")

    sub.add_parser("snapshot", help="take a thin snapshot of the instance data dir, replicated to all providers")

    sub.add_parser("attack", help="simulate a dormant-malware-style compromise of the instance")

    p_regen = sub.add_parser("regen", help="manually trigger destroy + regenerate + restore")
    p_regen.add_argument("--reason", default="manual trigger", help="why regeneration was triggered")

    sub.add_parser("status", help="show instance state, snapshot count, providers, policy, and recent audit events")

    p_policy = sub.add_parser("policy", help="get/set the scheduled regeneration cadence")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)
    p_policy_set = policy_sub.add_parser("set", help="set cadence to 'daily' or 'per_session'")
    p_policy_set.add_argument("cadence", choices=["daily", "per_session"])
    p_policy_set.add_argument(
        "--interval-seconds", type=int, default=DEFAULT_DAILY_INTERVAL_SECONDS,
        help="daily-cadence interval (default: 86400 = 24h; lower this for demos/tests)",
    )
    policy_sub.add_parser("show", help="show the current policy")

    sub.add_parser(
        "scheduled-run",
        help="cron entrypoint: regenerate if the 'daily' cadence is due, else no-op",
    )

    p_session = sub.add_parser("session", help="simulate a user session boundary")
    session_sub = p_session.add_subparsers(dest="session_command", required=True)
    session_sub.add_parser("start", help="regenerate first if cadence is 'per_session'")

    p_providers = sub.add_parser("providers", help="inspect/simulate multi-region storage providers")
    providers_sub = p_providers.add_subparsers(dest="providers_command", required=True)
    providers_sub.add_parser("status", help="show availability of each configured provider")
    p_outage = providers_sub.add_parser("outage", help="simulate a provider going down or recovering")
    p_outage.add_argument("provider")
    p_outage.add_argument("state", choices=["down", "up"])

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    phantom = PhantomInstance(args.root)

    if args.command == "init":
        phantom.init()
        print(f"Baseline created and instance spawned under {args.root}/instance")
        return 0

    if args.command == "write":
        phantom.write_user_file(args.relpath, args.content)
        print(f"Wrote {args.relpath} into instance data dir")
        return 0

    if args.command == "snapshot":
        snap = phantom.take_snapshot()
        print(f"Snapshot {snap.snapshot_id}: {len(snap.files)} file(s), replicated across providers")
        return 0

    if args.command == "attack":
        planted = phantom.simulate_attack()
        print("Simulated compromise. Planted files:")
        for relpath in planted:
            print(f"  {relpath}")
        return 0

    if args.command == "regen":
        report = phantom.regenerate(reason=args.reason)
        print(report.summary())
        return 0 if (report.rto_pass and report.rpo_pass) else 1

    if args.command == "status":
        print(json.dumps(phantom.status(), indent=2))
        return 0

    if args.command == "policy":
        if args.policy_command == "set":
            state = phantom.set_policy(args.cadence, interval_seconds=args.interval_seconds)
            print(f"Policy set: cadence={state.cadence} interval_seconds={state.interval_seconds}")
            return 0
        if args.policy_command == "show":
            state = phantom.policy.load()
            print(json.dumps(state.__dict__, indent=2) if state else "No policy set")
            return 0

    if args.command == "scheduled-run":
        report = phantom.scheduled_check()
        if report is None:
            print("Not due yet (cadence unset, not 'daily', or interval hasn't elapsed)")
            return 0
        print(report.summary())
        return 0 if (report.rto_pass and report.rpo_pass) else 1

    if args.command == "session" and args.session_command == "start":
        report = phantom.session_start()
        if report is None:
            print("Session started; no regeneration (cadence unset or not 'per_session')")
            return 0
        print("Session started; regenerated first (per-session cadence):")
        print(report.summary())
        return 0 if (report.rto_pass and report.rpo_pass) else 1

    if args.command == "providers":
        if args.providers_command == "status":
            print(json.dumps(phantom.backup.provider_status(), indent=2))
            return 0
        if args.providers_command == "outage":
            phantom.backup.set_outage(args.provider, down=(args.state == "down"))
            print(f"Provider {args.provider!r} marked {args.state}")
            return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
