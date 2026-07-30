"""`python3 -m phantom <command>` -- Phase 1 MVP CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phantom.orchestrator import PhantomInstance

DEFAULT_ROOT = Path("./phantom_state")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phantom", description="Project Phantom Phase 1 MVP")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="state directory (default: ./phantom_state)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the hardened baseline and spawn a fresh instance")

    p_write = sub.add_parser("write", help="simulate a user creating/editing a file")
    p_write.add_argument("relpath")
    p_write.add_argument("content")

    sub.add_parser("snapshot", help="take a thin snapshot of the instance data dir and replicate it")

    sub.add_parser("attack", help="simulate a ransomware-style compromise of the instance")

    p_regen = sub.add_parser("regen", help="manually trigger destroy + regenerate + restore")
    p_regen.add_argument("--reason", default="manual trigger", help="why regeneration was triggered")

    sub.add_parser("status", help="show instance state, snapshot count, and recent audit events")

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
        print(f"Snapshot {snap.snapshot_id}: {len(snap.files)} file(s), replicated to region-replica")
        return 0

    if args.command == "attack":
        planted = phantom.simulate_attack()
        print("Simulated compromise. Planted/mutated files:")
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

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
