"""`python3 -m phantom <command>` -- Phase 1 + Phase 2 MVP CLI."""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path

from phantom.benchmark import SCALES as BENCHMARK_SCALES
from phantom.benchmark import run_scale
from phantom.chaos import ChaosRunner
from phantom.intel_export import verify_bundle
from phantom.orchestrator import PhantomInstance
from phantom.policy import DEFAULT_DAILY_INTERVAL_SECONDS

DEFAULT_ROOT = Path("./phantom_state")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phantom", description="Project Phantom MVP")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="state directory (default: ./phantom_state)")
    parser.add_argument(
        "--feed", type=Path, default=None,
        help="path to a shared threat-intel feed; point several instances at one file to form a fleet "
             "(default: per-instance feed inside --root)",
    )
    parser.add_argument("--instance-id", default="phantom-vm-0", help="identifier for this instance")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the hardened baseline and spawn a fresh instance")

    p_write = sub.add_parser("write", help="simulate a user creating/editing a file")
    p_write.add_argument("relpath")
    p_write.add_argument("content")

    sub.add_parser("snapshot", help="take a thin snapshot of the instance data dir, replicated to all providers")

    p_attack = sub.add_parser("attack", help="simulate a compromise of the instance")
    p_attack.add_argument(
        "--mode", choices=["dropper", "encryption"], default="dropper",
        help="dropper: plant malicious files alongside user data (default). "
             "encryption: overwrite existing files in place with high-entropy content "
             "(no known-bad hashes -- detection has to earn it)",
    )

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

    sub.add_parser(
        "detect",
        help="score the latest inter-snapshot delta for behavioral drift (no action taken)",
    )

    p_respond = sub.add_parser(
        "detect-and-respond",
        help="score the latest delta and auto-regenerate if it looks like an attack",
    )
    p_respond.add_argument(
        "--no-share-intel", action="store_true",
        help="don't contribute indicators to the fleet feed (models a customer who hasn't opted in)",
    )

    p_vault = sub.add_parser("vault", help="inspect the forensic evidence vault")
    vault_sub = p_vault.add_subparsers(dest="vault_command", required=True)
    vault_sub.add_parser("list", help="list captured evidence cases with chain-of-custody metadata")
    vault_sub.add_parser("verify", help="verify the chain of custody and stored artifacts are untampered")

    p_fleet = sub.add_parser("fleet", help="threat-intel feed / fleet immunity")
    fleet_sub = p_fleet.add_subparsers(dest="fleet_command", required=True)
    fleet_sub.add_parser("show", help="show indicators currently published to the feed")
    fleet_sub.add_parser("pull", help="fold fleet indicators into this instance's local blocklist")

    p_deception = sub.add_parser("deception", help="deception layer / honeypot (opt-in, default off)")
    deception_sub = p_deception.add_subparsers(dest="deception_command", required=True)
    deception_sub.add_parser("status", help="show whether deception is permitted, and why not")
    p_dec_enable = deception_sub.add_parser(
        "enable", help="record a customer opt-in with legal review (does not itself clear a jurisdiction)")
    p_dec_enable.add_argument("--jurisdiction", required=True, help="operating jurisdiction for this deployment")
    p_dec_enable.add_argument("--reviewed-by", required=True, help="who accepted the legal/risk review")
    p_dec_enable.add_argument(
        "--permit-jurisdiction", action="append", default=None, dest="permitted",
        help="add a jurisdiction counsel has cleared (repeatable); empty allowlist = deception never runs",
    )
    deception_sub.add_parser("disable", help="turn the deception module back off")
    deception_sub.add_parser("ttps", help="list TTP observations harvested from the sandbox")

    p_intel = sub.add_parser("intel", help="threat-intel feed productization (export/revoke)")
    intel_sub = p_intel.add_subparsers(dest="intel_command", required=True)
    p_intel_export = intel_sub.add_parser("export", help="build a subscriber-facing bundle")
    p_intel_export.add_argument("--tier", choices=["intel", "community"], default="intel")
    p_intel_export.add_argument("--out", type=Path, default=None, help="write the bundle to this path")
    p_intel_revoke = intel_sub.add_parser("revoke", help="withdraw an indicator from future exports")
    p_intel_revoke.add_argument("content_hash")
    p_intel_verify = intel_sub.add_parser("verify", help="subscriber-side integrity check of a bundle file")
    p_intel_verify.add_argument("bundle", type=Path)

    p_chaos = sub.add_parser("chaos", help="chaos/resilience testing")
    chaos_sub = p_chaos.add_subparsers(dest="chaos_command", required=True)
    p_chaos_run = chaos_sub.add_parser("run", help="run fault-injection scenarios and check recovery invariants")
    p_chaos_run.add_argument("--seed", type=int, default=None, help="seed for randomized scenarios")
    p_chaos_run.add_argument(
        "--workdir", type=Path, default=None,
        help="scratch directory for scenario instances (default: <root>/chaos_runs)",
    )

    p_bench = sub.add_parser("benchmark", help="scale benchmark for the snapshot/restore path (§9 top risk)")
    bench_sub = p_bench.add_subparsers(dest="benchmark_command", required=True)
    p_bench_run = bench_sub.add_parser("run", help="measure snapshot/restore cost at a given scale")
    p_bench_run.add_argument(
        "--scale", default="small", choices=sorted(BENCHMARK_SCALES),
        help="workload size preset (default: small). 'large' writes several GiB and takes minutes.",
    )
    p_bench_run.add_argument("--rounds", type=int, default=5, help="incremental snapshot rounds (default: 5)")
    p_bench_run.add_argument(
        "--workdir", type=Path, default=None,
        help="scratch directory for generated data (default: <root>/benchmark_runs)",
    )
    p_bench_run.add_argument(
        "--keep", action="store_true",
        help="keep generated data and stores after the run instead of deleting them",
    )

    p_compliance = sub.add_parser("compliance", help="control-evidence report (NOT a certification)")
    compliance_sub = p_compliance.add_subparsers(dest="compliance_command", required=True)
    p_comp_report = compliance_sub.add_parser("report", help="generate the control-evidence report")
    p_comp_report.add_argument("--out", type=Path, default=None, help="also write the report as JSON here")

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
    phantom = PhantomInstance(args.root, feed_path=args.feed, instance_id=args.instance_id)

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
        if args.mode == "encryption":
            encrypted = phantom.simulate_encryption_attack()
            print("Simulated in-place encryption. Overwritten files:")
            for relpath in encrypted:
                print(f"  {relpath}")
            return 0
        planted = phantom.simulate_attack()
        print("Simulated compromise. Planted files:")
        for relpath in planted:
            print(f"  {relpath}")
        return 0

    if args.command == "detect":
        result = phantom.detect()
        if result is None:
            print("No snapshots to evaluate")
            return 0
        print(result.summary())
        return 0

    if args.command == "detect-and-respond":
        result, report = phantom.detect_and_respond(share_intel=not args.no_share_intel)
        if result is None:
            print("No snapshots to evaluate")
            return 0
        print(result.summary())
        if report is None:
            print("No action taken.")
            return 0
        print()
        print(report.summary())
        return 0 if (report.rto_pass and report.rpo_pass) else 1

    if args.command == "vault":
        if args.vault_command == "list":
            entries = phantom.vault.entries()
            if not entries:
                print("Forensic vault is empty")
                return 0
            for entry in entries:
                print(f"[{entry.sequence}] {entry.case_id}")
                print(f"    captured_at: {entry.captured_at}   custodian: {entry.custodian}")
                print(f"    reason: {entry.reason}")
                print(f"    content_digest: {entry.content_digest[:16]}...  entry_hash: {entry.entry_hash[:16]}...")
            return 0
        if args.vault_command == "verify":
            problems = phantom.vault.verify_chain()
            if not problems:
                print(f"Chain of custody intact across {len(phantom.vault.entries())} case(s)")
                return 0
            print("CHAIN OF CUSTODY COMPROMISED:")
            for problem in problems:
                print(f"  {problem}")
            return 1

    if args.command == "fleet":
        if args.fleet_command == "show":
            indicators = phantom.feed.indicators()
            if not indicators:
                print("Threat-intel feed is empty")
                return 0
            for indicator in indicators:
                print(f"{indicator.content_hash[:16]}...  {indicator.label}  "
                      f"published={indicator.published_at}  source={indicator.source_fingerprint}")
            return 0
        if args.fleet_command == "pull":
            learned = phantom.pull_fleet_intel()
            print(f"Learned {learned} new indicator(s) from the fleet feed")
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

    if args.command == "deception":
        if args.deception_command == "status":
            config = phantom.deception_policy.load()
            decision = phantom.deception_policy.evaluate()
            print(decision.summary())
            print()
            print(f"  enabled: {config.enabled}")
            print(f"  jurisdiction: {config.jurisdiction or '(none declared)'}")
            print(f"  legal review: {'acknowledged by ' + config.reviewed_by if config.legal_review_ack else 'NOT on record'}")
            print(f"  permitted jurisdictions: {config.permitted_jurisdictions or '(empty -- nothing cleared)'}")
            return 0
        if args.deception_command == "enable":
            _config, decision = phantom.enable_deception(
                jurisdiction=args.jurisdiction, reviewed_by=args.reviewed_by,
                permitted_jurisdictions=args.permitted,
            )
            print(f"Opt-in recorded for jurisdiction {args.jurisdiction!r}, reviewed by {args.reviewed_by!r}")
            print()
            print(decision.summary())
            return 0
        if args.deception_command == "disable":
            phantom.deception_policy.disable()
            print("Deception module disabled")
            return 0
        if args.deception_command == "ttps":
            observations = phantom.honeypot.observations()
            if not observations:
                print("No TTP observations harvested")
                return 0
            for observation in observations:
                print(f"{observation.content_hash[:16]}...  {observation.relpath}  "
                      f"{observation.size_bytes}B  observed={observation.observed_at}")
            return 0

    if args.command == "intel":
        if args.intel_command == "export":
            if args.out is not None:
                bundle = phantom.intel_exporter.export_to_file(args.out, tier=args.tier)
                print(f"Wrote {bundle.indicator_count} indicator(s) to {args.out} (tier={bundle.tier})")
                print(f"integrity_digest: {bundle.integrity_digest}")
            else:
                bundle = phantom.intel_exporter.export(tier=args.tier)
                print(bundle.to_json())
            return 0
        if args.intel_command == "revoke":
            phantom.revocations.revoke(args.content_hash)
            print(f"Revoked {args.content_hash}; it will be excluded from future exports")
            return 0
        if args.intel_command == "verify":
            problems = verify_bundle(args.bundle.read_text())
            if not problems:
                print("Bundle integrity OK (checksum only -- does not authenticate the issuer)")
                return 0
            print("BUNDLE PROBLEMS:")
            for problem in problems:
                print(f"  {problem}")
            return 1

    if args.command == "chaos" and args.chaos_command == "run":
        workdir = args.workdir or (args.root / "chaos_runs")
        counter = itertools.count()

        def make_instance():
            return PhantomInstance(workdir / f"run-{next(counter):03d}", instance_id=args.instance_id)

        report = ChaosRunner(make_instance, seed=args.seed).run_all()
        # Recorded so the compliance report can evidence "test recovery
        # procedures" (A1.3) -- an untested recovery claim is just a claim.
        phantom.audit.append(
            "chaos_suite_run",
            scenarios=len(report.results),
            passed=sum(1 for r in report.results if r.passed),
            all_passed=report.passed,
            seed=args.seed,
        )
        print(report.summary())
        return 0 if report.passed else 1

    if args.command == "benchmark" and args.benchmark_command == "run":
        workdir = args.workdir or (args.root / "benchmark_runs")
        results = run_scale(args.scale, workdir, rounds=args.rounds, keep=args.keep)
        for result in results:
            print(result.summary())
            print()
        phantom.audit.append(
            "benchmark_run",
            scale=args.scale,
            rounds=args.rounds,
            workloads=[r.workload.name for r in results],
            overhead_pass=all(r.overhead_pass for r in results),
            rto_pass=all(r.rto_pass for r in results),
        )
        # Exit non-zero when a §4 target is missed, so this can gate CI later.
        return 0 if all(r.rto_pass and r.overhead_pass for r in results) else 1

    if args.command == "compliance" and args.compliance_command == "report":
        report = phantom.compliance.generate()
        print(report.summary())
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(report.to_json())
            print()
            print(f"Wrote JSON report to {args.out}")
        return 0

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
