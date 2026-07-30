# Project Phantom — Phase 1 MVP Prototype

Working code for the **Phase 1: MVP** milestone of the Project Phantom charter
(v0.2, 2026-07-29):

> Single-VM proof: thin snapshots, cloud backup, manual trigger, demonstrated
> <5 min recovery. Patch/QA pipeline stood up in parallel.

This is a runnable proof of the core regeneration loop, not a production
platform. It exists to prove the concept end-to-end before Phase 2
(scheduled ephemeral regeneration + the real sanitization gate) and Phase 3
(AI-vs-AI detection, forensic vault, fleet immunity) are built on top of it.

## What's implemented (maps to charter §5)

| Charter item | This prototype |
|---|---|
| A. Real-Time Snapshot Engine | `phantom/snapshot.py` — content-addressed, thin/incremental snapshots of the instance data directory. Only changed blobs are written; unchanged files are deduplicated by hash. |
| B. Cloud Backup & Versioning | `phantom/backup_store.py` — snapshot store replicated across two local "regions" as a stand-in for multi-region immutable storage; versioned snapshot chain; dedup comes free from content addressing. |
| C. Regeneration & Spawn Orchestration | `phantom/orchestrator.py` — manual-trigger regeneration: destroy the instance, spawn fresh from the immutable baseline, restore the latest data snapshot. |
| I. Vulnerability Scanning & Patch QA (parallel track) | `.github/workflows/phantom-patch-qa.yml` — CI pipeline that runs the regression test suite on every push, standing in for the QA-bot regression gate. |

**Single VM, not a fleet.** The "instance" is a workspace directory
(`InstanceDriver` in `phantom/instance.py`), not a real VM/container/hypervisor.
The driver interface is intentionally the seam Phase 3's multi-cloud control
plane (§5.K) will plug real KVM/QEMU and cloud drivers into — see
"What's deliberately out of scope" below.

A minimal, explicitly-labeled sanitization check ships in `phantom/sanitize.py`
so the attack -> regenerate demo doesn't just restore the malware verbatim.
**This is not the Phase 2 sanitization layer** — the charter's own risk
register is explicit that the real layer is "a Phase 2 gate, not optional."
Treat this one as a placeholder that proves where the gate goes.

## What's deliberately out of scope (later phases)

- Real VM/container/hypervisor drivers (KVM/QEMU, cloud) — Phase 3, §5.K.
- The real Data Sanitization Layer — Phase 2 gate per the risk register.
- AI-vs-AI behavioral detection, forensic vault, deception layer, threat-intel
  feed, multi-cloud control plane, enterprise integrations — Phases 2-4.

## Quick start

Stdlib only, no dependencies, no install required.

```bash
cd project-phantom

# 1. Stand up the baseline image + a fresh instance
python3 -m phantom init

# 2. Simulate normal usage: user files land in the instance, get snapshotted
python3 -m phantom write notes.txt "quarterly numbers"
python3 -m phantom snapshot
python3 -m phantom write budget.csv "1,2,3"
python3 -m phantom snapshot

# 3. Simulate a ransomware-style compromise
python3 -m phantom attack

# The next interval snapshot fires before anyone notices -- it captures the
# attacker's payload too, which is exactly why restore has to go through
# the sanitize gate rather than trusting "latest snapshot" blindly.
python3 -m phantom snapshot

# 4. Manually trigger regeneration and see the RTO/RPO report
python3 -m phantom regen --reason "manual trigger: ransomware indicators"

# 5. Inspect instance state / audit trail
python3 -m phantom status
```

`regen` prints a report like:

```
Regeneration complete: reason=manual trigger: ransomware indicators
  RTO: 0.042s  (target < 300s)   PASS
  RPO: 3.11s   (target < 60s)    PASS
  files restored: 2   quarantined: 2
  evidence preserved: evidence/2026-07-30T12-00-00Z/
```

(Local-disk operations are far faster than a real snapshot/restore over the
network — the numbers above demonstrate the *mechanism*, not production
latency. The <5 min / <1 min targets are the ones from charter §4.)

## Run the tests

```bash
cd project-phantom
python3 -m pytest -q
```

## Layout

```
project-phantom/
  phantom/
    baseline.py      # hardened immutable baseline: create + integrity-verify
    snapshot.py       # thin, content-addressed snapshot engine
    backup_store.py    # multi-region replication stand-in + restore
    sanitize.py         # placeholder quarantine gate (see caveat above)
    instance.py          # disposable-instance driver (local workspace)
    metrics.py            # RTO/RPO timing + audit log
    orchestrator.py        # ties it together: PhantomInstance facade
    cli.py                  # `python3 -m phantom ...`
  tests/
    test_snapshot.py
    test_sanitize.py
    test_e2e.py
```
