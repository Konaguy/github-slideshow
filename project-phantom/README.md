# Project Phantom — MVP Prototype (Phase 1 + Phase 2)

Working code for the **Phase 1** and **Phase 2** milestones of the Project
Phantom charter (v0.2, 2026-07-29):

> **Phase 1: MVP.** Single-VM proof: thin snapshots, cloud backup, manual
> trigger, demonstrated <5 min recovery. Patch/QA pipeline stood up in
> parallel.
>
> **Phase 2: Ephemeral First.** Scheduled regeneration ships before
> automated detection. Moving-target value doesn't depend on detection
> accuracy. Data sanitization layer ships here (required for safe scheduled
> restores). Multi-region failover and initial multi-cloud storage
> abstraction.

This is a runnable proof of the core regeneration loop, not a production
platform. It exists to prove the concept end-to-end before Phase 3
(AI-vs-AI detection, forensic vault, fleet immunity, deception layer) is
built on top of it.

## What's implemented (maps to charter §5)

| Charter item | This prototype |
|---|---|
| A. Real-Time Snapshot Engine | `phantom/snapshot.py` — content-addressed, thin/incremental snapshots of the instance data directory. Only changed blobs are written; unchanged files are deduplicated by hash. |
| B. Cloud Backup & Versioning | `phantom/backup_store.py` — snapshots replicated across named storage providers (see §5.K below); versioned snapshot chain; dedup comes free from content addressing. |
| C. Regeneration & Spawn Orchestration | `phantom/orchestrator.py` — destroy the instance, spawn fresh from the immutable baseline, restore the latest sanitized data snapshot. Two trigger modes, per §5.C: manual/attack-triggered (`regen`) and scheduled/ephemeral (`scheduled-run`, `session start`). |
| E. Data Sanitization Layer | `phantom/sanitize.py` — a multi-signal restore-time scanning pipeline (see below). This is the Phase 2 gate the risk register calls "not optional." |
| I. Vulnerability Scanning & Patch QA (parallel track) | `.github/workflows/phantom-patch-qa.yml` — CI pipeline that runs the regression test suite on every push, standing in for the QA-bot regression gate. |
| K. Multi-Cloud Control Plane (initial, storage only) | `phantom/storage.py` — a `StorageProvider` interface with named providers standing in for AWS/Azure/private-cloud, fan-out replication on write, and failover on read. Phase 2 scope is explicitly "initial... abstraction," not the full control plane. |

**Single VM, not a fleet.** The "instance" is a workspace directory
(`InstanceDriver` in `phantom/instance.py`), not a real VM/container/hypervisor.
The driver interface is intentionally the seam Phase 3's multi-cloud control
plane (§5.K) will plug real KVM/QEMU and cloud drivers into.

**Storage providers are still local disk.** There are no real cloud
credentials available in this environment, so `aws-us-east-1`,
`azure-westus`, and `private-cloud` are all local directories addressed
through the same `StorageProvider` interface a real S3/Blob/GCS backend
would implement. What's real is the *shape*: fan-out replication and
failover-on-read, exercised by `phantom providers outage` and covered by
`tests/test_storage.py`.

**Sanitization is heuristic, not a production AV/ML engine.** `phantom/sanitize.py`
runs four rules against restored data before it's mounted into the fresh
instance — a known-bad-hash blocklist, suspicious-filename patterns,
magic-byte-vs-extension mismatch detection, and a Shannon-entropy check for
files claiming to be plain text. Quarantined files are moved to
`quarantine/<batch>/` with a findings manifest rather than silently
dropped, for operator review. There's no substitute here for real
signature/behavioral detection engines — what Phase 2 delivers over Phase
1's two-check placeholder is the pipeline shape (pluggable rules, severity,
a persisted quarantine store) that a real engine plugs into.

## What's deliberately out of scope (Phase 3+)

- Real VM/container/hypervisor drivers (KVM/QEMU, cloud) — §5.K.
- The full multi-cloud control plane (identity, network restoration, audit
  logging normalized across providers) — §5.K; only the storage slice ships here.
- AI-vs-AI behavioral detection, forensic vault, deception layer, threat-intel
  feed, enterprise integrations (SIEM/EDR hooks, compliance) — Phases 3-4.

## Quick start

Stdlib only, no dependencies, no install required.

```bash
cd project-phantom

# 1. Stand up the baseline image + a fresh instance
python3 -m phantom init

# 2. Simulate normal usage: user files land in the instance, get snapshotted
#    (replicated across all three storage providers automatically)
python3 -m phantom write notes.txt "quarterly numbers"
python3 -m phantom snapshot
python3 -m phantom write budget.csv "1,2,3"
python3 -m phantom snapshot

# 3. Simulate a dormant-malware-style compromise
python3 -m phantom attack

# The next interval snapshot fires before anyone notices -- it captures the
# attacker's payload too, which is exactly why restore has to go through
# the sanitize gate rather than trusting "latest snapshot" blindly.
python3 -m phantom snapshot

# 4. Manually trigger regeneration and see the RTO/RPO report
python3 -m phantom regen --reason "manual trigger: ransomware indicators"

# 5. Inspect instance state / storage providers / policy / audit trail
python3 -m phantom status
```

### Scheduled / ephemeral regeneration (Phase 2 headline feature)

Moving-target defense that doesn't depend on any attack being detected:

```bash
# Daily cadence: regenerate on a schedule regardless of attack status.
# (86400s = 24h by default; shorten it for a demo.)
python3 -m phantom policy set daily --interval-seconds 5
python3 -m phantom scheduled-run     # due immediately (never regenerated before)
python3 -m phantom scheduled-run     # no-op, interval hasn't elapsed
# ... wait 5s ...
python3 -m phantom scheduled-run     # due again

# `scheduled-run` is meant to be invoked by cron/systemd-timer in a real
# deployment; it's a no-op unless the daily interval has actually elapsed.

# Per-session cadence: regenerate at every session boundary.
python3 -m phantom policy set per_session
python3 -m phantom session start     # regenerates first, then "logs in" to a clean instance
```

### Multi-region failover

```bash
python3 -m phantom providers status
python3 -m phantom providers outage aws-us-east-1 down
python3 -m phantom regen --reason "demo: failover"   # still succeeds via the other two providers
python3 -m phantom providers outage aws-us-east-1 up
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
    storage.py          # StorageProvider abstraction + multi-region failover
    backup_store.py       # named storage providers (aws/azure/private-cloud stand-ins)
    sanitize.py             # restore-time scanning pipeline + quarantine store
    policy.py                 # scheduled/ephemeral regeneration cadence (daily, per-session)
    instance.py                 # disposable-instance driver (local workspace)
    metrics.py                    # RTO/RPO timing + audit log
    orchestrator.py                 # ties it together: PhantomInstance facade
    cli.py                            # `python3 -m phantom ...`
  tests/
    test_snapshot.py
    test_storage.py
    test_sanitize.py
    test_policy.py
    test_e2e.py
```
