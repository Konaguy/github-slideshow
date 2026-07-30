# Project Phantom — MVP Prototype (Phases 1–3)

Working code for the **Phase 1**, **Phase 2**, and (part of) **Phase 3**
milestones of the Project Phantom charter (v0.2, 2026-07-29):

> **Phase 1: MVP.** Single-VM proof: thin snapshots, cloud backup, manual
> trigger, demonstrated <5 min recovery. Patch/QA pipeline stood up in
> parallel.
>
> **Phase 2: Ephemeral First.** Scheduled regeneration ships before
> automated detection. Moving-target value doesn't depend on detection
> accuracy. Data sanitization layer ships here (required for safe scheduled
> restores). Multi-region failover and initial multi-cloud storage
> abstraction.
>
> **Phase 3: Detection & Intelligence.** AI-vs-AI behavioral detection,
> forensic vault, fleet immunity propagation. *(Also serverless +
> multi-hypervisor support and cross-cloud regeneration orchestration —
> see the scope note below.)*

This is a runnable proof of the core regeneration loop, not a production
platform.

**Phase 3 is partially covered.** The three detection/intelligence
deliverables (§5.D, §5.F, §5.H) are implemented and tested. The
infrastructure half of Phase 3 — serverless and multi-hypervisor support,
cross-cloud regeneration orchestration against real AWS/Azure/GCP targets —
is *not*, because it needs real hypervisors and cloud credentials rather
than more code. Phase 4 (deception layer, threat-intel productization,
compliance certification) is untouched.

## What's implemented (maps to charter §5)

| Charter item | This prototype |
|---|---|
| A. Real-Time Snapshot Engine | `phantom/snapshot.py` — content-addressed, thin/incremental snapshots of the instance data directory. Only changed blobs are written; unchanged files are deduplicated by hash. |
| B. Cloud Backup & Versioning | `phantom/backup_store.py` — snapshots replicated across named storage providers (see §5.K below); versioned snapshot chain; dedup comes free from content addressing. |
| C. Regeneration & Spawn Orchestration | `phantom/orchestrator.py` — destroy the instance, spawn fresh from the immutable baseline, restore the latest sanitized data snapshot. Two trigger modes, per §5.C: manual/attack-triggered (`regen`) and scheduled/ephemeral (`scheduled-run`, `session start`). |
| D. AI-vs-AI Detection Engine | `phantom/detection.py` — scores inter-snapshot behavioral drift (mass rewrite, mass deletion, entropy spike, suspicious arrivals) and auto-triggers regeneration above a threshold. Consumes the snapshot engine's own manifests, so detection and snapshots genuinely share one pipeline per §5.A/§5.D. |
| E. Data Sanitization Layer | `phantom/sanitize.py` — a multi-signal restore-time scanning pipeline (see below). This is the Phase 2 gate the risk register calls "not optional." |
| F. Forensic Vault | `phantom/forensics.py` — hash-chained, append-only evidence vault with chain-of-custody metadata. Each entry commits to the one before it, so tampering with stored artifacts *or* the ledger is detectable via `phantom vault verify`. |
| H. Fleet Immunity & Threat-Intel Feed | `phantom/fleet.py` — a shared indicator feed. When one instance detects an attack it publishes content hashes (anonymized: hash + coarse label only, never contents or paths, opt-in per §9); other instances pull them and harden pre-emptively. |
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

**"AI-vs-AI" is a weighted heuristic here, not a trained model.** The
charter's §5.D engine is a behavioral model trained per machine;
`phantom/detection.py` is a hand-tuned signal scorer. What's real is the
interface a trained model would sit behind (`evaluate(previous, current)`
→ score + the signals that produced it) and the shared data pipeline —
it reads the same snapshot manifests the snapshot engine writes, no
separate agent. It keys on the *shape* of an attack delta rather than any
specific payload, and a real deployment would also weigh process,
network, and identity signals (§1.1 step 1) that this file-level prototype
never sees. Thresholds are tuned to avoid the obvious false positive:
a bulk rewrite with no entropy change (a formatter, a sync) stays below
the trigger, and percentage-based signals are suppressed entirely below
5 files, since "50% of your 2 files changed" is noise.

**The forensic vault is an integrity ledger, not a legal chain of custody.**
Hash-chaining makes tampering *detectable*, which is the property Phases
1–2 lacked. Genuinely defensible evidence additionally needs WORM storage
with independent access control (this writes to the same local disk as
everything else), signed timestamps from a trusted authority rather than
local clock reads, and per-custodian cryptographic signatures rather than
a name string. Those are deployment/PKI concerns; the ledger format is
what they'd attach to.

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

## What's deliberately out of scope

- Real VM/container/hypervisor drivers (KVM/QEMU, cloud), serverless and
  multi-hypervisor support, cross-cloud regeneration orchestration — the
  infrastructure half of Phase 3 (§5.K). Needs real hypervisors and cloud
  credentials, not more code.
- The full multi-cloud control plane (identity, network restoration, audit
  logging normalized across providers) — §5.K; only the storage slice ships here.
- Deception layer / honeypot migration (§5.G), threat-intel feed
  productization, chaos testing, compliance certification — Phase 4.
- Enterprise integrations: SIEM/EDR hooks, Kubernetes/vSphere APIs,
  dashboards, SOC 2 evidence (§5.J).

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

### Behavioral detection and automatic response (Phase 3, §5.D)

Detection works on the *shape* of the change, so it catches an attack that
plants no known-bad file and drops no ransom note:

```bash
# Ordinary editing does not trigger anything.
python3 -m phantom write doc1.txt "revised text"
python3 -m phantom snapshot
python3 -m phantom detect          # -> No behavioral drift detected (score 0.00)

# Ransomware encrypts files in place; the next interval snapshot captures it.
python3 -m phantom attack --mode encryption
python3 -m phantom snapshot
python3 -m phantom detect-and-respond
```

```
ANOMALY: score 1.00 (threshold 0.50)
  [mass_rewrite +0.40] 6/6 existing files rewritten in one interval
  [entropy_spike +0.70] 6 file(s) jumped >= 2.0 bits/byte entropy (e.g. doc1.txt); consistent with in-place encryption

Regeneration complete: reason=detection: behavioral drift score 1.00
  RTO: 0.006s  (target < 300s)   PASS
  RPO: 1.045s  (target < 60s)    PASS
  files restored: 6   quarantined: 0
  evidence preserved: forensic_vault/CASE-20260730T154849Z-0000
```

Recovery deliberately restores from the snapshot *before* the anomalous
one — the latest snapshot is the attacker's work.

### Forensic vault and chain of custody (Phase 3, §5.F)

```bash
python3 -m phantom vault list      # cases with custodian, reason, digests
python3 -m phantom vault verify    # recomputes the chain + re-hashes artifacts
```

Editing anything in the vault after the fact is detected:

```
CHAIN OF CUSTODY COMPROMISED:
  entry 0 (CASE-20260730T154849Z-0000): artifacts do not match recorded digest (tampered)
```

### Fleet immunity (Phase 3, §5.H)

Point several instances at one shared feed to form a fleet. An attack on
one hardens the others:

```bash
FEED=/tmp/fleet/shared_intel.jsonl

# VM A is attacked and responds, publishing indicators to the feed.
python3 -m phantom --root /tmp/fleet/vm_a --feed $FEED --instance-id phantom-vm-a detect-and-respond

# VM B was never attacked, but learns from A and hardens pre-emptively.
python3 -m phantom --root /tmp/fleet/vm_b --feed $FEED --instance-id phantom-vm-b fleet show
python3 -m phantom --root /tmp/fleet/vm_b --feed $FEED --instance-id phantom-vm-b fleet pull
# -> Learned 2 new indicator(s) from the fleet feed
```

The same payload arriving at VM B is now quarantined on restore, despite
VM B never having seen it before. Sharing is opt-in
(`detect-and-respond --no-share-intel`) per the §9 privacy mitigation;
opting out of *contributing* never disables *protection*.

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
    detection.py                # inter-snapshot behavioral drift scoring (§5.D)
    forensics.py                  # hash-chained evidence vault + chain of custody (§5.F)
    fleet.py                        # shared threat-intel feed / herd immunity (§5.H)
    instance.py                       # disposable-instance driver (local workspace)
    metrics.py                          # RTO/RPO timing + audit log
    orchestrator.py                       # ties it together: PhantomInstance facade
    cli.py                                  # `python3 -m phantom ...`
  tests/
    test_snapshot.py
    test_storage.py
    test_sanitize.py
    test_policy.py
    test_detection.py
    test_forensics.py
    test_fleet.py
    test_e2e.py
```
