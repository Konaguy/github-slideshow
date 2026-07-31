# Project Phantom — MVP Prototype (Phases 1–4)

Working code for the **Phase 1**, **Phase 2**, and (parts of) **Phase 3**
and **Phase 4** milestones of the Project Phantom charter (v0.2, 2026-07-29):

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
>
> **Phase 4: Deception & GA Hardening.** Honeypot migration module,
> threat-intel feed productization, chaos/resilience testing, customer
> pilots, compliance certification.

This is a runnable proof of the core regeneration loop, not a production
platform.

**Phases 3 and 4 are partially covered.** Everything that is code is built
and tested; what's missing needs infrastructure, customers, or an auditor
rather than more code:

| Deliverable | Status |
|---|---|
| §5.D detection · §5.F forensic vault · §5.H fleet immunity | built |
| §5.G deception / honeypot migration | built — default-denied, see below |
| Threat-intel productization · chaos/resilience testing | built |
| Serverless · multi-hypervisor · cross-cloud orchestration | **not built** — needs real hypervisors and cloud credentials |
| Customer pilots | **not built** — needs customers |
| Compliance *certification* | **not built** — that's an audit, not a program. Evidence *reporting* is built |

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
| G. Deception Layer (optional) | `phantom/deception.py` — migrates a compromised workload into a quarantined honeypot so the attacker keeps working against a decoy while the real instance regenerates, harvesting TTPs as hashes/metadata. **Default-denied**: requires customer opt-in, a recorded legal review, *and* a jurisdiction counsel has cleared. |
| I. Vulnerability Scanning & Patch QA (parallel track) | `.github/workflows/phantom-patch-qa.yml` — CI pipeline that runs the regression test suite on every push, standing in for the QA-bot regression gate. |
| J. Enterprise Integration (compliance slice) | `phantom/compliance.py` — control-evidence report built from the audit log, vault, and policy state. Reports gaps as loudly as coverage. Explicitly **not** a certification. |
| K. Multi-Cloud Control Plane (initial, storage only) | `phantom/storage.py` — a `StorageProvider` interface with named providers standing in for AWS/Azure/private-cloud, fan-out replication on write, and failover on read. Phase 2 scope is explicitly "initial... abstraction," not the full control plane. |

**Single VM, not a fleet.** The "instance" the orchestrator drives is a
workspace directory (`InstanceDriver` in `phantom/instance.py`), not a real
VM/container/hypervisor. Earlier revisions of this README called that
interface "the seam cloud drivers plug into" — **that was wrong**, and the
[Compute drivers](#compute-drivers--and-a-correction) section below explains
why and what replaced it. The usable seam is `phantom/drivers/`.

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

**The deception layer is off, and it is meant to stay off until someone
decides otherwise.** The charter marks it "(optional)," makes it opt-in
per customer with legal review required (§8), and flags legal exposure as
a live risk (§9). So `DeceptionPolicy` is default-deny and needs three
independent conditions: the module enabled, a recorded legal-review
acknowledgement naming who signed off, and the operating jurisdiction
present in an allowlist. **That allowlist ships empty and this code has no
built-in opinion about which jurisdictions permit deception, retaining an
intruder's session, or harvesting their tooling** — those turn on local
law, customer contracts, and the deployment, and a guess encoded here
would be invented legal advice someone might rely on. Counsel fills it in.
Only attack-triggered rebuilds are eligible; scheduled/ephemeral rebuilds
never migrate, because cloning an ordinary desktop nightly is surveillance
rather than deception. Scope is containment and observation of a workload
the customer already owns — it never reaches back toward whoever is on the
other end, and it should not grow in that direction.

**The compliance report is audit input, not compliance.** Running it
doesn't make a deployment compliant; certification is an audit performed
by a licensed firm over a defined observation period. The control mapping
is a starting point for a conversation with an auditor, not a validated
mapping, and the report lists what's missing (including that Phantom's own
audit log isn't tamper-evident, unlike the forensic vault) as prominently
as what's present.

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
- Customer pilots (§6 Phase 4) and compliance *certification* — neither is
  a programming task.
- Real network isolation for the honeypot sandbox, a believable synthetic
  decoy environment, and the §10 open question of building deception
  in-house versus partnering with a honeypot vendor.
- Real cryptographic signing of intel bundles (the current integrity digest
  is a checksum, not a provenance claim), plus authenticated distribution,
  subscriber identity, and billing.
- Enterprise integrations: SIEM/EDR hooks, Kubernetes/vSphere APIs,
  dashboards (§5.J).

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

### Deception layer (Phase 4, §5.G) — opt-in, default off

```bash
python3 -m phantom deception status
```

```
Deception DENIED:
  - deception module is not enabled for this customer (opt-in required, §8)
  - no legal/risk review acknowledgement on record (§8, §9)
  - no operating jurisdiction declared
```

Opting in is deliberately *not* sufficient — counsel must clear the
jurisdiction as a separate act:

```bash
python3 -m phantom deception enable --jurisdiction EXAMPLE-1 --reviewed-by counsel@example.com
# -> still DENIED: jurisdiction 'EXAMPLE-1' is not in the allowlist (empty)

python3 -m phantom deception enable --jurisdiction EXAMPLE-1 \
    --reviewed-by counsel@example.com --permit-jurisdiction EXAMPLE-1
# -> Deception permitted
```

With it permitted, an attack-triggered rebuild clones the compromised
workload into the sandbox and harvests TTPs, while the real instance
recovers clean:

```bash
python3 -m phantom detect-and-respond
python3 -m phantom deception ttps
```

```
9884ecae60f4b3a2...  RANSOM_NOTE_README.txt  47B  observed=2026-07-30T16:02:31Z
19179b447359df6d...  invoice.pdf.exe  21B  observed=2026-07-30T16:02:31Z
```

Harvested hashes can be pushed to the fleet feed via
`publish_harvested_ttps()`, closing §5.G into §5.H.

### Threat-intel productization (Phase 4)

```bash
python3 -m phantom intel export --tier intel --out bundle.json
python3 -m phantom intel verify bundle.json
python3 -m phantom intel revoke <content-hash>   # excluded from future exports
```

Bundles are versioned, TTL-filtered, revocation-filtered, and tiered
(`intel` gets full history, `community` a 7-day window). `verify` detects
corruption or modification in transit — but see the caveat above: the
digest is a checksum, **not** proof of who issued the bundle.

### Chaos / resilience testing (Phase 4)

```bash
python3 -m phantom chaos run --seed 7
```

```
[PASS] provider_outage: regenerated with provider 'aws-us-east-1' unavailable
[PASS] majority_provider_outage: regenerated with only 1 of 3 providers reachable
[PASS] attack_then_outage: regenerated from a compromised snapshot with a region down
[PASS] baseline_drift: regeneration correctly refused to spawn from a drifted baseline
[PASS] vault_tampering_detected: custody chain flagged post-capture evidence tampering
[PASS] random_multi_outage: regenerated with ['aws-us-east-1', 'azure-westus'] unavailable

6/6 scenarios passed
```

Each scenario injects a fault, runs a real regeneration, and asserts the
invariants that must survive it: recovery completes, RTO/RPO stay inside
the §4 targets, clean data returns, nothing quarantined gets restored, and
the custody chain still verifies. Note `baseline_drift` passes by
*refusing* to regenerate — spawning from a tampered baseline would be the
failure.

### Compliance evidence (Phase 4, §5.J)

```bash
python3 -m phantom compliance report --out compliance.json
```

Reports which controls have evidence in the audit log and which don't, and
lists the gaps an auditor will raise — including that Phantom's own audit
log has no hash chain. It is **not** a certification; see the caveat above.

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

## Compute drivers — and a correction

`phantom/drivers/` is a provider-agnostic contract that can express both a
local workspace and a real cloud VM, with a shared conformance suite both
implementations must pass.

**It exists because the old claim was wrong.** This README described
`InstanceDriver` (in `phantom/instance.py`) as "the seam Phase 3's cloud
drivers plug into" from Phase 1 onward. It is not, and cannot be:

```python
def spawn_from_baseline(self, baseline_dir: Path, ...) -> None
@property
def data_dir(self) -> Path
```

Both signatures are filesystem-shaped. A cloud baseline is an AMI id, not
a `Path`; a remote VM has no local `data_dir`. Implementing that Protocol
for EC2 would require lying about the return types. The new contract uses
opaque references and handles instead, and puts snapshot/restore *on the
driver* — because on a real VM, data moves via EBS/Managed Disk snapshots
taken from outside the guest, not by reading a local directory.

That last point matters beyond tidiness: **EBS and Azure Managed Disk
snapshots are already block-level incremental**, which is the fix for the
12,288x write amplification the benchmark measured. Delegating to provider
primitives may make writing our own chunking unnecessary — worth settling
before building it.

### The destroy guard

Phantom's core loop is *programmatically terminating machines on a timer*.
A scheduler bug here doesn't produce a wrong answer, it deletes
infrastructure. So `destroy()` re-reads the target's tags **from the
provider API** and refuses anything not carrying `phantom:managed=true`.

This is deliberately redundant with IAM. IAM is the control that *should*
stop it, but tag-condition policies are easy to get subtly wrong, and this
costs one API call. Tests cover an untagged EC2 instance named
`prod-database` surviving a destroy attempt, and a *forged handle* that
claims Phantom ownership in its own metadata being refused anyway — a
handle is a local object and is never authoritative.

### Verification status — read this before trusting it

The EC2 driver is verified against **`moto`**, not a real account. There
are no cloud credentials in this repo or its CI.

- **Verified:** call sequencing, tag propagation, the destroy guard, error
  shapes, `exists` not raising on a vanished instance.
- **Not verified:** real IAM behaviour, latency, eventual consistency on
  tag reads, service quotas, or whether a restored volume actually boots.

`EC2Driver.restore` is explicitly incomplete: it creates a volume from the
snapshot and attaches it, but a production restore also stops the
instance, detaches the old root volume, and reattaches at the right device
name. That sequence depends on state transitions moto models only
approximately, so verifying it here would manufacture false confidence.

**The orchestrator still uses the old `phantom/instance.py`.** Wiring it
onto this contract is a separate change with real blast radius across the
existing suite.

## Admin console (§5.J)

```bash
python3 -m phantom dashboard render --out console.html
```

Renders a self-contained HTML console from real instance state: §4 RTO/RPO
tiles, recovery history, storage-provider health, the forensic vault with
its chain-verification result, the quarantine review queue, compliance
evidence, and the audit trail. No dependencies, no external requests, no
JavaScript; light and dark are separately stepped, not an inverted flip.

**It is a point-in-time render, not a live console.** There is no server
and no auto-refresh — the header timestamp says when it was generated.

**Escaping is load-bearing, not hygiene.** This page displays strings the
*attacker* chose: quarantined filenames come from the blocked payload, and
the audit log quotes them back. A filename is an injection vector into the
console an incident responder reads during a live incident, so every
interpolated value goes through `esc()` and `tests/test_dashboard.py`
asserts a `<img src=x onerror=...>` filename renders inert.

**No authentication, authorization, or multi-tenancy** — whoever can run
the command renders every case in the vault. That's why it ships as a file
you generate rather than a service you expose, and it's one of the gaps
between this prototype and anything pilot-ready.

Sections with no underlying data say so ("No regenerations recorded yet")
rather than showing a plausible-looking zero — a fresh instance must not
display a passing `0.00s` RTO it never achieved.

## Scale benchmark — and what it found

Charter §9 lists **"Snapshot overhead at scale"** as a High-impact risk
mitigated by "incremental snapshots, tiered intervals, **early
benchmarks**." `phantom/benchmark.py` is that benchmark.

```bash
python3 -m phantom benchmark run --scale small     # seconds
python3 -m phantom benchmark run --scale medium    # ~4 min, writes ~7GiB
```

It exits non-zero when a §4 target is missed, so it can gate CI later.

### Finding 1 — file-level snapshots cannot meet the §4 overhead target

§5.A specifies **block-level** thin deltas. This prototype snapshots at
*file* granularity, and the benchmark quantifies what that costs. Measured
at `--scale medium` (100 files × 16MiB = 1.6GiB, ten 4KiB edits per round):

| Metric | Measured | §4 target |
|---|---|---|
| write amplification | **12,288x** | — |
| CPU duty cycle @30s interval | **30.2%** | < 5% |
| bandwidth | **134.2%** of a 100 Mbps uplink | < 5% |
| RTO | 19.4s | < 5 min ✅ |

40KiB of real user change produces **480MiB of writes per snapshot**. The
12,288x decomposes cleanly: 4096x because a 4KiB edit rewrites its whole
16MiB file, times 3x for replication to three providers. At 134% of the
uplink the pipeline cannot ship one snapshot per interval — it falls
permanently behind.

Even the benign workload (20,000 × 8KiB, full-file rewrites, no
granularity penalty) lands at 6.5% CPU and 6.6% bandwidth — still over.

**So block-level granularity is a prerequisite, not an optimization.**
Content-defined chunking (or any sub-file delta scheme) is what makes §4
reachable; no amount of faster storage substitutes, because the bytes are
being generated before they ever reach storage.

Two honest caveats on the numbers: the 3x replication factor is a
deliberate design choice, not a defect, and it sets a hard floor on
bandwidth — a real deployment may replicate to fewer regions
synchronously. And RTO passes comfortably here only because restore reads
from local disk; 1.6GiB over a 100 Mbps link is ~2.2 min, still inside the
5-minute target but with far less headroom than 19s suggests.

### Finding 2 — an O(n) defect in the snapshot chain (found, fixed)

`take_snapshot` called `list_snapshots()`, parsing **every** manifest in
the chain to get two things: the chain length and the parent's id. Cost
therefore scaled with history — and the chain grows by one every 30–60s,
forever.

| Chain length | `take_snapshot` before | after |
|---|---|---|
| 1 | 74.6ms | 69.2ms |
| 100 | 134.8ms | 69.9ms |
| 200 | 196.3ms | 71.5ms |

By snapshot 200 — under two hours of operation — manifest re-parsing was
~60% of snapshot cost and still climbing. A day is ~2,880 snapshots. Both
values are available from manifest *filenames*, so the fix parses nothing;
cost is now flat. `tests/test_benchmark.py` guards it structurally (by
asserting no manifest is parsed) rather than by timing, so it can't go
flaky in CI.

A five-round benchmark showed this as "1.02x, flat" and missed it
entirely — the defect only appears when chain length is varied
independently of data size, which is what `measure_chain_scaling` does.

### What the numbers do and don't transfer

Storage is local disk, so **absolute latency does not transfer** — real
object storage adds a network round-trip per blob and would be slower.
What transfers is everything that's a property of the algorithm rather
than the medium: write amplification, CPU per snapshot, and cost growth
with chain length. Read wall-clock figures as a floor, not a forecast.
The 100 Mbps uplink in `NOMINAL_UPLINK_MBPS` is a stated assumption, not a
measurement — the charter doesn't specify one.

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
    deception.py                      # default-deny gate + quarantined honeypot (§5.G)
    intel_export.py                     # subscriber bundles: TTL, revocation, tiers
    chaos.py                              # fault injection + recovery invariants
    compliance.py                           # control-evidence report (NOT certification)
    dashboard.py                              # admin console: self-contained HTML (§5.J)
    drivers/                                    # provider-agnostic compute contract
      base.py                                     #   contract + destroy guard + conformance suite
      local.py                                    #   local-workspace driver
      aws.py                                      #   EC2 driver (moto-verified, not live-tested)
    benchmark.py                              # scale benchmark for snapshot/restore (§9 top risk)
    instance.py                               # disposable-instance driver (local workspace)
    metrics.py                                  # RTO/RPO timing + audit log
    orchestrator.py                               # ties it together: PhantomInstance facade
    cli.py                                          # `python3 -m phantom ...`
  tests/
    test_snapshot.py     test_detection.py    test_deception.py
    test_storage.py      test_forensics.py    test_intel_export.py
    test_sanitize.py     test_fleet.py        test_chaos.py
    test_policy.py       test_e2e.py          test_compliance.py
                                              test_benchmark.py
                                              test_dashboard.py
                                              test_drivers.py
                                              test_drivers_aws.py
```
