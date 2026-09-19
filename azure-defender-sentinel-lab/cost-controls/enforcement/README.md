# Enforcement automation

Two things the basic budget + flat-timer can't do on their own:

- **Budget *enforcement*** — a budget only emails. `Enforce-Budget` actually
  **deallocates every VM when month-to-date spend reaches $25**.
- **True idle shutdown** — `Stop-IdleVms` deallocates a VM only when its **average
  CPU has been below a threshold** for the last 30 minutes, so a VM you're
  actively using keeps running (unlike the flat 30-minute timer).

Both run as scheduled PowerShell runbooks in one **Azure Automation account**,
authenticating with the account's **system-assigned managed identity** and acting
over REST (no Az-module import, no action-group/webhook wiring).

## Deploy (from your Mac)

Push the branch first (the runbook bodies are pulled from raw GitHub), then:

```bash
cd azure-defender-sentinel-lab/cost-controls/enforcement
./deploy-enforcement.sh
```

Overrides:

```bash
BUDGET=50 IDLE_CPU=3 IDLE_WINDOW=30 ./deploy-enforcement.sh
```

It deploys the Automation account + runbooks + schedules, grants the identity
**Virtual Machine Contributor** and **Monitoring Reader** on the resource group
(in the Bicep) and **Cost Management Reader** on the subscription (in the script).

## What runs, when

| Runbook | Schedule | Action |
|---|---|---|
| `Enforce-Budget` | hourly | If MTD actual cost ≥ `$25`, deallocate all lab VMs. |
| `Stop-IdleVms` | every 30 min (two offset hourly schedules) | Deallocate each running VM whose avg CPU < `5%` over the last 30 min. |

## Choosing your shutdown model

You now have **two** ways to stop idle spend — pick per how you work:

- **Flat 30-minute timer** (`../apply-cost-controls.sh`) — deallocates every VM 30
  min after start, busy or not. Strictest.
- **Idle-based** (`Stop-IdleVms` here) — keeps busy VMs alive, stops only genuinely
  idle ones.

Running **both** means the flat timer wins (it ignores activity). If you want
active sessions to survive, use idle-based and **disable the flat timer**:

```bash
for c in DC01 SRV01 WIN11-01 WIN11-02 WIN11-03; do
  az vm run-command invoke -g rg-mdlab -n $c --command-id RunPowerShellScript \
    --scripts "Unregister-ScheduledTask -TaskName LabAutoDeallocate -Confirm:\$false"
done
```

`Enforce-Budget` is independent of both and should stay on regardless.

## Verify / operate

```bash
# Automation account + runbooks
az automation runbook list -g rg-mdlab --automation-account-name mdlab-automation -o table

# Recent job runs
az automation job list -g rg-mdlab --automation-account-name mdlab-automation -o table
```

Run one on demand to test: **Portal → Automation account `mdlab-automation` →
Runbooks →** pick one **→ Start**. Its output stream shows the cost figure or the
per-VM CPU readings and any deallocate it issued.

## Notes and caveats

- **Cost data lags.** Azure actual-cost is not real-time (often hours behind), so
  `Enforce-Budget` is a backstop, not an instant cutoff. The flat timer / idle
  shutdown are what keep normal spend down; this stops a runaway before it grows.
- **Currency** is assumed USD. If your billing currency differs, the threshold is
  in that currency.
- **Schedules start ~1 hour out** (Automation requires a future start). The first
  idle/budget check therefore runs within the first hour after deploy; start a
  runbook manually if you want an immediate pass.
- These runbooks deallocate; restart with `az vm start -g rg-mdlab -n <VM>`.
