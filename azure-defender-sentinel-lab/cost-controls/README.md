# Cost controls

Two guardrails for the lab:

1. **30-minute auto-deallocate** — every VM deallocates 30 minutes after it
   starts, so an idle (or forgotten) lab stops billing compute quickly.
2. **$25 budget email alert** — emails `ed.cleveland@3ch3lon.com` and
   `escleveland@outlook.com` when spend reaches 90% and 100% of $25, and when
   forecast spend is projected to hit 100%.

## Apply both (from your Mac)

```bash
cd azure-defender-sentinel-lab/cost-controls
./apply-cost-controls.sh
```

Options:

```bash
DELAY_MINUTES=45 BUDGET=50 ./apply-cost-controls.sh   # different timer / amount
./apply-cost-controls.sh --budget-only
./apply-cost-controls.sh --shutdown-only
```

## How the 30-minute shutdown works

- It **deallocates**, not just shuts down. An in-guest `shutdown` leaves the VM
  in the *Stopped* state, which **still bills for compute**; only *Stopped
  (deallocated)* stops the compute meter. This kit deallocates.
- Each VM's **system-assigned managed identity** is granted **Virtual Machine
  Contributor on itself**, then a scheduled task (`LabAutoDeallocate`) is
  installed that calls the deallocate REST API on the VM. It fires once for the
  current session and again at every future boot + 30 min.
- It is a **flat timer, not CPU-idle detection** — a VM you are actively using
  is still deallocated at the 30-minute mark. That matches "shut down after 30
  minutes of use or idle time." To allow longer working sessions, raise
  `DELAY_MINUTES`. For true idle-based shutdown (keep running while CPU is busy),
  see the note below.

### Restarting after an auto-deallocate

```bash
az vm start -g rg-mdlab -n WIN11-01     # or DC01, SRV01, etc.
```
The 30-minute timer re-arms on each start.

### Disable the timer on a VM

```bash
az vm run-command invoke -g rg-mdlab -n WIN11-01 --command-id RunPowerShellScript \
  --scripts "Unregister-ScheduledTask -TaskName LabAutoDeallocate -Confirm:\$false"
```

## How the budget works

`budget.bicep` creates a subscription **Consumption budget** of $25/month with
three email notifications (actual 90%, actual 100%, forecast 100%) to both
addresses. Deployed with:

```bash
az deployment sub create --location eastus \
  --template-file budget.bicep --parameters startDate=$(date -u '+%Y-%m-01')
```

Budgets are **informational** — they email, they do not stop spend. The
auto-deallocate is what actually caps the burn. To make the budget *act*
(e.g. deallocate everything at 100%), wire its notification to an action group
that triggers a runbook; ask and I'll add it.

Change recipients by editing `contactEmails` in `budget.bicep` and re-running.

## Relationship to the existing daily shutdown

The lab template already sets a **daily** DevTest auto-shutdown (19:00 UTC).
That stays as a backstop; this 30-minute timer is the tight guardrail on top of
it. Both deallocate.

## True idle-based shutdown (optional, heavier)

If you want "stop only when genuinely idle" rather than a flat 30-minute cap, the
approach is a metric alert on average CPU (e.g. < 5% for 30 min) wired to an
action group that deallocates the VM. That needs a per-VM alert rule + action
group + an automation target. Say the word and I'll build it as an alternative
to the flat timer.
