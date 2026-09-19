# Defender AV baseline + ASR rules (audit mode)

Applies, via **Group Policy** on DC01, a Microsoft Defender Antivirus baseline
and all **Attack Surface Reduction (ASR) rules in AUDIT mode** to the lab's
servers and Windows 11 workstations.

Group Policy is used because the machines are AD domain-joined (not yet enrolled
in Intune). Once Intune enrollment is done (see `../intune/`), the same settings
can move to Intune Endpoint Security policies — ask and I'll generate those too.

## What it sets

**Antivirus baseline (protective, on all targets):**
- Real-time, behavior, script, and downloaded-file scanning ON
- Cloud protection (MAPS Advanced) + sample submission
- Cloud block level High
- PUA protection ON

**Audit-mode (log-only, non-blocking):**
- Network Protection → Audit
- All 16 ASR rules → Audit

Audit mode records what each rule *would* block, in Defender's Operational event
log and the lab's endpoint DCR (the `Event` table in Sentinel), without blocking
anything — so you can watch impact before enforcing.

## Targets

| GPO | Linked to | Covers |
|---|---|---|
| `Lab - Defender Baseline - Servers (Audit)` | `OU=Servers,OU=Lab` + Domain Controllers OU | SRV01, DC01 |
| `Lab - Defender Baseline - Workstations (Audit)` | `OU=Workstations,OU=Lab` | WIN11-01/02/03 |

The script also **moves** SRV01 into `OU=Servers` and the clients into
`OU=Workstations` (they domain-joined into the default Computers container),
so the GPOs actually apply. DC01 stays in the Domain Controllers OU; the servers
GPO is additionally linked there to cover it.

## Deploy (from your Mac)

```bash
cd azure-defender-sentinel-lab/defender-policy
./deploy-defender-policy.sh
```

It runs the GPO script on DC01, forces a policy refresh on each member, and
prints the ASR rule states on WIN11-01. In the output, action codes are:
**2 = AuditMode, 1 = Block, 0 = Off** — all rules should read `2`.

## Verify

```bash
# ASR rules and their mode on any client (from your Mac)
az vm run-command invoke -g rg-mdlab -n WIN11-01 --command-id RunPowerShellScript \
  --scripts "(Get-MpPreference).AttackSurfaceReductionRules_Actions"

# Overall Defender status
az vm run-command invoke -g rg-mdlab -n SRV01 --command-id RunPowerShellScript \
  --scripts "Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled,IsTamperProtected"
```

Audit events show up in KQL (Sentinel → Logs):

```kql
Event
| where Source == "Microsoft-Windows-Windows Defender"
| where EventID in (1121,1122,1125,1126)   // 1122/1126 = ASR/NP audited (would-block)
| summarize count() by Computer, EventID
```

## Enforce later

When you're happy with the audit impact, flip everything to blocking:

```bash
MODE=Block ./deploy-defender-policy.sh
```

That rewrites the same GPOs with ASR + Network Protection set to Block (1) and
re-links nothing new. Revert by re-running without `MODE=Block`.

## Notes

- ASR needs Defender real-time protection on (the baseline enables it) and, for
  a couple of rules, cloud protection (also enabled here).
- New audit events appear after `gpupdate` + the next relevant activity; some
  ASR rules only log when the matching behavior occurs.
- These are the same rule GUIDs the lab's `Set-LabTelemetry.ps1` set locally at
  build time; this replaces that per-machine config with managed GPO so it stays
  applied and consistent.
