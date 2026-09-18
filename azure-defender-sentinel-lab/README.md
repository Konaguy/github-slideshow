# Microsoft Defender + Microsoft Sentinel Lab

Infrastructure-as-code for a small, self-contained Active Directory environment
wired end to end into **Microsoft Defender for Cloud / Defender for Endpoint**
and **Microsoft Sentinel**. Deploy it, generate some attacker noise, and watch
incidents show up.

## What gets built

| Machine    | OS                                   | Role                                   | Size (default)   |
|------------|--------------------------------------|----------------------------------------|------------------|
| `DC01`     | Windows Server 2022 Azure Edition    | Forest root DC + DNS (`lab.local`)     | Standard_D2s_v3  |
| `SRV01`    | Windows Server 2022 Azure Edition    | Domain-joined general-purpose server   | Standard_D2s_v3  |
| `WIN11-01` | Windows 11 Enterprise (24H2)         | Domain-joined workstation              | Standard_D2s_v3  |
| `WIN11-02` | Windows 11 Enterprise (24H2)         | Domain-joined workstation              | Standard_D2s_v3  |
| `WIN11-03` | Windows 11 Enterprise (24H2)         | Domain-joined workstation              | Standard_D2s_v3  |

Plus the surrounding platform:

- **VNet** `10.10.0.0/16` — `snet-lab 10.10.10.0/24`, `AzureBastionSubnet 10.10.250.0/26`
- **NAT Gateway** for outbound internet (required — see [Networking](#networking))
- **Azure Bastion** (Basic) for RDP; **no VM has a public IP**
- **Log Analytics workspace** onboarded to **Microsoft Sentinel**, 5 GB/day cap
- **Two Data Collection Rules** — Windows Security Events, and Sysmon / PowerShell / Defender
- **Defender for Cloud** — Defender for Servers **Plan 2** on the subscription
- **Sentinel data connectors** — Defender for Cloud alerts + Defender XDR incidents
- **Four starter analytics rules** — Kerberoasting, password spray, LSASS access, privileged-group changes

Each VM runs the **Azure Monitor Agent**, has **Sysmon** installed with the
SwiftOnSecurity config, and has advanced audit policy, command-line process
auditing, and PowerShell script-block logging turned on.

## Layout

```
azure-defender-sentinel-lab/
├── main.bicep                 # subscription-scope orchestration
├── main.bicepparam            # edit these values
├── deploy.sh                  # login, register providers, deploy (--what-if / --validate)
├── teardown.sh                # delete RG, purge workspace, revert Defender plans
├── modules/
│   ├── network.bicep          # VNet, NSG, NAT Gateway, Bastion
│   ├── workspace.bicep        # Log Analytics + Sentinel onboarding
│   ├── dataCollection.bicep   # the two DCRs
│   ├── vm.bicep               # one VM: NIC, AMA, DCRs, domain join, CSE, MDE, auto-shutdown
│   ├── dcReadyGate.bicep      # blocks members until the forest is serving
│   ├── defenderPlans.bicep    # Defender for Cloud pricing + MDE integration
│   ├── sentinelConnectors.bicep
│   └── analyticsRules.bicep
└── scripts/                   # pulled onto the VMs by the Custom Script Extension
    ├── Initialize-DomainController.ps1
    ├── Complete-DomainController.ps1
    ├── Initialize-LabEndpoint.ps1
    ├── Install-Sysmon.ps1
    └── Set-LabTelemetry.ps1
```

## Prerequisites

- **Azure CLI** with the Bicep tooling (`az bicep install`)
- An Azure subscription where you are **Owner** (needed for the subscription-level Defender plans)
- For the **Defender XDR connector**: **Security Administrator** or **Global Administrator** in Entra ID.
  If you do not have that, set `deployDefenderXdrConnector = false` in `main.bicepparam` and connect it
  from the portal later — the rest of the lab deploys fine without it.
- Quota for **10 vCPUs** of the `Dsv3` family in your region (5 × D2s_v3). Check with
  `az vm list-usage -l eastus -o table`.

## How the scripts reach the VMs

The VMs pull the PowerShell in `scripts/` at boot via the Custom Script
Extension, from the raw URL in the `scriptsBaseUri` parameter, which defaults to
this branch on GitHub:

```
https://raw.githubusercontent.com/konaguy/github-slideshow/refs/heads/claude/exciting-curie-806ybx/azure-defender-sentinel-lab/scripts/
```

If you fork, rename the branch, or work in a private repo, **update
`scriptsBaseUri`** (in `main.bicepparam` or with `--parameters`) to a location
the VMs can read anonymously — a public raw URL, or a storage blob with a SAS
token.

## Deploy

```bash
cd azure-defender-sentinel-lab

# Optional dry runs
./deploy.sh --validate
./deploy.sh --what-if

# Real thing (prompts for the two passwords and a confirmation)
./deploy.sh
```

You can also feed the passwords through the environment for an unattended run:

```bash
export LAB_ADMIN_PASSWORD='<12+ chars, 3 of 4 classes>'
export LAB_DSRM_PASSWORD='<different value>'
./deploy.sh
```

Or straight through the CLI without the wrapper:

```bash
LAB_ADMIN_PASSWORD=... LAB_DSRM_PASSWORD=... \
az deployment sub create \
  --name mdlab \
  --location eastus \
  --template-file main.bicep \
  --parameters main.bicepparam
```

**Expect 35–50 minutes.** The DC promotes and reboots, a run-command gate waits
until the forest is actually answering, and only then are `SRV01` and the
Windows 11 clients allowed to start joining. That ordering is deliberate — see
[Deployment ordering](#deployment-ordering).

## Post-deployment

### 1. Sign in

Portal → resource group `rg-mdlab` → **DC01** → **Connect → Bastion**, as
`LAB\labadmin` with the admin password. Same path for the other machines. There
are no public IPs; Bastion is the only inbound route.

### 2. Onboard the Windows 11 clients to Defender for Endpoint (manual, per-tenant)

This is the one step a template cannot do for you. Defender for Servers
auto-onboards `DC01` and `SRV01`, but the **Windows 11 clients are not servers**
and need a per-tenant onboarding package plus a Defender for Endpoint or
Defender for Business licence.

1. Go to <https://security.microsoft.com> → **Settings → Endpoints → Onboarding**.
2. OS: **Windows 10 and 11**, method: **Local Script**. Download the `.zip`.
3. Put it where the VMs can read it — e.g. upload to a storage blob and mint a short-lived SAS URL.
4. On each `WIN11-0x`, from an elevated PowerShell:

   ```powershell
   C:\LabSetup\Initialize-LabEndpoint.ps1 `
     -ScriptsBaseUri '<same scriptsBaseUri you deployed with>' `
     -Role Client `
     -MdeOnboardingPackageUri '<SAS URL to the onboarding zip>'
   ```

   The bootstrap script already ran once at deploy time without the package (so
   audit policy and Sysmon are in place); re-running it with the URL performs
   onboarding. Confirm with `Get-Service Sense` (should be **Running**).

   For a fleet, push the same package via Intune or a GPO instead.

### 3. Confirm telemetry is flowing

In **Sentinel → Logs**, after ~15–20 minutes:

```kql
SecurityEvent | summarize count() by Computer | order by count_ desc
Event | where Source == "Microsoft-Windows-Sysmon" | summarize count() by Computer
Heartbeat | summarize arg_max(TimeGenerated, *) by Computer   // all 5 machines should report
```

## Try the detections

The DC seeding script deliberately plants two weak accounts so the shipped
analytics rules have something to catch. **Only safe because the lab is
isolated** — never do this in a directory that matters.

- `svc_sql` — a user account carrying an SPN and a weak password → **Kerberoastable**
- `svc_backup` — Kerberos pre-authentication disabled → **AS-REP roastable**

From a domain-joined client, signed in as a domain user, a couple of harmless examples:

```powershell
# Trigger the Kerberoasting rule: request many RC4 service tickets.
setspn -T lab.local -Q */*    # enumerate SPNs
Add-Type -AssemblyName System.IdentityModel
'MSSQLSvc/srv01.lab.local:1433' | ForEach-Object {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_
}
```

```powershell
# Trigger the password-spray rule: one bad password against many accounts.
'jdoe','msmith','aroberts','pnguyen','svc_sql' | ForEach-Object {
    Start-Process -FilePath cmd.exe `
      -ArgumentList "/c net use \\srv01\IPC$ /user:lab\$_ WrongPassword123!" `
      -Wait -WindowStyle Hidden
}
```

Each scheduled rule runs hourly, so give it up to an hour, then look in
**Sentinel → Incidents**. For the LSASS rule, running a known credential-dumping
tool against `lsass.exe` on a client produces the Sysmon event 10 it keys on —
do that only with tooling you are authorised to run, and only in this lab.

## Cost and shutting down

This lab **is not free to leave running.** Rough list-price order of magnitude:

| Component                         | Ballpark                                          |
|-----------------------------------|---------------------------------------------------|
| 5 × D2s_v3 VMs                    | ~$0.10/hr each **while running** (auto-shutdown 19:00 UTC daily) |
| Managed disks (5 × 128 GB SSD)    | billed whether the VM runs or not                 |
| Azure Bastion (Basic)             | ~$0.19/hr (~$140/mo) as long as it exists         |
| Defender for Servers Plan 2       | ~$15 per protected server per month, billed hourly on protected servers |
| Log Analytics ingest              | first 10 GB/day is free tier–eligible; cap set to 5 GB/day |
| NAT Gateway                       | ~$0.045/hr + data processed                       |

Cost controls already in place: a **daily VM auto-shutdown** at 19:00 UTC, and a
**5 GB/day ingestion cap** on the workspace. To fully stop the meters:

```bash
./teardown.sh
```

That deletes the resource group, **purges** the Log Analytics workspace (so the
name frees up immediately instead of sitting soft-deleted for 14 days), and
**reverts the Defender for Cloud plans to Free**. Deleting the resource group
alone does **not** turn off the subscription-level Defender plan — the script does.

## Key parameters

All in `main.bicepparam`.

| Parameter                        | Default                              | Notes |
|----------------------------------|--------------------------------------|-------|
| `prefix`                         | `mdlab`                              | Name stem for every resource; also `rg-<prefix>` and `<prefix>-law` |
| `location`                       | `eastus`                             | Region |
| `adminUsername`                  | `labadmin`                           | Must not be a reserved name (`administrator`, `admin`, …) |
| `clientCount`                    | `3`                                  | Number of Windows 11 clients |
| `domainName` / `domainNetbiosName` | `lab.local` / `LAB`                | Forest root |
| `serverVmSize` / `clientVmSize`  | `Standard_D2s_v3`                    | Must support Trusted Launch |
| `windows11Sku`                   | `win11-24h2-ent`                     | Client image SKU |
| `defenderForServersPlan`         | `P2`                                 | `Free` \| `P1` \| `P2` |
| `deployDefenderXdrConnector`     | `true`                               | Needs tenant-level rights; set `false` otherwise |
| `dailyQuotaGb`                   | `5`                                  | Workspace ingestion cap |
| `enableAutoShutdown` / `autoShutdownTime` | `true` / `1900`             | Daily VM shutdown (UTC by default) |
| `scriptsBaseUri`                 | this branch's raw URL                | Where the VMs fetch the bootstrap scripts |

## How it works

### Networking

New VNets lost **default outbound internet access on 2025-09-30**, so a VM with
no public IP and no explicit egress can't reach Windows Update, the Custom
Script Extension payloads, AMA ingestion, or MDE onboarding. This lab attaches a
**NAT Gateway** to `snet-lab` to provide that egress. Inbound is Bastion-only;
the NSG denies inbound from the internet and allows RDP solely from the Bastion
subnet.

### Deployment ordering

Standing up an AD forest and then joining machines to it is inherently
sequential, and two things make it awkward inside a single ARM deployment:

1. **The VNet's DNS has to change mid-deployment.** While `DC01` promotes it
   needs Azure-provided DNS to reach the internet; once it's a DC, the member
   machines need DNS pointed *at the DC* to find the domain. So `network.bicep`
   is deployed **twice** — first with Azure DNS, then (after the DC exists) with
   `dnsServers = [10.10.10.4]`. Re-deploying the same VNet is idempotent.

2. **Promotion requires a reboot the Custom Script Extension can't survive.**
   `Initialize-DomainController.ps1` stages the promotion, registers a
   `RunOnce`-style scheduled task, and reboots; `Complete-DomainController.ps1`
   finishes seeding on the way back up and drops a marker file. A separate
   **run-command gate** (`dcReadyGate.bicep`) then polls for that marker and a
   live directory before ARM is allowed to start joining `SRV01` and the
   clients.

### Data collection

- **Security Events DCR** → `SecurityEvent` table. The Common audit set plus
  Kerberos ticket events (4768/4769/4771) and directory-service access (4662,
  5136) so the AD-focused detections have data.
- **Endpoint DCR** → `Event` table. Sysmon operational log, PowerShell 4103/4104,
  Defender AV operational events, scheduled-task and service-install events.

Both use the Azure Monitor Agent; no legacy MMA/OMS agent is involved.

### Security posture

`defenderPlans.bicep` turns on **Defender for Servers Plan 2** (agentless
scanning included) and enables the **WDATP / unified-solution** integration so
Defender for Endpoint alerts flow into Defender for Cloud, which
`sentinelConnectors.bicep` then forwards into Sentinel alongside the Defender XDR
incident connector.

## Troubleshooting

- **A VM's Custom Script Extension failed.** RDP in via Bastion and read
  `C:\LabSetup\Logs\*.log` — every script transcribes there. Most failures are
  the VM being unable to reach `scriptsBaseUri`; confirm the URL is anonymously
  readable from inside the VM.
- **Members won't join the domain.** Check that the VNet's DNS is `10.10.10.4`
  (`network-domain-dns` deployment) and that `Complete-DomainController.ps1`
  finished — look for `C:\LabSetup\dc-complete.marker` on `DC01`.
- **Deployment fails on the Defender XDR connector.** You lack the tenant-level
  role. Set `deployDefenderXdrConnector = false` and redeploy; connect it from
  the portal.
- **No logs in Sentinel.** Give it 15–20 minutes. Then check `Heartbeat` for the
  machine, and confirm the DCR associations exist on the VM (**VM → left
  menu → Data collection rules** in the Monitor blade).
- **`SkuNotAvailable` / quota errors.** Pick another region or VM size, or raise
  the `Dsv3` quota. Any Trusted-Launch-capable size works.

## Security note

This is a **lab**. It intentionally weakens a directory (Kerberoastable and
AS-REP-roastable accounts, audit-mode ASR) so detections have something to fire
on, and it exposes RDP through Bastion to whoever can reach the portal. Keep it
in an isolated subscription, keep the domain non-routable, and tear it down when
you're done. Don't reuse any of these accounts, passwords, or patterns anywhere
real.
