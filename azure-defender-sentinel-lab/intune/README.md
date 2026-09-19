# Intune hybrid Entra join for the lab

Bring the AD-domain-joined Windows 11 clients (`WIN11-01/02/03`) into **Microsoft
Intune** using **hybrid Entra join** — the clients keep their `lab.local` domain
membership *and* gain an Entra ID identity, then auto-enroll into Intune.

## The one part that isn't automatable

**Microsoft Entra Connect Sync** is installed and configured through an
interactive wizard on a Windows server. There is no clean CLI for a first-time
setup, so step 3 below is done by hand on `SRV01` via Bastion. Everything else —
AD prep, the auto-enrollment GPO, and verification — runs from your Mac with
`prep-intune.sh` (which uses `az vm run-command`, no Bastion needed).

## Prerequisites

- Intune licensing on the tenant (M365 E3/E5, EMS E3/E5, or Intune standalone) — you have this.
- A **verified custom domain** in Entra to use as the routable UPN suffix. Your
  tenant is `3ch3lon.com`; confirm it shows **Verified** under
  **Entra admin center → Identity → Settings → Domain names**. If it isn't
  verified, either verify it or use `<tenant>.onmicrosoft.com` as the suffix.
- The lab deployed and healthy (all five VMs joined to `lab.local`).

## Why the UPN suffix matters

The domain is `lab.local`, which is **non-routable** — Entra Connect won't sync
users with a `.local` UPN, and hybrid join needs a sign-in UPN that matches a
verified tenant domain. So the first step adds `3ch3lon.com` as a UPN suffix in
AD and repoints the lab users at it (`jdoe@3ch3lon.com`, etc.).

---

## Step 1 & 2 — AD prep (from your Mac)

```bash
cd azure-defender-sentinel-lab/intune
UPN_SUFFIX=3ch3lon.com ./prep-intune.sh
```

This runs, on `DC01`:
1. **`Set-LabUpnSuffix.ps1`** — adds the `3ch3lon.com` UPN suffix to the forest
   and updates every user under `OU=Lab` to `sam@3ch3lon.com`.
2. **`New-MdmAutoEnrollGpo.ps1`** — creates and links a GPO ("Lab - Intune Auto
   Enrollment") that turns on automatic MDM enrollment using the device's Entra
   credential.

## Step 3 — Install Entra Connect on SRV01 (manual, ~20 min)

Connect to **SRV01** via Bastion (`LAB\labadmin`), then:

1. Download **Microsoft Entra Connect** from
   <https://www.microsoft.com/download/details.aspx?id=47594> (or search "Entra
   Connect download"). Run the MSI.
2. Choose **Customize** (not Express).
3. **User sign-in**: pick **Password Hash Synchronization** (simplest for a lab;
   gives you sign-in + leaked-credential detection). Pass-through auth or ADFS
   also work but are heavier.
4. **Connect to Entra ID**: sign in as a tenant **Global Administrator**.
5. **Connect directories**: add the `lab.local` forest with **Enterprise Admin**
   credentials (`LAB\labadmin`).
6. **Entra sign-in**: choose **userPrincipalName** as the attribute. The wizard
   should show `3ch3lon.com` as verified — if it warns about unverified
   suffixes, you missed step 1 or the domain isn't verified in Entra.
7. **Domain/OU filtering**: sync at least `OU=Lab` (users) and the **Computers**
   container (the clients live there unless you set `computerOuPath` at deploy).
8. On the **Optional features** / device options page, or by re-running the
   wizard afterward → **Configure device options → Configure Hybrid Entra join**:
   - Device operating systems: **Windows 10 or later domain-joined devices**
   - SCP configuration: let the wizard create the **Service Connection Point**
     for `lab.local` (authenticates as Enterprise Admin).
9. Finish and let the initial sync run.

The SCP is what tells the domain-joined clients which tenant to register with;
the wizard writing it is the key output of this step.

## Step 4 — Tenant-side settings (portal, 2 min)

1. **Entra admin center → Identity → Devices → All devices → Device settings**:
   confirm users may register/join devices.
2. **Entra admin center → Devices → Enrollment → Automatic enrollment**
   (a.k.a. **Mobility (MDM and MAM) → Microsoft Intune**): set **MDM user scope**
   to **All** (or a group containing your lab users). Leave the default
   Terms-of-use / Discovery / Compliance URLs.
3. **Assign Intune licenses** to the synced lab users
   (**Identity → Users →** select users **→ Licenses → + Assignments**). A user
   without a license can't complete enrollment.

## Step 5 — Trigger and verify (from your Mac)

On each client the hybrid join happens automatically within ~30–60 min, or force
it. First push policy + a sync (via run-command or Bastion):

```bash
# force GPO + a device-registration attempt on all clients, from your Mac
for c in WIN11-01 WIN11-02 WIN11-03; do
  az vm run-command invoke -g rg-mdlab -n $c --command-id RunPowerShellScript \
    --scripts "gpupdate /force; Start-Sleep 5; dsregcmd /join" \
    --query "value[].message" -o tsv --only-show-errors
done
```

Then check status:

```bash
cd azure-defender-sentinel-lab/intune
./prep-intune.sh --status
```

You want, per client:
```
AzureAdJoined : YES
DomainJoined  : YES
```
and, once auto-enrolled, an MDM URL present. Enrolled devices then appear in
**Intune admin center → Devices → Windows**, and in **Entra → Devices** as
**Hybrid Entra joined**.

## How this ties to Defender

Once the clients are in Intune you can push the **Defender for Endpoint**
onboarding as an Intune policy instead of the local-script method
(`onboard-clients.sh`): **Intune → Endpoint security → Endpoint detection and
response**, create a policy, assign it to the clients. Intune pulls the
onboarding blob from the Defender connector automatically — no per-machine
package. Connect the two first at **Intune → Endpoint security → Microsoft
Defender for Endpoint → Open the Microsoft Defender for Endpoint admin console**
and enable the Intune connection.

## Troubleshooting

- **Wizard says the UPN suffix is unverified** → the domain isn't verified in
  Entra, or step 1 didn't run. Re-run step 1 and verify the domain in Entra.
- **`AzureAdJoined : NO` after an hour** → SCP missing or wrong tenant. Re-run
  the Entra Connect device-options wizard; confirm `dsregcmd /status` shows the
  right `TenantName`.
- **Device hybrid-joined but not in Intune** → MDM user scope not set (step 4.2),
  no Intune license on the user (step 4.3), or the GPO hasn't applied
  (`gpupdate /force`).
- **Sync not picking up a user/computer** → it's outside the OUs you selected in
  step 3.7; add the OU in the Entra Connect sync-scope wizard.
