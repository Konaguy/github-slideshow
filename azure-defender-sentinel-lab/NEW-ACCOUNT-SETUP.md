# Rebuilding the lab on a new account (escleveland_@hotmail.com)

End-to-end runbook for standing the lab up from zero in the Azure subscription
and Entra tenant that belong to **escleveland_@hotmail.com**.

Topology this time — **4 VMs**:

| VM         | Role                                   |
|------------|----------------------------------------|
| `DC01`     | Domain controller + DNS (`lab.local`)  |
| `SRV01`    | Member server (also hosts Entra Connect) |
| `WIN11-01` | Windows 11 Enterprise, domain joined   |
| `WIN11-02` | Windows 11 Enterprise, domain joined   |

Everything below runs from your Mac, in this folder, unless it says "portal".

---

## Step 0 — Subscription sanity check

```bash
az login                      # sign in as escleveland_@hotmail.com
az account list -o table      # note the subscription and TenantId
az account set --subscription "<subscription name or id>"
```

- The subscription must be **Pay-As-You-Go** (or better). An Azure **Free
  Trial** caps you at 4 vCPUs total and blocks Defender plans — upgrade it in
  **Portal → Subscriptions → Upgrade** first.
- The hotmail account becomes **Owner** of the subscription and **Global
  Administrator** of the tenant it created automatically. Good for Azure — but
  see step 1.

## Step 1 — Create a work admin account in the tenant

A personal Microsoft account (hotmail/outlook) works in the Azure portal but
**cannot** sign in to Entra Connect, and often hits `401 No Permission` in
Intune and Defender. Create a cloud-only admin and use it for all M365 portals.

```bash
# Your tenant's built-in domain, e.g. esclevelandhotmail.onmicrosoft.com
TENANT_DOMAIN=$(az rest --url https://graph.microsoft.com/v1.0/domains \
  --query "value[?isInitial].id | [0]" -o tsv); echo "$TENANT_DOMAIN"

read -r -s -p "New admin password: " ADMIN_PW; echo
ADMIN_ID=$(az ad user create \
  --display-name "Lab Admin" \
  --user-principal-name "admin@$TENANT_DOMAIN" \
  --password "$ADMIN_PW" \
  --query id -o tsv)

# Global Administrator (built-in role template id)
az rest --method POST \
  --url https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments \
  --body "{\"principalId\":\"$ADMIN_ID\",\"roleDefinitionId\":\"62e90394-69f5-4237-9190-012177145e10\",\"directoryScopeId\":\"/\"}"

# Give it Owner on the subscription too, so it can run everything
az role assignment create --assignee "$ADMIN_ID" --role Owner \
  --scope "/subscriptions/$(az account show --query id -o tsv)"
```

Sign in once at <https://portal.azure.com> as `admin@<tenant>.onmicrosoft.com`
to set up MFA. **Use this account for Intune, Defender, Entra and M365 admin.**

## Step 2 — Check VM quota and capacity

Four 2-vCPU VMs need **8 vCPUs** of one family in `eastus`.

```bash
az vm list-usage -l eastus -o table | grep -Ei "Total Regional|DSv5|DASv5|DSv7|DASv7"
az vm list-skus -l eastus --size Standard_D2 --resource-type virtualMachines \
  --query "[?restrictions==\`[]\`].name" -o tsv
```

Pick a size that has **both** ≥ 8 vCPU quota and no restriction, and set it in
`main.bicepparam` (`serverVmSize` / `clientVmSize`). If none qualify, request
more quota: **Portal → Quotas → Compute → eastus → <family> → Request increase**
(new limit 10). Also make sure **Total Regional vCPUs** is ≥ 8.

## Step 3 — Start the licence trial (portal, as the work admin)

A new personal tenant has **no Intune, no Defender for Endpoint and no Entra P1**.
One trial covers all of it — and also grants the Windows 11 multitenant hosting
right the Win11 VMs rely on:

1. <https://admin.microsoft.com> → **Billing → Purchase services** → search
   **Microsoft 365 E5** (or **Business Premium**) → **Start free trial**.
2. **Users → Active users → Lab Admin → Licenses and apps** → tick the trial
   licence → **Save**.
3. Wait ~30 min, then check <https://intune.microsoft.com> → **Tenant
   administration → Tenant status** loads. If it asks for an MDM authority, set
   **Intune**.

```bash
# Confirm the tenant now has Intune in a SKU
az rest --url https://graph.microsoft.com/v1.0/subscribedSkus \
  --query "value[].{sku:skuPartNumber,total:prepaidUnits.enabled}" -o table
```

## Step 4 — Deploy the lab (35–50 min)

```bash
az login --tenant "$TENANT_DOMAIN"     # hotmail or the work admin, both are Owner
az account set --subscription "<subscription>"
./deploy.sh --validate
./deploy.sh
```

Prompts for the `labadmin` password and the DSRM password. Output ends with
the four VM names. Sign in via **Portal → rg-mdlab → DC01 → Connect → Bastion**
as `LAB\labadmin`.

## Step 5 — Cost guardrails (do this right after deploy)

```bash
./cost-controls/apply-cost-controls.sh              # $25 budget email + 30-min auto-deallocate
./cost-controls/billing-alert/deploy-billing-alert.sh   # $100 email alert (add SMS_PHONE=... for texts)
./cost-controls/enforcement/deploy-enforcement.sh   # $25 hard stop + CPU-idle shutdown
./cost-controls/install-idle-shutdown.sh            # stop after 20 min with no signed-in session
./kill-switch/pin-kill-switch.sh                    # optional: one-command stop-all
```

Alerts go to `escleveland_@hotmail.com`. Day-to-day:

```bash
./lab.sh status | ./lab.sh start | ./lab.sh stop
```

## Step 6 — Defender for Endpoint + Sentinel

1. **Defender portal** (<https://security.microsoft.com>, as the work admin):
   **Settings → Endpoints → Onboarding** → Windows 10 and 11 → *Local script* →
   **Download onboarding package**.
2. Onboard both clients in one go:
   ```bash
   MDE_PACKAGE=~/Downloads/WindowsDefenderATPOnboardingPackage.zip ./onboard-clients.sh
   ```
3. **Sentinel → Configuration → Data connectors → Microsoft Defender XDR →
   Connect incidents & alerts.**
4. After ~20 min in **Sentinel → Logs**:
   ```kql
   Heartbeat | summarize arg_max(TimeGenerated, *) by Computer   // expect 4
   ```

## Step 7 — Defender AV baseline + ASR (audit) GPOs

```bash
./defender-policy/deploy-defender-policy.sh
```

See `defender-policy/README.md` for what it sets and how to flip ASR to block.

## Step 8 — Intune (hybrid Entra join)

Full detail in `intune/README.md`. Short version:

```bash
UPN_SUFFIX="$TENANT_DOMAIN" ./intune/prep-intune.sh
```

Then on **SRV01** (Bastion), install **Microsoft Entra Connect**, and when it
asks for Entra credentials sign in as **`admin@<tenant>.onmicrosoft.com`** —
*not* the hotmail account. Configure Hybrid Entra join + the SCP, set the MDM
user scope to **All**, and license the synced lab users with the trial SKU.

```bash
UPN_SUFFIX="$TENANT_DOMAIN" ./intune/prep-intune.sh --status
```

## Tearing it all down

```bash
./teardown.sh
```
