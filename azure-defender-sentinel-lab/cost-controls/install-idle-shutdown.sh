#!/usr/bin/env bash
#
# Installs the "no interaction for N minutes -> deallocate" watchdog on every VM,
# from your Mac. Grants each VM's managed identity rights over itself (idempotent),
# then pushes the watchdog scheduled task via az vm run-command.
#
# "No interaction" = no keyboard/mouse activity in any Active session (session
# idle time from 'quser'), not CPU idle.
#
# Usage:
#   ./install-idle-shutdown.sh                 # 20 min, check every 5 min
#   IDLE_MINUTES=30 CHECK_EVERY=5 ./install-idle-shutdown.sh
#   ./install-idle-shutdown.sh WIN11-01        # specific VMs only
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"
IDLE_MINUTES="${IDLE_MINUTES:-20}"
CHECK_EVERY="${CHECK_EVERY:-5}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VMS=("$@")
if [ "${#VMS[@]}" -eq 0 ]; then
  VMS=(DC01 SRV01 WIN11-01 WIN11-02 WIN11-03)
fi

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first." >&2; exit 1; }

TMP="$(mktemp -t idleinteraction.XXXXXX.ps1)"
sed -e "s/\$IdleMinutes    = 20/\$IdleMinutes    = $IDLE_MINUTES/" \
    -e "s/\$CheckEveryMins = 5/\$CheckEveryMins = $CHECK_EVERY/" \
    "$DIR/scripts/Set-IdleInteractionShutdown.ps1" > "$TMP"

for vm in "${VMS[@]}"; do
  echo "-- $vm --"
  PID="$(az vm show -g "$RG" -n "$vm" --query identity.principalId -o tsv)"
  VMID="$(az vm show -g "$RG" -n "$vm" --query id -o tsv)"
  if [ -z "$PID" ] || [ "$PID" = "None" ]; then
    echo "  no managed identity on $vm - skipping"; continue
  fi
  az role assignment create \
    --assignee-object-id "$PID" --assignee-principal-type ServicePrincipal \
    --role "Virtual Machine Contributor" --scope "$VMID" \
    --only-show-errors -o none 2>/dev/null || echo "  (role assignment already present)"
  az vm run-command invoke -g "$RG" -n "$vm" \
    --command-id RunPowerShellScript --scripts "@$TMP" \
    --query "value[].message" -o tsv --only-show-errors
done
rm -f "$TMP"

echo
echo "Done. Each VM deallocates after ${IDLE_MINUTES} min with no interaction (checked every ${CHECK_EVERY} min)."
echo "Restart with: az vm start -g $RG -n <VM>"
echo "Disable with: az vm run-command invoke -g $RG -n <VM> --command-id RunPowerShellScript \\"
echo "                --scripts \"Unregister-ScheduledTask -TaskName LabIdleInteractionShutdown -Confirm:\\\$false\""
