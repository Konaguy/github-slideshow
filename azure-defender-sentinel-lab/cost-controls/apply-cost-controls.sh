#!/usr/bin/env bash
#
# Applies both cost guardrails to the running lab, from your Mac:
#   1. a $25 monthly budget that emails two addresses at 90% / 100% / forecast,
#   2. a 30-minute auto-DEALLOCATE on every VM (grants each VM's managed
#      identity rights over itself, then installs the scheduled task).
#
# Usage:
#   ./apply-cost-controls.sh                 # both, 30 min, $25
#   DELAY_MINUTES=45 BUDGET=50 ./apply-cost-controls.sh
#   ./apply-cost-controls.sh --budget-only
#   ./apply-cost-controls.sh --shutdown-only
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"
LOCATION="${LOCATION:-eastus}"
DELAY_MINUTES="${DELAY_MINUTES:-30}"
BUDGET="${BUDGET:-25}"
VMS=(DC01 SRV01 WIN11-01 WIN11-02 WIN11-03)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DO_BUDGET=1; DO_SHUTDOWN=1
case "${1:-}" in
  --budget-only)   DO_SHUTDOWN=0 ;;
  --shutdown-only) DO_BUDGET=0 ;;
esac

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first." >&2; exit 1; }

if [ "$DO_BUDGET" -eq 1 ]; then
  echo "=== Budget: \$$BUDGET/month with email alerts ==="
  START="$(date -u '+%Y-%m-01')"
  az deployment sub create \
    --name "lab-budget-$(date +%s)" \
    --location "$LOCATION" \
    --template-file "$DIR/budget.bicep" \
    --parameters amount="$BUDGET" startDate="$START" \
    --only-show-errors -o none
  echo "Budget deployed. Alerts go to the addresses in budget.bicep."
fi

if [ "$DO_SHUTDOWN" -eq 1 ]; then
  echo
  echo "=== ${DELAY_MINUTES}-minute auto-deallocate on each VM ==="
  TMP="$(mktemp -t deallocate.XXXXXX.ps1)"
  sed "s/\$DelayMinutes = 30/\$DelayMinutes = $DELAY_MINUTES/" "$DIR/scripts/Set-AutoDeallocate.ps1" > "$TMP"

  for vm in "${VMS[@]}"; do
    echo "-- $vm --"
    PID="$(az vm show -g "$RG" -n "$vm" --query identity.principalId -o tsv)"
    VMID="$(az vm show -g "$RG" -n "$vm" --query id -o tsv)"
    if [ -z "$PID" ] || [ "$PID" = "None" ]; then
      echo "  no managed identity on $vm - skipping (unexpected)"; continue
    fi
    # Grant the VM's identity rights to deallocate itself (idempotent).
    az role assignment create \
      --assignee-object-id "$PID" --assignee-principal-type ServicePrincipal \
      --role "Virtual Machine Contributor" --scope "$VMID" \
      --only-show-errors -o none 2>/dev/null || echo "  (role assignment already present)"
    # Install the scheduled task.
    az vm run-command invoke -g "$RG" -n "$vm" \
      --command-id RunPowerShellScript --scripts "@$TMP" \
      --query "value[].message" -o tsv --only-show-errors
  done
  rm -f "$TMP"
  echo
  echo "Done. Every VM deallocates ${DELAY_MINUTES} min after it starts (this session included)."
fi
