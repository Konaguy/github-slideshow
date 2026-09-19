#!/usr/bin/env bash
#
# Deploys the enforcement automation (budget-stop + idle-stop) from your Mac.
#
#   1. deploys automation.bicep into the resource group (Automation account,
#      two runbooks, schedules, RG-scope role assignments),
#   2. grants the automation identity Cost Management Reader at the SUBSCRIPTION
#      scope (needed to read spend; outside the RG so it can't live in the bicep).
#
# The runbook bodies are pulled from raw GitHub, so push this branch first.
#
# Usage:
#   ./deploy-enforcement.sh
#   BUDGET=50 IDLE_CPU=3 IDLE_WINDOW=30 ./deploy-enforcement.sh
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"
BUDGET="${BUDGET:-25}"
IDLE_CPU="${IDLE_CPU:-5}"
IDLE_WINDOW="${IDLE_WINDOW:-30}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COST_READER_ROLE='Cost Management Reader'

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first." >&2; exit 1; }
SUB_ID="$(az account show --query id -o tsv)"

echo "=== Deploying enforcement automation into $RG ==="
az deployment group create \
  --resource-group "$RG" \
  --name "lab-enforcement-$(date +%s)" \
  --template-file "$DIR/automation.bicep" \
  --parameters budgetThresholdUsd="$BUDGET" idleCpuThresholdPercent="$IDLE_CPU" idleWindowMinutes="$IDLE_WINDOW" \
  --only-show-errors -o none

PID="$(az deployment group show -g "$RG" \
        --name "$(az deployment group list -g "$RG" --query "sort_by([?contains(name,'lab-enforcement')], &properties.timestamp)[-1].name" -o tsv)" \
        --query "properties.outputs.automationPrincipalId.value" -o tsv)"

echo "Automation identity: $PID"
echo "=== Granting '$COST_READER_ROLE' at subscription scope ==="
az role assignment create \
  --assignee-object-id "$PID" --assignee-principal-type ServicePrincipal \
  --role "$COST_READER_ROLE" --scope "/subscriptions/$SUB_ID" \
  --only-show-errors -o none 2>/dev/null || echo "  (already assigned)"

echo
echo "Done."
echo "  Enforce-Budget runs hourly; deallocates all VMs when MTD cost >= \$$BUDGET."
echo "  Stop-IdleVms runs every 30 min; deallocates VMs under ${IDLE_CPU}% CPU over ${IDLE_WINDOW} min."
echo
echo "Watch runbook jobs:"
echo "  az automation job list --resource-group $RG --automation-account-name ${RG#rg-}-automation -o table"
echo "Run one now (test):"
echo "  Portal > Automation account > Runbooks > Enforce-Budget > Start"
