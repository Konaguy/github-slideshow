#!/usr/bin/env bash
#
# Tears the lab down and stops the meters.
#
# Deleting the resource group is not enough on its own:
#   * Defender for Servers is a subscription-level plan and keeps billing.
#   * Log Analytics workspaces are soft-deleted for 14 days and the name stays
#     reserved, which blocks a rebuild with the same prefix.
#
set -euo pipefail

PREFIX="${PREFIX:-mdlab}"
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-${PREFIX}}"
WORKSPACE_NAME="${WORKSPACE_NAME:-${PREFIX}-law}"
REVERT_DEFENDER="${REVERT_DEFENDER:-true}"

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first." >&2; exit 1; }

SUB_NAME="$(az account show --query name -o tsv)"
echo "Subscription:   ${SUB_NAME}"
echo "Resource group: ${RESOURCE_GROUP}"
echo "Workspace:      ${WORKSPACE_NAME} (will be purged, not soft-deleted)"
echo
read -r -p "Permanently delete all of the above? [y/N] " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Aborted."; exit 0; }

if az monitor log-analytics workspace show -g "$RESOURCE_GROUP" -n "$WORKSPACE_NAME" >/dev/null 2>&1; then
  echo "Purging the Log Analytics workspace..."
  az monitor log-analytics workspace delete -g "$RESOURCE_GROUP" -n "$WORKSPACE_NAME" --force true --yes
fi

if az group exists --name "$RESOURCE_GROUP" | grep -q true; then
  echo "Deleting the resource group (runs in the background)..."
  az group delete --name "$RESOURCE_GROUP" --yes --no-wait
fi

if [[ "$REVERT_DEFENDER" == "true" ]]; then
  echo "Reverting Defender for Cloud plans to Free..."
  for plan in VirtualMachines CloudPosture Arm KeyVaults StorageAccounts; do
    az security pricing create -n "$plan" --tier free --only-show-errors >/dev/null 2>&1 \
      || echo "  (skipped ${plan})"
  done
fi

echo
echo "Teardown started. 'az group show -n ${RESOURCE_GROUP}' will 404 once it finishes."
echo "Note: Defender for Servers bills hourly, so the final invoice covers the time the plan was on."
