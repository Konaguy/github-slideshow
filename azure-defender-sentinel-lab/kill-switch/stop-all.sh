#!/usr/bin/env bash
#
# KILL SWITCH - deallocate every VM in the lab resource group, immediately.
#
# No prompts. Deallocation stops compute billing at once; disks and config are
# untouched, so it is fully reversible with:  az vm start -g rg-mdlab -n <VM>
# (or ./start-all.sh).
#
# Runs the deallocate in the background (--no-wait) so it returns instantly.
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Not logged in - run 'az login' first." >&2; exit 1; }

IDS="$(az vm list -g "$RG" --query "[].id" -o tsv)"
if [ -z "$IDS" ]; then
  echo "No VMs found in $RG - nothing to stop."
  exit 0
fi

echo "KILL SWITCH: deallocating all VMs in $RG ..."
az vm list -g "$RG" --query "[].name" -o tsv | sed 's/^/  - /'
# shellcheck disable=SC2086
az vm deallocate --ids $IDS --no-wait
echo "Deallocate issued (running in background)."
echo "Confirm:  az vm list -g $RG -d --query \"[].{name:name,power:powerState}\" -o table"
echo "Restart:  ./start-all.sh   (or az vm start -g $RG -n <VM>)"
