#!/usr/bin/env bash
#
# Bring the lab back up - start every VM in the resource group.
# Starts the domain controller first so members can reach it, then the rest.
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Not logged in - run 'az login' first." >&2; exit 1; }

# DC first (best effort), so DNS/domain is up before members boot.
if az vm show -g "$RG" -n DC01 >/dev/null 2>&1; then
  echo "Starting DC01 first..."
  az vm start -g "$RG" -n DC01 -o none
fi

OTHER="$(az vm list -g "$RG" --query "[?name!='DC01'].id" -o tsv)"
if [ -n "$OTHER" ]; then
  echo "Starting the remaining VMs..."
  # shellcheck disable=SC2086
  az vm start --ids $OTHER --no-wait
fi

echo "Start issued."
echo "Confirm:  az vm list -g $RG -d --query \"[].{name:name,power:powerState}\" -o table"
