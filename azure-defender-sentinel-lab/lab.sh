#!/usr/bin/env bash
#
# Lab control: start / stop / status / restart every VM in the lab RG.
#
#   ./lab.sh status     # show power state of each VM (default)
#   ./lab.sh stop       # deallocate ALL VMs (waits, confirms - stops billing)
#   ./lab.sh start      # start ALL VMs, DC first
#   ./lab.sh restart    # stop then start
#
# Deallocation stops compute billing; disks/config are kept, so start brings the
# lab back exactly as it was.
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"
CMD="${1:-status}"

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Not logged in - run 'az login' first." >&2; exit 1; }

SUB_NAME="$(az account show --query name -o tsv)"
echo "Subscription: $SUB_NAME   |   Resource group: $RG"

# Read VM ids into an array (bash 3.2 compatible - macOS has no mapfile).
IDS=()
while IFS= read -r _id; do [ -n "$_id" ] && IDS+=("$_id"); done \
  < <(az vm list -g "$RG" --query "[].id" -o tsv)
if [ "${#IDS[@]}" -eq 0 ]; then
  echo
  echo "No VMs found in '$RG' on this subscription."
  echo "If the lab lives on a different subscription, switch to it and retry:"
  echo "  az account list -o table"
  echo "  az account set --subscription \"<name-or-id>\""
  exit 1
fi

show_status() {
  az vm list -g "$RG" -d --query "sort_by([].{name:name, power:powerState}, &name)" -o table
}

case "$CMD" in
  status)
    show_status
    ;;

  stop)
    echo "Deallocating all VMs (this waits until each is down)..."
    az vm deallocate --ids "${IDS[@]}"     # synchronous - errors surface here
    echo "All deallocate operations completed."
    show_status
    ;;

  start)
    if az vm show -g "$RG" -n DC01 >/dev/null 2>&1; then
      echo "Starting DC01 first (so DNS/domain is up before members)..."
      az vm start -g "$RG" -n DC01 -o none
    fi
    OTHERS=()
    while IFS= read -r _id; do [ -n "$_id" ] && OTHERS+=("$_id"); done \
      < <(az vm list -g "$RG" --query "[?name!='DC01'].id" -o tsv)
    if [ "${#OTHERS[@]}" -gt 0 ]; then
      echo "Starting the remaining VMs..."
      az vm start --ids "${OTHERS[@]}"
    fi
    echo "All start operations completed."
    show_status
    ;;

  restart)
    "$0" stop
    "$0" start
    ;;

  *)
    echo "Usage: $0 {status|stop|start|restart}" >&2
    exit 2
    ;;
esac
