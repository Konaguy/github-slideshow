#!/usr/bin/env bash
#
# Runs the scriptable parts of the Intune hybrid-join prep from your Mac, via
# 'az vm run-command' (as SYSTEM on the VMs - no Bastion logins).
#
# It does NOT install Entra Connect - that is an interactive wizard on SRV01
# (see README.md, step 3). This handles the AD-side prep and verification:
#   1. adds the routable UPN suffix + repoints lab users (DC01)
#   2. creates/links the Intune auto-enrollment GPO (DC01)
#   3. reports hybrid-join status on each client
#
# Usage:
#   UPN_SUFFIX=3ch3lon.com ./prep-intune.sh            # steps 1 + 2
#   UPN_SUFFIX=3ch3lon.com ./prep-intune.sh --status   # step 3 only (after Entra Connect + gpupdate)
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"
UPN_SUFFIX="${UPN_SUFFIX:-}"
CLIENTS=(WIN11-01 WIN11-02 WIN11-03)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts"
MODE="prep"
[ "${1:-}" = "--status" ] && MODE="status"

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first." >&2; exit 1; }

run_on() {  # run_on <vm> <local-ps1>
  az vm run-command invoke -g "$RG" -n "$1" \
    --command-id RunPowerShellScript --scripts "@$2" \
    --query "value[].message" -o tsv --only-show-errors
}

if [ "$MODE" = "prep" ]; then
  [ -n "$UPN_SUFFIX" ] || { echo "Set UPN_SUFFIX to your verified Entra domain, e.g. UPN_SUFFIX=3ch3lon.com" >&2; exit 1; }

  echo "=== 1/2 UPN suffix + lab users (DC01) ==="
  TMP="$(mktemp -t upn.XXXXXX.ps1)"
  sed "s/__UPN_SUFFIX__/$UPN_SUFFIX/g" "$DIR/Set-LabUpnSuffix.ps1" > "$TMP"
  run_on DC01 "$TMP"
  rm -f "$TMP"

  echo
  echo "=== 2/2 Intune auto-enrollment GPO (DC01) ==="
  run_on DC01 "$DIR/New-MdmAutoEnrollGpo.ps1"

  echo
  echo "AD-side prep done. NEXT (manual): install & configure Entra Connect on SRV01"
  echo "with Hybrid Entra join enabled - see README.md step 3. Then run:"
  echo "  ./prep-intune.sh --status"
else
  for c in "${CLIENTS[@]}"; do
    echo "=== hybrid-join status: $c ==="
    run_on "$c" "$DIR/Get-HybridJoinStatus.ps1" || echo "  (run-command failed on $c)"
    echo
  done
fi
