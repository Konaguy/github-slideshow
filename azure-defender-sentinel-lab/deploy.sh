#!/usr/bin/env bash
#
# Deploys the Microsoft Defender + Sentinel lab.
#
#   ./deploy.sh                 deploy
#   ./deploy.sh --what-if       preview changes without deploying
#   ./deploy.sh --validate      template validation only
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-mdlab-$(date +%Y%m%d-%H%M%S)}"
LOCATION="${LOCATION:-eastus}"
MODE="deploy"

for arg in "$@"; do
  case "$arg" in
    --what-if)  MODE="what-if" ;;
    --validate) MODE="validate" ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

command -v az >/dev/null || { echo "Azure CLI not found. Install it first: https://aka.ms/azure-cli" >&2; exit 1; }

if ! az account show >/dev/null 2>&1; then
  echo "Not signed in. Running 'az login'..."
  az login >/dev/null
fi

SUB_ID="$(az account show --query id -o tsv)"
SUB_NAME="$(az account show --query name -o tsv)"
echo "Subscription: ${SUB_NAME} (${SUB_ID})"
read -r -p "Deploy the lab into this subscription? [y/N] " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Aborted."; exit 0; }

echo "Registering resource providers (no-op if already registered)..."
for ns in Microsoft.Compute Microsoft.Network Microsoft.Storage \
          Microsoft.OperationalInsights Microsoft.OperationsManagement \
          Microsoft.SecurityInsights Microsoft.Security Microsoft.Insights \
          Microsoft.DevTestLab Microsoft.GuestConfiguration; do
  az provider register --namespace "$ns" --only-show-errors >/dev/null &
done
wait

if [[ -z "${LAB_ADMIN_PASSWORD:-}" ]]; then
  read -r -s -p "Local/domain admin password: " LAB_ADMIN_PASSWORD; echo
  read -r -s -p "Confirm: " confirm_pw; echo
  [[ "$LAB_ADMIN_PASSWORD" == "$confirm_pw" ]] || { echo "Passwords do not match." >&2; exit 1; }
fi
if [[ -z "${LAB_DSRM_PASSWORD:-}" ]]; then
  read -r -s -p "DSRM (directory restore) password: " LAB_DSRM_PASSWORD; echo
fi
export LAB_ADMIN_PASSWORD LAB_DSRM_PASSWORD

if [[ ${#LAB_ADMIN_PASSWORD} -lt 12 ]]; then
  echo "Admin password must be at least 12 characters." >&2; exit 1
fi

COMMON=(--location "$LOCATION"
        --template-file "$SCRIPT_DIR/main.bicep"
        --parameters "$SCRIPT_DIR/main.bicepparam")

case "$MODE" in
  validate)
    echo "Validating..."
    az deployment sub validate --name "$DEPLOYMENT_NAME" "${COMMON[@]}" --only-show-errors >/dev/null
    echo "Template is valid."
    ;;
  what-if)
    az deployment sub what-if --name "$DEPLOYMENT_NAME" "${COMMON[@]}"
    ;;
  deploy)
    echo "Deploying '${DEPLOYMENT_NAME}'. Expect 35-50 minutes: the DC promotes and"
    echo "reboots before the member machines are allowed to start joining."
    az deployment sub create --name "$DEPLOYMENT_NAME" "${COMMON[@]}"
    echo
    echo "=== Outputs ==="
    az deployment sub show --name "$DEPLOYMENT_NAME" --query properties.outputs -o jsonc
    echo
    echo "Next: see 'Post-deployment' in README.md - Windows 11 clients still need"
    echo "Defender for Endpoint onboarding, which is a per-tenant manual step."
    ;;
esac
