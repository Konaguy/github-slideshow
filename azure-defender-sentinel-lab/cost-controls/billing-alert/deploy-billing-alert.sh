#!/usr/bin/env bash
#
# Deploys the $100 billing alert (email + optional SMS) from your Mac.
#
# Usage:
#   SMS_PHONE=5551234567 ./deploy-billing-alert.sh          # email + text (US +1)
#   ./deploy-billing-alert.sh                               # email only
#   AMOUNT=200 SMS_COUNTRY=1 SMS_PHONE=5551234567 ./deploy-billing-alert.sh
#
set -euo pipefail

LOCATION="${LOCATION:-eastus}"
AMOUNT="${AMOUNT:-100}"
SMS_COUNTRY="${SMS_COUNTRY:-1}"
SMS_PHONE="${SMS_PHONE:-}"
RG="${RESOURCE_GROUP:-rg-mdlab}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first." >&2; exit 1; }

START="$(date -u '+%Y-%m-01')"

if [ -z "$SMS_PHONE" ]; then
  echo "No SMS_PHONE set - deploying EMAIL-ONLY billing alert at \$$AMOUNT."
  echo "For texts too, re-run with: SMS_PHONE=5551234567 ./deploy-billing-alert.sh"
else
  echo "Deploying billing alert at \$$AMOUNT with email + SMS to +$SMS_COUNTRY $SMS_PHONE."
fi

az deployment sub create \
  --name "lab-billing-alert-$(date +%s)" \
  --location "$LOCATION" \
  --template-file "$DIR/billing-alert.bicep" \
  --parameters amount="$AMOUNT" startDate="$START" resourceGroupName="$RG" \
               smsCountryCode="$SMS_COUNTRY" smsPhoneNumber="$SMS_PHONE" \
  --only-show-errors -o none

echo "Done."
echo "Alerts fire at 90% (\$$((AMOUNT * 90 / 100))), 100% (\$$AMOUNT), and on forecast."
echo "Manage at: Portal > Cost Management > Budgets, and Monitor > Action groups > ag-lab-billing."
