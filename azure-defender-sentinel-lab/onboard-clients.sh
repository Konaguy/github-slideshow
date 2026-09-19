#!/usr/bin/env bash
#
# Automates Microsoft Defender for Endpoint onboarding of the Windows 11 clients.
#
# The ONLY manual prerequisite is downloading your tenant's onboarding package:
#   https://security.microsoft.com > Settings > Endpoints > Onboarding
#   OS: "Windows 10 and 11", Deployment method: "Local Script" > Download package
# That .zip is tenant-specific and cannot be scripted. Everything after it can.
#
# This script:
#   1. uploads the package to a short-lived storage blob (SAS, 2h),
#   2. runs it on each client via 'az vm run-command' (as SYSTEM, no Bastion),
#   3. reports each client's Sense service status,
#   4. deletes the temp storage account.
#
# Usage:
#   MDE_PACKAGE=~/Downloads/WindowsDefenderATPOnboardingPackage.zip ./onboard-clients.sh
#   # optional: pass specific client names, else defaults to WIN11-01/02/03
#   MDE_PACKAGE=... ./onboard-clients.sh WIN11-01 WIN11-02
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"
LOCATION="${LOCATION:-eastus}"
PKG="${MDE_PACKAGE:?Set MDE_PACKAGE to the path of the onboarding .zip downloaded from security.microsoft.com}"

CLIENTS=("$@")
if [ "${#CLIENTS[@]}" -eq 0 ]; then
  CLIENTS=(WIN11-01 WIN11-02 WIN11-03)
fi

[ -f "$PKG" ] || { echo "Package not found: $PKG" >&2; exit 1; }
command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first." >&2; exit 1; }

# Unique, lowercase, <=24 char storage account name.
SA="mdeonb$(date +%s | tail -c 8)$RANDOM"
SA="$(echo "$SA" | tr -cd 'a-z0-9' | cut -c1-24)"
CONTAINER="onboarding"
BLOB="onboarding.zip"

cleanup() {
  if [ -n "${SA:-}" ] && az storage account show -n "$SA" -g "$RG" >/dev/null 2>&1; then
    echo "Cleaning up temp storage account $SA..."
    az storage account delete -n "$SA" -g "$RG" --yes >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Creating temp storage account $SA..."
az storage account create -n "$SA" -g "$RG" -l "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 --only-show-errors >/dev/null

echo "Uploading package..."
az storage container create --account-name "$SA" -n "$CONTAINER" --auth-mode login --only-show-errors >/dev/null
az storage blob upload --account-name "$SA" -c "$CONTAINER" -n "$BLOB" -f "$PKG" \
  --auth-mode login --overwrite --only-show-errors >/dev/null

# 2-hour SAS. macOS 'date -v' vs GNU 'date -d'.
EXPIRY="$(date -u -v+2H '+%Y-%m-%dT%H:%MZ' 2>/dev/null || date -u -d '+2 hours' '+%Y-%m-%dT%H:%MZ')"
SAS="$(az storage blob generate-sas --account-name "$SA" -c "$CONTAINER" -n "$BLOB" \
  --permissions r --expiry "$EXPIRY" --auth-mode login --as-user -o tsv --only-show-errors)"
URL="https://${SA}.blob.core.windows.net/${CONTAINER}/${BLOB}?${SAS}"

# The script that runs on each client (URL embedded so no fragile param passing).
PS1="$(mktemp -t mde-onboard.XXXXXX.ps1)"
trap 'rm -f "$PS1"; cleanup' EXIT
cat > "$PS1" <<PSEOF
\$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
\$dir = 'C:\LabSetup\MDE'
New-Item -Path \$dir -ItemType Directory -Force | Out-Null
\$zip = Join-Path \$dir 'onboarding.zip'
Invoke-WebRequest -Uri '${URL}' -OutFile \$zip -UseBasicParsing -TimeoutSec 180
Expand-Archive -Path \$zip -DestinationPath \$dir -Force
\$cmd = Get-ChildItem -Path \$dir -Filter '*OnboardingScript*.cmd' -Recurse | Select-Object -First 1
if (-not \$cmd) { throw 'No *OnboardingScript*.cmd found in the package.' }
\$p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('"' + \$cmd.FullName + '"') -Wait -PassThru -NoNewWindow
Write-Output ("Onboarding script exit code: " + \$p.ExitCode)
Start-Sleep -Seconds 10
\$svc = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
if (\$svc) { Write-Output ("Sense service: " + \$svc.Status) } else { Write-Output 'Sense service: NOT PRESENT' }
Remove-Item -Path \$zip -Force -ErrorAction SilentlyContinue
PSEOF

FAIL=0
for c in "${CLIENTS[@]}"; do
  echo
  echo "=== Onboarding $c (this can take 1-2 minutes) ==="
  if az vm run-command invoke -g "$RG" -n "$c" \
       --command-id RunPowerShellScript --scripts "@$PS1" \
       --query "value[].message" -o tsv --only-show-errors; then
    :
  else
    echo "  run-command failed on $c" >&2
    FAIL=1
  fi
done

echo
if [ "$FAIL" -eq 0 ]; then
  echo "Done. Each client above should report 'Sense service: Running'."
  echo "Devices appear in https://security.microsoft.com > Assets > Devices within ~15 min."
else
  echo "One or more clients failed - see messages above."
fi
exit $FAIL
