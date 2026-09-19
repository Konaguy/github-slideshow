#!/usr/bin/env bash
#
# Builds the Defender AV baseline + ASR (audit) Group Policy from your Mac:
#   1. runs New-DefenderPolicyGpo.ps1 on DC01 (creates/links the GPOs, moves the
#      computer objects into OU=Servers / OU=Workstations),
#   2. forces a policy refresh on each member,
#   3. verifies the ASR rules landed on WIN11-01.
#
# Usage:
#   ./deploy-defender-policy.sh            # audit mode (default)
#   MODE=Block ./deploy-defender-policy.sh # flip ASR + Network Protection to block
#
set -euo pipefail

RG="${RESOURCE_GROUP:-rg-mdlab}"
MODE="${MODE:-Audit}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MEMBERS=(SRV01 WIN11-01 WIN11-02 WIN11-03)

command -v az >/dev/null || { echo "Azure CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first." >&2; exit 1; }

# One run-command per VM at a time - wait out the conflict.
invoke_rc() {  # invoke_rc <vm> <script-file> [extra inline script]
  local vm="$1" file="$2" attempt out
  for attempt in $(seq 1 8); do
    if out="$(az vm run-command invoke -g "$RG" -n "$vm" \
                --command-id RunPowerShellScript --scripts "@$file" \
                --query "value[].message" -o tsv --only-show-errors 2>&1)"; then
      printf '%s\n' "$out"; return 0
    fi
    if printf '%s' "$out" | grep -qiE 'in progress|Conflict'; then
      echo "  $vm busy; waiting 30s (attempt $attempt/8)..."; sleep 30; continue
    fi
    echo "  $vm error: $out" >&2; return 1
  done
  echo "  $vm still busy after retries." >&2; return 1
}

invoke_inline() {  # invoke_inline <vm> <powershell>
  local vm="$1" ps="$2" attempt out
  for attempt in $(seq 1 8); do
    if out="$(az vm run-command invoke -g "$RG" -n "$vm" \
                --command-id RunPowerShellScript --scripts "$ps" \
                --query "value[].message" -o tsv --only-show-errors 2>&1)"; then
      printf '%s\n' "$out"; return 0
    fi
    if printf '%s' "$out" | grep -qiE 'in progress|Conflict'; then
      echo "  $vm busy; waiting 30s (attempt $attempt/8)..."; sleep 30; continue
    fi
    echo "  $vm error: $out" >&2; return 1
  done
  return 1
}

echo "=== 1/3 Create + link GPOs on DC01 (mode: $MODE) ==="
TMP="$(mktemp -t defpolicy.XXXXXX.ps1)"
sed "s/\$Mode = 'Audit'/\$Mode = '$MODE'/" "$DIR/scripts/New-DefenderPolicyGpo.ps1" > "$TMP"
invoke_rc DC01 "$TMP"
rm -f "$TMP"

echo
echo "=== 2/3 Refresh policy on members ==="
for vm in "${MEMBERS[@]}"; do
  echo "-- $vm --"
  invoke_inline "$vm" "gpupdate /target:computer /force | Out-Null; 'gpupdate done on ' + \$env:COMPUTERNAME" || echo "  (refresh failed on $vm)"
done

echo
echo "=== 3/3 Verify ASR rules on WIN11-01 ==="
invoke_inline WIN11-01 "\$p = Get-MpPreference; for (\$i=0; \$i -lt \$p.AttackSurfaceReductionRules_Ids.Count; \$i++) { '{0} = {1}' -f \$p.AttackSurfaceReductionRules_Ids[\$i], \$p.AttackSurfaceReductionRules_Actions[\$i] }" \
  || echo "  (verify failed - rules may need a few minutes to apply)"

echo
echo "Done. Action code 2 = AuditMode, 1 = Block, 0 = Off."
echo "Audit hits surface in Defender's Operational log and the lab's endpoint DCR"
echo "(Event table). Flip to enforce later:  MODE=Block ./deploy-defender-policy.sh"
