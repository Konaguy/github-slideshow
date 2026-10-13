#!/bin/bash
# CyberShield RedTeam — Credential Strength Test
# Tests password strength on authorized services using Hydra
#
# REQUIRES: Explicit operator authorization before each run
# REQUIRES: IDGuard notified to suppress lockout alerts during test
#
# Usage: ./credential-test.sh [ssh|winrm|wazuh] [target_ip]

SERVICE="${1:-ssh}"
TARGET="${2:-sarge.cloud}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="/opt/cybershield/redteam/reports"
REPORT_FILE="$REPORT_DIR/credtest_${SERVICE}_${TIMESTAMP}.txt"
WORDLIST_PASS="/opt/cybershield/redteam/wordlists/10k-most-common.txt"
WORDLIST_USER="/opt/cybershield/redteam/wordlists/top-usernames-shortlist.txt"

# ── SAFETY GATE ────────────────────────────────────────────────
echo "============================================="
echo "CYBERSHIELD REDTEAM — CREDENTIAL TEST"
echo "Service: $SERVICE"
echo "Target:  $TARGET"
echo "============================================="
echo ""
echo "WARNING: This test will attempt credential brute-forcing."
echo "         IDGuard must be notified to suppress false lockout alerts."
echo ""
read -p "Has operator authorized this test? (yes/no): " AUTHORIZED
if [ "$AUTHORIZED" != "yes" ]; then
  echo "[-] Test aborted — operator authorization required."
  exit 1
fi

read -p "Has IDGuard been notified to suppress lockout alerts? (yes/no): " IDGUARD_NOTIFIED
if [ "$IDGUARD_NOTIFIED" != "yes" ]; then
  echo "[-] Test aborted — notify IDGuard first to avoid false alerts."
  exit 1
fi

mkdir -p "$REPORT_DIR"

echo "=============================================" | tee "$REPORT_FILE"
echo "REDTEAM CREDENTIAL TEST"                      | tee -a "$REPORT_FILE"
echo "Date: $(date)"                                | tee -a "$REPORT_FILE"
echo "Service: $SERVICE | Target: $TARGET"          | tee -a "$REPORT_FILE"
echo "Operator authorized: YES"                     | tee -a "$REPORT_FILE"
echo "IDGuard notified: YES"                        | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

case "$SERVICE" in

  # ── SSH Test ──────────────────────────────────────────────────
  ssh)
    echo "[*] Testing SSH on $TARGET:22" | tee -a "$REPORT_FILE"
    echo "    Wordlist: top usernames x top 100 passwords" | tee -a "$REPORT_FILE"
    echo "    Max attempts: 100 per user | Delay: 1s between attempts" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    # Limit to top 100 passwords to avoid full lockout
    head -100 "$WORDLIST_PASS" > /tmp/cs_pass_limited.txt

    hydra -L "$WORDLIST_USER" \
          -P /tmp/cs_pass_limited.txt \
          -t 4 \
          -w 1 \
          -f \
          -o "$REPORT_DIR/hydra_ssh_${TIMESTAMP}.txt" \
          "$TARGET" ssh 2>/dev/null | tee -a "$REPORT_FILE"

    rm -f /tmp/cs_pass_limited.txt
    ;;

  # ── Wazuh Dashboard Test ──────────────────────────────────────
  wazuh)
    echo "[*] Testing Wazuh dashboard on $TARGET:8443" | tee -a "$REPORT_FILE"
    echo "    Testing common admin passwords only" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    # Only test a small set for web forms
    cat > /tmp/cs_wazuh_users.txt << 'EOF'
admin
wazuh
administrator
EOF

    cat > /tmp/cs_wazuh_pass.txt << 'EOF'
admin
password
wazuh
Admin123
Password1
changeme
123456
EOF

    hydra -L /tmp/cs_wazuh_users.txt \
          -P /tmp/cs_wazuh_pass.txt \
          -t 2 \
          -w 2 \
          -f \
          -o "$REPORT_DIR/hydra_wazuh_${TIMESTAMP}.txt" \
          -s 8443 \
          "$TARGET" https-form-post \
          "/auth/login:username=^USER^&password=^PASS^:F=Invalid" 2>/dev/null | tee -a "$REPORT_FILE"

    rm -f /tmp/cs_wazuh_users.txt /tmp/cs_wazuh_pass.txt
    ;;

  # ── WinRM Test ────────────────────────────────────────────────
  winrm)
    echo "[*] Testing WinRM on $TARGET:5986" | tee -a "$REPORT_FILE"
    echo "    Testing service account and common admin accounts" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    cat > /tmp/cs_winrm_users.txt << 'EOF'
Administrator
admin
svc_cybershield
EOF

    head -50 "$WORDLIST_PASS" > /tmp/cs_winrm_pass.txt

    hydra -L /tmp/cs_winrm_users.txt \
          -P /tmp/cs_winrm_pass.txt \
          -t 2 \
          -w 2 \
          -f \
          -o "$REPORT_DIR/hydra_winrm_${TIMESTAMP}.txt" \
          -s 5986 \
          "$TARGET" http-get "/wsman" 2>/dev/null | tee -a "$REPORT_FILE"

    rm -f /tmp/cs_winrm_users.txt /tmp/cs_winrm_pass.txt
    ;;

  *)
    echo "[-] Unknown service: $SERVICE"
    echo "    Usage: $0 [ssh|winrm|wazuh] [target]"
    exit 1
    ;;
esac

echo "" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "CREDENTIAL TEST COMPLETE: $(date)"           | tee -a "$REPORT_FILE"
echo "Report: $REPORT_FILE"                        | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "POST-TEST ACTIONS REQUIRED:"                 | tee -a "$REPORT_FILE"
echo "  1. Notify IDGuard test is complete"        | tee -a "$REPORT_FILE"
echo "  2. Route any found credentials to IDGuard for immediate reset" | tee -a "$REPORT_FILE"
echo "  3. Report findings to Sarge"               | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"

logger -t "cybershield-redteam" -p local0.warning \
  "CREDENTIAL TEST COMPLETE: service=$SERVICE target=$TARGET report=$REPORT_FILE"

echo ""
echo "[+] Test complete. Notify IDGuard that testing has ended."
