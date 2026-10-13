#!/bin/bash
# CyberShield RedTeam — Recon Scan
# Runs daily non-intrusive discovery against authorized targets
# Feeds findings to Wazuh and Sarge

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="/opt/cybershield/redteam/reports"
LOG_DIR="/opt/cybershield/redteam/logs"
REPORT_FILE="$REPORT_DIR/recon_${TIMESTAMP}.txt"
LOG_FILE="$LOG_DIR/recon_${TIMESTAMP}.log"

# ── AUTHORIZED TARGETS ─────────────────────────────────────────
# Edit this list to match your authorized scope
TARGETS=(
  "127.0.0.1"           # VPS loopback
  "sarge.cloud"         # Your domain
  # "192.168.1.0/24"   # Uncomment and set your internal range
)
# ───────────────────────────────────────────────────────────────

mkdir -p "$REPORT_DIR" "$LOG_DIR"
chmod 700 "$REPORT_DIR" "$LOG_DIR"

echo "=============================================" | tee "$REPORT_FILE"
echo "CYBERSHIELD REDTEAM — RECON SCAN"            | tee -a "$REPORT_FILE"
echo "Date: $(date)"                                | tee -a "$REPORT_FILE"
echo "Operator: Automated scheduled scan"          | tee -a "$REPORT_FILE"
echo "Engagement type: Reconnaissance (non-intrusive)" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

for TARGET in "${TARGETS[@]}"; do
  echo "[*] Scanning: $TARGET" | tee -a "$REPORT_FILE" "$LOG_FILE"
  echo "--------------------------------------------" | tee -a "$REPORT_FILE"

  # Service version detection + safe scripts only
  nmap -sV -sC \
    --script="safe,discovery" \
    --script-timeout=30s \
    -T3 \
    -oN "$REPORT_DIR/nmap_${TARGET//\//_}_${TIMESTAMP}.txt" \
    "$TARGET" 2>>"$LOG_FILE" | tee -a "$REPORT_FILE"

  echo "" | tee -a "$REPORT_FILE"
done

echo "=============================================" | tee -a "$REPORT_FILE"
echo "SCAN COMPLETE: $(date)"                       | tee -a "$REPORT_FILE"
echo "Full report: $REPORT_FILE"                    | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"

# Send summary to Wazuh as a custom alert
logger -t "cybershield-redteam" -p local0.info \
  "RECON SCAN COMPLETE: report=$REPORT_FILE targets=${TARGETS[*]}"

echo ""
echo "[+] Recon scan complete. Report saved to: $REPORT_FILE"
echo "[+] Alert sent to Wazuh log collector."
