#!/bin/bash
# CyberShield RedTeam — Vulnerability Scan
# Weekly deep vulnerability scan using Nmap vuln scripts + Nikto
# No exploitation — identification only

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="/opt/cybershield/redteam/reports"
LOG_DIR="/opt/cybershield/redteam/logs"
REPORT_FILE="$REPORT_DIR/vulnscan_${TIMESTAMP}.txt"

# ── AUTHORIZED TARGETS ─────────────────────────────────────────
VPS_IP="sarge.cloud"
WEB_TARGET="https://sarge.cloud:8443"
# ───────────────────────────────────────────────────────────────

mkdir -p "$REPORT_DIR" "$LOG_DIR"

echo "=============================================" | tee "$REPORT_FILE"
echo "CYBERSHIELD REDTEAM — VULNERABILITY SCAN"    | tee -a "$REPORT_FILE"
echo "Date: $(date)"                               | tee -a "$REPORT_FILE"
echo "Engagement: Vulnerability ID (no exploitation)" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# ── PHASE 1: Nmap Vulnerability Scripts ────────────────────────
echo "[PHASE 1] Nmap vulnerability scan: $VPS_IP" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"

nmap -sV \
  --script="vuln,exploit" \
  --script-args="unsafe=0" \
  -T3 \
  -p 22,80,443,8443,1514,1515,55000,9200,5601 \
  -oN "$REPORT_DIR/nmap_vuln_${TIMESTAMP}.txt" \
  "$VPS_IP" 2>/dev/null | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"

# ── PHASE 2: Nikto Web Scan ────────────────────────────────────
echo "[PHASE 2] Nikto web application scan: $WEB_TARGET" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"

nikto \
  -h "$WEB_TARGET" \
  -ssl \
  -Tuning 123457890abc \
  -maxtime 600 \
  -output "$REPORT_DIR/nikto_${TIMESTAMP}.txt" \
  -Format txt 2>/dev/null | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"

# ── PHASE 3: TLS/SSL Check ─────────────────────────────────────
echo "[PHASE 3] TLS configuration check" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"

nmap -sV \
  --script="ssl-enum-ciphers,ssl-cert,ssl-dh-params,ssl-poodle,ssl-heartbleed" \
  -p 443,8443 \
  "$VPS_IP" 2>/dev/null | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"

# ── PHASE 4: SSH Configuration Check ──────────────────────────
echo "[PHASE 4] SSH security check" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"

nmap -sV \
  --script="ssh-auth-methods,ssh2-enum-algos,ssh-hostkey" \
  -p 22 \
  "$VPS_IP" 2>/dev/null | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "VULN SCAN COMPLETE: $(date)"                 | tee -a "$REPORT_FILE"
echo "Report: $REPORT_FILE"                        | tee -a "$REPORT_FILE"
echo "ACTION: Review findings and route to VulnScan agent for risk scoring" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"

logger -t "cybershield-redteam" -p local0.warning \
  "VULN SCAN COMPLETE: report=$REPORT_FILE"

echo ""
echo "[+] Vulnerability scan complete."
echo "[+] Report: $REPORT_FILE"
echo "[+] Next step: Feed findings to VulnScan agent for CVSS scoring."
