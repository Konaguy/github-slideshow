#!/bin/bash
# CyberShield RedTeam — Web Application Test
# Full OWASP Top 10 assessment using Nikto + Nmap web scripts
# Targets: sarge.cloud web services

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="/opt/cybershield/redteam/reports"
REPORT_FILE="$REPORT_DIR/webapp_${TIMESTAMP}.txt"
TARGET_HOST="sarge.cloud"
TARGET_PORT="8443"
TARGET_URL="https://${TARGET_HOST}:${TARGET_PORT}"

mkdir -p "$REPORT_DIR"

echo "=============================================" | tee "$REPORT_FILE"
echo "CYBERSHIELD REDTEAM — WEB APPLICATION TEST"  | tee -a "$REPORT_FILE"
echo "Date: $(date)"                               | tee -a "$REPORT_FILE"
echo "Target: $TARGET_URL"                         | tee -a "$REPORT_FILE"
echo "Framework: OWASP Top 10"                     | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# ── CHECK 1: HTTP Security Headers ─────────────────────────────
echo "[CHECK 1] HTTP Security Headers" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"
echo "Testing for missing security headers (OWASP A05 — Security Misconfiguration)" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

curl -sk -I "$TARGET_URL" 2>/dev/null | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"
echo "EXPECTED HEADERS (flag if missing):" | tee -a "$REPORT_FILE"

HEADERS_RESPONSE=$(curl -sk -I "$TARGET_URL" 2>/dev/null)

for HEADER in \
  "Strict-Transport-Security" \
  "X-Content-Type-Options" \
  "X-Frame-Options" \
  "Content-Security-Policy" \
  "Referrer-Policy" \
  "Permissions-Policy"; do
  if echo "$HEADERS_RESPONSE" | grep -qi "$HEADER"; then
    echo "  [PASS] $HEADER: present" | tee -a "$REPORT_FILE"
  else
    echo "  [FAIL] $HEADER: MISSING — potential security misconfiguration" | tee -a "$REPORT_FILE"
  fi
done

echo "" | tee -a "$REPORT_FILE"

# ── CHECK 2: TLS Configuration ─────────────────────────────────
echo "[CHECK 2] TLS Configuration" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"
echo "Testing for weak protocols and ciphers (OWASP A02 — Cryptographic Failures)" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

nmap -sV \
  --script="ssl-enum-ciphers,ssl-poodle,ssl-heartbleed,ssl-dh-params" \
  -p "$TARGET_PORT" \
  "$TARGET_HOST" 2>/dev/null | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"

# ── CHECK 3: Open Ports and Attack Surface ─────────────────────
echo "[CHECK 3] Attack Surface — Open Ports" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"
echo "Mapping exposed services (OWASP A05 — Security Misconfiguration)" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

nmap -sV -sC \
  --script="http-methods,http-title,http-server-header,http-auth-finder" \
  -p 80,443,8080,8443,8888,3000,5000,9200,5601 \
  "$TARGET_HOST" 2>/dev/null | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"

# ── CHECK 4: Full Nikto Scan ───────────────────────────────────
echo "[CHECK 4] Nikto Full Web Scan" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"
echo "Checking for known vulnerabilities, misconfigs, and exposed files" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

nikto \
  -h "$TARGET_URL" \
  -ssl \
  -maxtime 900 \
  -Tuning 1234567890abcde \
  -output "$REPORT_DIR/nikto_full_${TIMESTAMP}.txt" \
  -Format txt 2>/dev/null | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"

# ── CHECK 5: Sensitive File Exposure ──────────────────────────
echo "[CHECK 5] Sensitive File and Directory Exposure" | tee -a "$REPORT_FILE"
echo "----------------------------------------------" | tee -a "$REPORT_FILE"
echo "Checking for exposed config files, backups, and admin panels" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

SENSITIVE_PATHS=(
  "/.env"
  "/config.yml"
  "/config.json"
  "/.git/config"
  "/backup.zip"
  "/admin"
  "/phpinfo.php"
  "/server-status"
  "/robots.txt"
  "/.well-known/security.txt"
)

for PATH_CHECK in "${SENSITIVE_PATHS[@]}"; do
  RESPONSE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET_URL$PATH_CHECK")
  if [ "$RESPONSE" = "200" ]; then
    echo "  [EXPOSED] $PATH_CHECK — HTTP $RESPONSE" | tee -a "$REPORT_FILE"
  elif [ "$RESPONSE" = "403" ]; then
    echo "  [EXISTS but FORBIDDEN] $PATH_CHECK — HTTP $RESPONSE" | tee -a "$REPORT_FILE"
  else
    echo "  [OK] $PATH_CHECK — HTTP $RESPONSE" | tee -a "$REPORT_FILE"
  fi
done

echo "" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "WEB APP TEST COMPLETE: $(date)"              | tee -a "$REPORT_FILE"
echo "Full report: $REPORT_FILE"                   | tee -a "$REPORT_FILE"
echo "Nikto detail: $REPORT_DIR/nikto_full_${TIMESTAMP}.txt" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Route findings to:"                          | tee -a "$REPORT_FILE"
echo "  - Ironclad: header misconfigs"             | tee -a "$REPORT_FILE"
echo "  - CertSentry: TLS issues"                  | tee -a "$REPORT_FILE"
echo "  - VulnScan: CVE matches from Nikto"        | tee -a "$REPORT_FILE"
echo "  - Sarge: executive summary"                | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"

logger -t "cybershield-redteam" -p local0.warning \
  "WEB APP TEST COMPLETE: target=$TARGET_URL report=$REPORT_FILE"
