#!/bin/bash
# CyberShield RedTeam — Install Scheduled Scan Cron Jobs
# Run once on the VPS to activate automated scanning schedule

SCRIPTS_DIR="/opt/cybershield/redteam/scripts"

# Make all scripts executable
chmod +x "$SCRIPTS_DIR"/*.sh

# Install cron jobs
crontab -l 2>/dev/null > /tmp/cs_crontab_backup.txt

cat >> /tmp/cs_crontab_backup.txt << 'EOF'

# CyberShield RedTeam — Automated Scans
# Daily recon scan at 03:00
0 3 * * * /opt/cybershield/redteam/scripts/recon-scan.sh >> /opt/cybershield/redteam/logs/cron.log 2>&1

# Weekly vulnerability scan — Sunday at 03:30
30 3 * * 0 /opt/cybershield/redteam/scripts/vuln-scan.sh >> /opt/cybershield/redteam/logs/cron.log 2>&1

# Weekly web app test — Saturday at 02:00
0 2 * * 6 /opt/cybershield/redteam/scripts/web-app-test.sh >> /opt/cybershield/redteam/logs/cron.log 2>&1
EOF

crontab /tmp/cs_crontab_backup.txt
rm /tmp/cs_crontab_backup.txt

echo "[+] RedTeam scan schedule installed:"
echo "    Daily 03:00    — Recon scan"
echo "    Sunday 03:30   — Vulnerability scan"
echo "    Saturday 02:00 — Web app test"
echo ""
echo "Verify with: crontab -l"
