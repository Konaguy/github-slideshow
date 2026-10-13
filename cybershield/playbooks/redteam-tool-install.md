# RedTeam Tool Installation Guide
## Install on: Hostinger VPS (sarge.cloud)

---

## PART 1: Nmap

### Install
```bash
apt install -y nmap
```

### Verify
```bash
nmap --version
```

### Test (against your own VPS loopback only)
```bash
nmap -sV -sC 127.0.0.1
```

---

## PART 2: Nikto (Web Scanner)

### Install
```bash
apt install -y nikto
```

### Verify
```bash
nikto -Version
```

### Test against your own dashboard
```bash
nikto -h https://sarge.cloud:8443 -ssl
```

---

## PART 3: Hydra (Credential Testing)

### Install
```bash
apt install -y hydra
```

### Verify
```bash
hydra -h 2>&1 | head -5
```

---

## PART 4: Metasploit Framework

### Install
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
chmod 755 /tmp/msfinstall
/tmp/msfinstall
```

### Verify
```bash
msfconsole -v
```

### Initialize database (required for storing scan results)
```bash
systemctl start postgresql
msfdb init
```

### Verify DB connected
```bash
msfconsole -q -x "db_status; exit"
```

---

## PART 5: Create RedTeam Directory Structure

```bash
mkdir -p /opt/cybershield/redteam/{scripts,reports,logs,wordlists}

# Set permissions — only root can read/write
chmod 700 /opt/cybershield/redteam
chmod 700 /opt/cybershield/redteam/scripts
chmod 700 /opt/cybershield/redteam/reports
```

---

## PART 6: Download Wordlists for Hydra

```bash
# Install SecLists — industry standard wordlist collection
apt install -y seclists

# Or manually get the most useful ones
mkdir -p /opt/cybershield/redteam/wordlists

# Top passwords list
cp /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
   /opt/cybershield/redteam/wordlists/

# Top usernames
cp /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
   /opt/cybershield/redteam/wordlists/
```

---

## PART 7: Verify All Tools Installed

```bash
echo "=== RedTeam Tool Check ===" && \
echo -n "Nmap: " && nmap --version | head -1 && \
echo -n "Nikto: " && nikto -Version 2>&1 | head -1 && \
echo -n "Hydra: " && hydra -h 2>&1 | grep "Hydra v" && \
echo -n "Metasploit: " && msfconsole -v 2>/dev/null | head -1 && \
echo "All tools ready."
```

---

## PART 8: Set Up Logging

All RedTeam scans log to `/opt/cybershield/redteam/logs/` with timestamps:

```bash
# Create log rotation config
cat > /etc/logrotate.d/cybershield-redteam << 'EOF'
/opt/cybershield/redteam/logs/*.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
}
EOF
```
