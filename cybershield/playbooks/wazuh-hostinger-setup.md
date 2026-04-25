# Wazuh Manager Setup — Hostinger VPS
## Complete Installation Guide for CyberShield Analytics

---

## Prerequisites
- Hostinger VPS: Ubuntu 22.04 LTS, minimum 4GB RAM (8GB recommended), 2 vCPUs, 50GB SSD
- SSH access to your VPS
- Domain or static IP for your VPS

---

## PART 1: System Preparation

```bash
# Update system
apt update && apt upgrade -y

# Install dependencies
apt install -y curl wget gnupg apt-transport-https lsb-release ca-certificates

# Set hostname (replace with your actual hostname)
hostnamectl set-hostname wazuh-manager.yourdomain.com

# Configure /etc/hosts
echo "$(hostname -I | awk '{print $1}') wazuh-manager.yourdomain.com wazuh-manager" >> /etc/hosts

# Set timezone
timedatectl set-timezone America/New_York  # adjust to your timezone
```

---

## PART 2: Install Wazuh Manager (All-in-One)

```bash
# Download and run the Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Edit config.yml with your server details
# Replace <wazuh-manager-ip> with your VPS public IP
cat > config.yml << 'EOF'
nodes:
  indexer:
    - name: node-1
      ip: "<YOUR_VPS_PUBLIC_IP>"
  server:
    - name: wazuh-1
      ip: "<YOUR_VPS_PUBLIC_IP>"
  dashboard:
    - name: dashboard
      ip: "<YOUR_VPS_PUBLIC_IP>"
EOF

# Run installation (takes 10-20 minutes)
bash wazuh-install.sh -a

# Save the credentials output — you will not see them again
# Credentials are stored in wazuh-install-files.tar
```

After installation, access the Wazuh dashboard at:
`https://<YOUR_VPS_PUBLIC_IP>` (default: admin / admin — CHANGE THIS)

---

## PART 3: Firewall Configuration (Hostinger VPS)

```bash
# Install UFW if not present
apt install -y ufw

# Default: deny in, allow out
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (from your IP only — replace YOUR_OFFICE_IP)
ufw allow from YOUR_OFFICE_IP to any port 22

# Allow Wazuh dashboard (HTTPS)
ufw allow 443/tcp

# Allow Wazuh agent communication
ufw allow 1514/tcp
ufw allow 1514/udp
ufw allow 1515/tcp

# Allow Wazuh API (from your app server / local only)
ufw allow from 127.0.0.1 to any port 55000

# Enable firewall
ufw enable
ufw status verbose
```

Also configure in Hostinger panel: match these firewall rules in the VPS firewall/security group.

---

## PART 4: Harden Wazuh Manager SSH

```bash
# Edit SSH config
nano /etc/ssh/sshd_config

# Set these values:
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes
# MaxAuthTries 3
# ClientAliveInterval 300
# ClientAliveCountMax 2

# Restart SSH
systemctl restart sshd
```

---

## PART 5: Install Wazuh Agent on Windows 11

### Method A: Installer (Recommended for first deployment)
1. Download: `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi`
2. Run as Administrator:
```powershell
# Replace WAZUH_MANAGER with your VPS IP
msiexec.exe /i wazuh-agent-4.7.0-1.msi /q WAZUH_MANAGER="<YOUR_VPS_PUBLIC_IP>" WAZUH_AGENT_NAME="WIN11-ENDPOINT-01"
```
3. Start the service:
```powershell
NET START WazuhSvc
```

### Method B: Silent install via PowerShell (for deploying to multiple endpoints)
```powershell
$installer = "wazuh-agent-4.7.0-1.msi"
$manager = "<YOUR_VPS_PUBLIC_IP>"
$agentName = $env:COMPUTERNAME

# Download
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/$installer" -OutFile "C:\Temp\$installer"

# Install silently
Start-Process msiexec.exe -ArgumentList "/i C:\Temp\$installer /q WAZUH_MANAGER=$manager WAZUH_AGENT_NAME=$agentName" -Wait

# Start service
Start-Service -Name WazuhSvc
Set-Service -Name WazuhSvc -StartupType Automatic

# Verify
Get-Service WazuhSvc | Select Status, StartType
```

---

## PART 6: Install Sysmon on Windows 11

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Temp\Sysmon.zip"
Expand-Archive "C:\Temp\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"

# Download the CyberShield Sysmon config (from this repo)
# OR use the SwiftOnSecurity config as a baseline:
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmon-config.xml"

# Install Sysmon with config
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmon-config.xml

# Verify installation
Get-Service Sysmon64 | Select Status
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## PART 7: Configure Windows Audit Policy

```powershell
# Run as Administrator — set comprehensive audit policy for CyberShield agents

# Account Logon
AuditPol /set /subcategory:"Credential Validation" /success:enable /failure:enable
AuditPol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
AuditPol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
AuditPol /set /subcategory:"User Account Management" /success:enable /failure:enable
AuditPol /set /subcategory:"Security Group Management" /success:enable /failure:enable
AuditPol /set /subcategory:"Computer Account Management" /success:enable /failure:enable

# Logon/Logoff
AuditPol /set /subcategory:"Logon" /success:enable /failure:enable
AuditPol /set /subcategory:"Logoff" /success:enable /failure:enable
AuditPol /set /subcategory:"Special Logon" /success:enable /failure:enable
AuditPol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Object Access
AuditPol /set /subcategory:"File System" /success:enable /failure:enable
AuditPol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# Policy Change
AuditPol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
AuditPol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable

# Privilege Use
AuditPol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Process Tracking
AuditPol /set /subcategory:"Process Creation" /success:enable

# System
AuditPol /set /subcategory:"Security System Extension" /success:enable /failure:enable
AuditPol /set /subcategory:"System Integrity" /success:enable /failure:enable

# Verify
AuditPol /get /category:*
```

---

## PART 8: Configure WinRM for PatchMaster and IDGuard

```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Configure HTTPS (recommended over HTTP)
# First, create a self-signed cert (use a proper cert in production)
$cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My `
  -DnsName $env:COMPUTERNAME

# Create WinRM HTTPS listener
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS `
  -Address * -CertificateThumbPrint $cert.Thumbprint -Force

# Configure firewall for WinRM HTTPS
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound `
  -LocalPort 5986 -Protocol TCP -Action Allow `
  -RemoteAddress <YOUR_VPS_PUBLIC_IP>  # restrict to VPS only

# Create dedicated service account for CyberShield
net user svc_cybershield <strong_password> /add
net localgroup Administrators svc_cybershield /add

# Test connection from your VPS:
# Enter-PSSession -ComputerName <Windows11_IP> -Port 5986 -UseSSL `
#   -Credential (Get-Credential) -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck)
```

---

## PART 9: Enable PowerShell Script Block Logging

```powershell
# Enable PowerShell logging (critical for Ironclad and IDGuard)
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# Module logging
$modulePath = "$regPath\ModuleLogging"
New-Item -Path $modulePath -Force
Set-ItemProperty -Path $modulePath -Name "EnableModuleLogging" -Value 1
New-Item -Path "$modulePath\ModuleNames" -Force
Set-ItemProperty -Path "$modulePath\ModuleNames" -Name "*" -Value "*"

# Script block logging
$scriptBlockPath = "$regPath\ScriptBlockLogging"
New-Item -Path $scriptBlockPath -Force
Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockInvocationLogging" -Value 1

# Transcription logging
$transcriptionPath = "$regPath\Transcription"
New-Item -Path $transcriptionPath -Force
Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $transcriptionPath -Name "OutputDirectory" -Value "C:\PSLogs"
Set-ItemProperty -Path $transcriptionPath -Name "EnableInvocationHeader" -Value 1

New-Item -Path "C:\PSLogs" -ItemType Directory -Force
icacls "C:\PSLogs" /inheritance:d /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F"

Write-Host "PowerShell logging configured. Events appear in: Microsoft-Windows-PowerShell/Operational"
```

---

## PART 10: Verification Checklist

```bash
# On Wazuh Manager (Hostinger VPS):
systemctl status wazuh-manager    # should be: active (running)
systemctl status wazuh-indexer     # should be: active (running)
systemctl status wazuh-dashboard   # should be: active (running)

# Check agent is connected:
/var/ossec/bin/agent_control -l    # list connected agents
/var/ossec/bin/ossec-logtest       # test log parsing

# View recent alerts:
tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool
```

```powershell
# On Windows 11:
Get-Service WazuhSvc, Sysmon64 | Select Name, Status
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
Get-WinEvent -LogName Security -MaxEvents 10
Test-NetConnection -ComputerName <YOUR_VPS_PUBLIC_IP> -Port 1514
```

---

## Custom Wazuh Rules for CyberShield Agents
Place custom rules in `/var/ossec/etc/rules/cybershield_rules.xml`:

```xml
<!-- cybershield_rules.xml -->
<group name="cybershield,">

  <!-- IDGuard: Brute force -->
  <rule id="100300" level="10" frequency="10" timeframe="300">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>CyberShield IDGuard: Brute force on $(win.eventdata.targetUserName)</description>
    <group>authentication_failure,brute_force,</group>
    <mitre><id>T1110.001</id></mitre>
  </rule>

  <!-- IDGuard: Admin group change -->
  <rule id="100301" level="12">
    <if_sid>60144</if_sid>
    <field name="win.eventdata.targetUserName" type="pcre2">(?i)(domain admins|administrators|enterprise admins)</field>
    <description>CyberShield IDGuard: User added to privileged group $(win.eventdata.targetUserName)</description>
    <group>account_changed,privileged_access,</group>
    <mitre><id>T1098</id></mitre>
  </rule>

  <!-- Ironclad DLP: USB storage -->
  <rule id="100200" level="10">
    <if_sid>60106</if_sid>
    <field name="win.system.eventID">^2003$</field>
    <description>CyberShield Ironclad: USB mass storage connected on $(win.system.computer)</description>
    <group>dlp,usb,</group>
    <mitre><id>T1052.001</id></mitre>
  </rule>

  <!-- NetWatch: Tor/proxy connection (requires DNS logging) -->
  <rule id="100400" level="14">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.destinationHostname" type="pcre2">\.onion$|torproject\.org|proxysite\.</field>
    <description>CyberShield NetWatch: Tor/proxy connection from $(win.eventdata.sourceHostname)</description>
    <group>network,tor,exfiltration,</group>
    <mitre><id>T1090.003</id></mitre>
  </rule>

  <!-- Sarge: Critical combined alert threshold -->
  <rule id="100500" level="15">
    <if_sid>100300,100301,100400</if_sid>
    <description>CyberShield SARGE: Multiple critical events — manual review required</description>
    <group>sarge_escalation,</group>
  </rule>

</group>
```

After adding rules:
```bash
# Test rules syntax
/var/ossec/bin/ossec-logtest -t

# Restart Wazuh manager to load rules
systemctl restart wazuh-manager
```
