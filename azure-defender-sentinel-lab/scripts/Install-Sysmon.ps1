<#
.SYNOPSIS
    Installs Sysinternals Sysmon with a detection-oriented configuration.

.DESCRIPTION
    Pulls Sysmon from download.sysinternals.com and, by default, the
    SwiftOnSecurity community configuration. Both are downloaded at deploy time,
    so the VM needs outbound HTTPS - the NAT Gateway in this lab provides it.

    Sysmon writes to Microsoft-Windows-Sysmon/Operational, which the lab's
    endpoint Data Collection Rule forwards into the Log Analytics Event table.

    Re-running this updates the configuration in place rather than reinstalling.
#>
[CmdletBinding()]
param(
    [string] $SysmonUri  = 'https://download.sysinternals.com/files/Sysmon.zip',
    [string] $ConfigUri  = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [string] $WorkingDir = 'C:\LabSetup\Sysmon'
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

New-Item -Path $WorkingDir -ItemType Directory -Force | Out-Null

function Invoke-Download {
    param([string] $Uri, [string] $OutFile)
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 120
            return
        } catch {
            Write-Warning "Download attempt $attempt for $Uri failed: $($_.Exception.Message)"
            Start-Sleep -Seconds ([Math]::Pow(2, $attempt))
        }
    }
    throw "Unable to download $Uri"
}

$zip       = Join-Path $WorkingDir 'Sysmon.zip'
$configXml = Join-Path $WorkingDir 'sysmonconfig.xml'

Write-Host 'Downloading Sysmon...'
Invoke-Download -Uri $SysmonUri -OutFile $zip

Write-Host 'Downloading Sysmon configuration...'
Invoke-Download -Uri $ConfigUri -OutFile $configXml

Expand-Archive -Path $zip -DestinationPath $WorkingDir -Force

$exe = Join-Path $WorkingDir 'Sysmon64.exe'
if (-not (Test-Path $exe)) { $exe = Join-Path $WorkingDir 'Sysmon.exe' }
if (-not (Test-Path $exe)) { throw 'Sysmon executable not found in the downloaded archive.' }

$installed = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1

if ($installed) {
    Write-Host "Sysmon already installed as $($installed.Name); applying configuration."
    & $exe -accepteula -c $configXml
} else {
    Write-Host 'Installing Sysmon.'
    & $exe -accepteula -i $configXml
}

if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1242) {
    # 1242 = already installed, which -i returns on a re-run.
    throw "Sysmon returned exit code $LASTEXITCODE"
}

# Give the operational channel enough room that a busy lab does not roll events
# away before AMA ships them.
& wevtutil.exe sl Microsoft-Windows-Sysmon/Operational /ms:268435456

Write-Host 'Sysmon ready.'
