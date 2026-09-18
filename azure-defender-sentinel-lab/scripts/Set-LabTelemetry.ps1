<#
.SYNOPSIS
    Turns on the Windows auditing and Microsoft Defender settings the lab's
    detections depend on.

.DESCRIPTION
    Out of the box a Windows VM logs far less than a Sentinel rule expects. This
    script enables:

      * Advanced audit policy for logon, process creation, account and group
        management, and (on a DC) directory service access
      * Command line capture in event 4688 - without this, 4688 tells you a
        process ran but not what it was told to do
      * PowerShell script block and module logging (4103/4104)
      * Microsoft Defender Antivirus cloud protection, sample submission, PUA
        blocking, and the attack surface reduction rules

    ASR rules default to Audit here, not Block. A lab you cannot run tooling on
    is not much of a lab - flip -AsrMode Block once you want to see prevention.
#>
[CmdletBinding()]
param(
    [ValidateSet('DomainController', 'Server', 'Client')]
    [string] $Role = 'Client',

    [ValidateSet('Audit', 'Block', 'Disabled')]
    [string] $AsrMode = 'Audit'
)

$ErrorActionPreference = 'Continue'
$LogDir = 'C:\LabSetup\Logs'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
Start-Transcript -Path (Join-Path $LogDir 'Set-LabTelemetry.log') -Append

Write-Host "=== Lab telemetry configuration ($Role) ==="

# --- Advanced audit policy -------------------------------------------------
$subcategories = @(
    'Logon', 'Logoff', 'Account Lockout', 'Special Logon', 'Other Logon/Logoff Events',
    'Process Creation', 'Process Termination',
    'User Account Management', 'Security Group Management', 'Computer Account Management',
    'Authentication Policy Change', 'Authorization Policy Change', 'Audit Policy Change',
    'Sensitive Privilege Use', 'Security System Extension', 'System Integrity',
    'Credential Validation', 'Other Object Access Events', 'File Share', 'Detailed File Share',
    'Removable Storage', 'Registry', 'SAM'
)
foreach ($sc in $subcategories) {
    & auditpol.exe /set /subcategory:"$sc" /success:enable /failure:enable | Out-Null
}

if ($Role -eq 'DomainController') {
    foreach ($sc in @('Directory Service Access', 'Directory Service Changes',
                      'Kerberos Authentication Service', 'Kerberos Service Ticket Operations')) {
        & auditpol.exe /set /subcategory:"$sc" /success:enable /failure:enable | Out-Null
    }
}

# --- Command line in 4688 --------------------------------------------------
$auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $auditKey -Force | Out-Null
Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord

# --- PowerShell logging ----------------------------------------------------
$sbl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $sbl -Force | Out-Null
Set-ItemProperty -Path $sbl -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord

$ml = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path "$ml\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path $ml -Name 'EnableModuleLogging' -Value 1 -Type DWord
Set-ItemProperty -Path "$ml\ModuleNames" -Name '*' -Value '*' -Type String

$tr = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
New-Item -Path $tr -Force | Out-Null
Set-ItemProperty -Path $tr -Name 'EnableTranscripting' -Value 1 -Type DWord
Set-ItemProperty -Path $tr -Name 'EnableInvocationHeader' -Value 1 -Type DWord
Set-ItemProperty -Path $tr -Name 'OutputDirectory' -Value 'C:\LabSetup\Logs\PSTranscripts' -Type String

# --- Event log sizing ------------------------------------------------------
& wevtutil.exe sl Security /ms:536870912
& wevtutil.exe sl 'Microsoft-Windows-PowerShell/Operational' /ms:268435456

# --- Microsoft Defender Antivirus -----------------------------------------
try {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendAllSamples
    Set-MpPreference -PUAProtection Enabled
    Set-MpPreference -CloudBlockLevel High
    Set-MpPreference -CloudExtendedTimeout 50
    # 1 = Block, 2 = Audit. Windows PowerShell 5.1 has no ternary operator.
    if ($AsrMode -eq 'Block') { Set-MpPreference -EnableNetworkProtection 1 }
    else { Set-MpPreference -EnableNetworkProtection 2 }
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Write-Host 'Defender Antivirus preferences applied.'
} catch {
    Write-Warning "Defender preference configuration failed: $($_.Exception.Message)"
}

# --- Attack surface reduction ---------------------------------------------
if ($AsrMode -ne 'Disabled') {
    $asrAction = if ($AsrMode -eq 'Block') { 'Enabled' } else { 'AuditMode' }
    $asrRules = @(
        '56a863a9-875e-4185-98a7-b882c64b5ce5' # Block abuse of exploited vulnerable signed drivers
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' # Block Adobe Reader child processes
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' # Block Office apps creating child processes
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' # Block credential stealing from LSASS
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' # Block executable content from email/webmail
        '01443614-cd74-433a-b99e-2ecdc07bfc25' # Block untrusted/unsigned processes from USB
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' # Block execution of potentially obfuscated scripts
        'd3e037e1-3eb8-44c8-a917-57927947596d' # Block JS/VBS from launching downloaded content
        '3b576869-a4ec-4529-8536-b80a7769e899' # Block Office apps creating executable content
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' # Block Office apps injecting into other processes
        '26190899-1602-49e8-8b27-eb1d0a1ce869' # Block Office comms app child processes
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' # Block persistence through WMI event subscription
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' # Block process creations from PSExec and WMI
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' # Block untrusted and unsigned processes from USB
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' # Block Win32 API calls from Office macros
        'c1db55ab-c21a-4637-bb3f-a12568109d35' # Use advanced protection against ransomware
    )
    try {
        foreach ($rule in $asrRules) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions $asrAction
        }
        Write-Host "ASR rules set to $asrAction."
    } catch {
        Write-Warning "ASR configuration failed: $($_.Exception.Message)"
    }
}

Write-Host 'Lab telemetry configuration complete.'
Stop-Transcript
