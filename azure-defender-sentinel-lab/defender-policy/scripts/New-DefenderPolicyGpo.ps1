<#
.SYNOPSIS
    Creates Group Policy Objects that apply a Microsoft Defender Antivirus
    baseline plus Attack Surface Reduction (ASR) rules in AUDIT mode, for the
    lab's servers and Windows 11 workstations.

.DESCRIPTION
    Run on DC01 (elevated). It:
      1. ensures OU=Servers and OU=Workstations under OU=Lab exist,
      2. moves SRV01 into OU=Servers and the WIN11 clients into OU=Workstations
         (they domain-joined into the default Computers container),
      3. creates two GPOs - one for servers, one for workstations - each setting:
           * Defender AV: real-time + behavior + script scanning ON, cloud
             protection (MAPS Advanced), sample submission, cloud block level
             High, PUA protection ON,
           * Network Protection: AUDIT,
           * all ASR rules: AUDIT,
      4. links the servers GPO to OU=Servers and the Domain Controllers OU
         (so DC01 is covered too), and the workstations GPO to OU=Workstations.

    Audit mode means the rules log what they WOULD block (Defender event log /
    the lab's endpoint DCR) without actually blocking - safe to observe first.
    Flip to Block later by re-running with -Mode Block.

.EXAMPLE
    .\New-DefenderPolicyGpo.ps1
    .\New-DefenderPolicyGpo.ps1 -Mode Block
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Block')]
    [string] $Mode = 'Audit',
    [bool]   $IncludeDomainController = $true
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Import-Module GroupPolicy

# Audit=2, Block=1 for ASR and Network Protection.
$asrAction = if ($Mode -eq 'Block') { 1 } else { 2 }
$npValue   = if ($Mode -eq 'Block') { 1 } else { 2 }

$domain   = Get-ADDomain
$domainDn = $domain.DistinguishedName
$labOu    = "OU=Lab,$domainDn"
$serversOu      = "OU=Servers,$labOu"
$workstationsOu = "OU=Workstations,$labOu"
$dcOu           = "OU=Domain Controllers,$domainDn"

# --- 1. OUs ---------------------------------------------------------------
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$labOu'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name 'Lab' -Path $domainDn -ProtectedFromAccidentalDeletion $false
}
foreach ($ou in @('Servers', 'Workstations')) {
    $dn = "OU=$ou,$labOu"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path $labOu -ProtectedFromAccidentalDeletion $false
    }
}

# --- 2. Place computer objects --------------------------------------------
function Move-LabComputer {
    param([string] $Name, [string] $Target)
    $c = Get-ADComputer -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    if ($c -and $c.DistinguishedName -notmatch [regex]::Escape($Target)) {
        Move-ADObject -Identity $c.DistinguishedName -TargetPath $Target
        Write-Output "Moved $Name -> $Target"
    }
}
Move-LabComputer -Name 'SRV01' -Target $serversOu
foreach ($n in @('WIN11-01', 'WIN11-02', 'WIN11-03')) { Move-LabComputer -Name $n -Target $workstationsOu }

# --- ASR rule GUIDs -------------------------------------------------------
$asrRules = @(
    '56a863a9-875e-4185-98a7-b882c64b5ce5' # Block abuse of exploited vulnerable signed drivers
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' # Block Adobe Reader child processes
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' # Block Office apps creating child processes
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' # Block credential stealing from LSASS
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' # Block executable content from email/webmail
    '01443614-cd74-433a-b99e-2ecdc07bfc25' # Block untrusted/unsigned from USB
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' # Block obfuscated scripts
    'd3e037e1-3eb8-44c8-a917-57927947596d' # Block JS/VBS launching downloaded content
    '3b576869-a4ec-4529-8536-b80a7769e899' # Block Office apps creating executable content
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' # Block Office apps injecting into other processes
    '26190899-1602-49e8-8b27-eb1d0a1ce869' # Block Office comms child processes
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' # Block persistence via WMI event subscription
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' # Block process creations from PSExec and WMI
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' # Block Win32 API calls from Office macros
    'c1db55ab-c21a-4637-bb3f-a12568109d35' # Advanced ransomware protection
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' # Block untrusted/unsigned from USB (2)
    '01443614-cd74-433a-b99e-2ecdc07bfc25' # (dup guard - Set-GPRegistryValue is idempotent)
)

$defRoot = 'HKLM\Software\Policies\Microsoft\Windows Defender'
$egRoot  = "$defRoot\Windows Defender Exploit Guard"

function Set-DefenderPolicy {
    param([string] $GpoName)

    if (-not (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue)) {
        New-GPO -Name $GpoName -Comment "Lab Defender AV baseline + ASR ($Mode mode)" | Out-Null
        Write-Output "Created GPO '$GpoName'."
    } else {
        Write-Output "Updating GPO '$GpoName'."
    }

    # --- Antivirus baseline (protective) ---
    Set-GPRegistryValue -Name $GpoName -Key "$defRoot\Real-Time Protection" -ValueName 'DisableRealtimeMonitoring' -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "$defRoot\Real-Time Protection" -ValueName 'DisableBehaviorMonitoring' -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "$defRoot\Real-Time Protection" -ValueName 'DisableScriptScanning' -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "$defRoot\Real-Time Protection" -ValueName 'DisableIOAVProtection' -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "$defRoot\Spynet" -ValueName 'SpynetReporting' -Type DWord -Value 2 | Out-Null   # MAPS Advanced
    Set-GPRegistryValue -Name $GpoName -Key "$defRoot\Spynet" -ValueName 'SubmitSamplesConsent' -Type DWord -Value 1 | Out-Null # send safe samples
    Set-GPRegistryValue -Name $GpoName -Key $defRoot -ValueName 'PUAProtection' -Type DWord -Value 1 | Out-Null                # block PUA
    Set-GPRegistryValue -Name $GpoName -Key "$defRoot\MpEngine" -ValueName 'MpCloudBlockLevel' -Type DWord -Value 2 | Out-Null # High
    Set-GPRegistryValue -Name $GpoName -Key "$defRoot\MpEngine" -ValueName 'MpBafsExtendedTimeout' -Type DWord -Value 50 | Out-Null

    # --- Network Protection (audit) ---
    Set-GPRegistryValue -Name $GpoName -Key "$egRoot\Network Protection" -ValueName 'EnableNetworkProtection' -Type DWord -Value $npValue | Out-Null

    # --- ASR rules (audit) ---
    Set-GPRegistryValue -Name $GpoName -Key "$egRoot\ASR" -ValueName 'ExploitGuard_ASR_Rules' -Type DWord -Value 1 | Out-Null
    foreach ($guid in ($asrRules | Select-Object -Unique)) {
        Set-GPRegistryValue -Name $GpoName -Key "$egRoot\ASR\Rules" -ValueName $guid -Type String -Value "$asrAction" | Out-Null
    }
    Write-Output "  Applied AV baseline + $((($asrRules | Select-Object -Unique)).Count) ASR rules ($Mode) + Network Protection ($Mode)."
}

function Link-Gpo {
    param([string] $GpoName, [string] $Target)
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$Target'" -ErrorAction SilentlyContinue)) {
        Write-Warning "OU not found, skipping link: $Target"; return
    }
    $links = (Get-GPInheritance -Target $Target).GpoLinks.DisplayName
    if ($links -notcontains $GpoName) {
        New-GPLink -Name $GpoName -Target $Target -LinkEnabled Yes | Out-Null
        Write-Output "Linked '$GpoName' -> $Target"
    } else {
        Write-Output "'$GpoName' already linked to $Target"
    }
}

# --- 3 & 4. Create + link -------------------------------------------------
$serverGpo = "Lab - Defender Baseline - Servers ($Mode)"
$wksGpo    = "Lab - Defender Baseline - Workstations ($Mode)"

Set-DefenderPolicy -GpoName $serverGpo
Set-DefenderPolicy -GpoName $wksGpo

Link-Gpo -GpoName $serverGpo -Target $serversOu
if ($IncludeDomainController) { Link-Gpo -GpoName $serverGpo -Target $dcOu }
Link-Gpo -GpoName $wksGpo -Target $workstationsOu

Write-Output ""
Write-Output "Done. Run 'gpupdate /force' on each member (or wait ~90 min), then verify with Get-MpPreference."
