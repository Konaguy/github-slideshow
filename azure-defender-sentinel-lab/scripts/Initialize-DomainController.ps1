<#
.SYNOPSIS
    Promotes the VM to the first domain controller of a new AD DS forest and
    installs the lab telemetry stack.

.DESCRIPTION
    Runs once, from the Azure Custom Script Extension, on DC01.

    Promotion needs a reboot, and the Custom Script Extension has no way to
    survive one. So this script promotes with -NoRebootOnCompletion, registers a
    scheduled task that runs Complete-DomainController.ps1 at next startup, then
    schedules the reboot far enough out that the extension can report success
    first. Directory seeding happens in that follow-up task.

.NOTES
    Everything is logged to C:\LabSetup\Logs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $DomainName,
    [Parameter(Mandatory)] [string] $NetbiosName,
    [Parameter(Mandatory)] [string] $SafeModePassword,
    [Parameter(Mandatory)] [string] $ScriptsBaseUri,
    [string[]] $DnsForwarders = @('168.63.129.16')
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LabRoot = 'C:\LabSetup'
$LogDir  = Join-Path $LabRoot 'Logs'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
Start-Transcript -Path (Join-Path $LogDir 'Initialize-DomainController.log') -Append

function Get-LabScript {
    param([string] $Name)
    $dest = Join-Path $LabRoot $Name
    $uri  = ($ScriptsBaseUri.TrimEnd('/')) + '/' + $Name
    Write-Host "Downloading $uri"
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            Invoke-WebRequest -Uri $uri -OutFile $dest -UseBasicParsing -TimeoutSec 60
            return $dest
        } catch {
            Write-Warning "Attempt $attempt failed: $($_.Exception.Message)"
            Start-Sleep -Seconds ([Math]::Pow(2, $attempt))
        }
    }
    throw "Could not download $Name from $ScriptsBaseUri"
}

try {
    Write-Host "=== Lab DC bootstrap: $DomainName ($NetbiosName) ==="

    # Pull the helper scripts down first. Once DNS flips to this box, outbound
    # name resolution depends on the DNS role being healthy, so fetch early.
    $telemetryScript = Get-LabScript -Name 'Set-LabTelemetry.ps1'
    $sysmonScript    = Get-LabScript -Name 'Install-Sysmon.ps1'
    $completeScript  = Get-LabScript -Name 'Complete-DomainController.ps1'

    Write-Host '--- Audit policy, PowerShell logging, Defender settings ---'
    & $telemetryScript -Role DomainController

    Write-Host '--- Sysmon ---'
    & $sysmonScript

    Write-Host '--- AD DS and DNS roles ---'
    Install-WindowsFeature -Name AD-Domain-Services, DNS, RSAT-AD-Tools, RSAT-ADDS, RSAT-DNS-Server -IncludeManagementTools

    Write-Host '--- Registering post-reboot completion task ---'
    $taskCmd = "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$completeScript`" -DomainName `"$DomainName`" -NetbiosName `"$NetbiosName`" -DnsForwarders `"$($DnsForwarders -join ',')`""
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskCmd
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromHours(2))
    Register-ScheduledTask -TaskName 'LabCompleteDomainController' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    Write-Host '--- Promoting to forest root domain controller ---'
    Import-Module ADDSDeployment
    $smsa = ConvertTo-SecureString -String $SafeModePassword -AsPlainText -Force

    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -SafeModeAdministratorPassword $smsa `
        -InstallDns `
        -DomainMode 'WinThreshold' `
        -ForestMode 'WinThreshold' `
        -DatabasePath 'C:\Windows\NTDS' `
        -LogPath 'C:\Windows\NTDS' `
        -SysvolPath 'C:\Windows\SYSVOL' `
        -NoRebootOnCompletion `
        -Force `
        -WarningAction SilentlyContinue

    Write-Host 'Promotion staged. Rebooting in 60 seconds so the extension can report success.'
    Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r', '/t', '60', '/c', '"Lab DC promotion"', '/f' -NoNewWindow
    exit 0
}
catch {
    Write-Error "DC bootstrap failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}
finally {
    Stop-Transcript
}
