<#
.SYNOPSIS
    Installs an in-VM watchdog that DEALLOCATES this VM when no interactive
    session has had keyboard/mouse activity for N minutes (default 20).

.DESCRIPTION
    "No interaction" here means user input idle, not CPU idle. The watchdog runs
    every few minutes as SYSTEM, reads logged-on sessions with 'quser', and
    decides the VM is unattended when:
      * there are no Active sessions at all (login screen, or only disconnected
        sessions), OR
      * every Active session's idle time is >= the threshold.

    When unattended, it deallocates the VM via its managed identity (REST). The
    identity must hold Virtual Machine Contributor on this VM
    (install-idle-shutdown.sh grants it).

    Deallocate, not shutdown, so compute billing actually stops.
#>
[CmdletBinding()]
param(
    [int] $IdleMinutes    = 20,
    [int] $CheckEveryMins = 5,
    [string] $TaskName    = 'LabIdleInteractionShutdown'
)

$ErrorActionPreference = 'Stop'
$labRoot = 'C:\LabSetup'
New-Item -Path $labRoot -ItemType Directory -Force | Out-Null
New-Item -Path 'C:\LabSetup\Logs' -ItemType Directory -Force | Out-Null
$worker = Join-Path $labRoot 'Check-Interaction.ps1'

# --- worker script (runs every $CheckEveryMins minutes) --------------------
$workerBody = @"
`$ErrorActionPreference = 'Stop'
`$IdleMinutes = $IdleMinutes
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
`$log = 'C:\LabSetup\Logs\idle-interaction.log'

function Get-MinActiveIdleMinutes {
    # `$null  = no active sessions (treat as unattended)
    # <int>  = smallest idle-minutes across Active sessions
    `$lines = @(quser 2>`$null)
    if (`$lines.Count -le 1) { return `$null }
    `$minIdle = [int]::MaxValue
    `$sawActive = `$false
    foreach (`$l in `$lines[1..(`$lines.Count-1)]) {
        if (`$l -match '\s(Active|Disc)\s+(\S+)\s+\d{1,2}/\d{1,2}/\d{2,4}') {
            `$state = `$matches[1]; `$tok = `$matches[2]
            if (`$state -eq 'Disc') { continue }
            `$sawActive = `$true
            `$idle = 0
            if (`$tok -eq '.' -or `$tok -eq 'none') { `$idle = 0 }
            elseif (`$tok -match '^\d+`$') { `$idle = [int]`$tok }
            elseif (`$tok -match '^(\d+):(\d+)`$') { `$idle = [int]`$matches[1]*60 + [int]`$matches[2] }
            elseif (`$tok -match '^(\d+)\+(\d+):(\d+)`$') { `$idle = [int]`$matches[1]*1440 + [int]`$matches[2]*60 + [int]`$matches[3] }
            if (`$idle -lt `$minIdle) { `$minIdle = `$idle }
        }
    }
    if (-not `$sawActive) { return `$null }
    return `$minIdle
}

try {
    `$idle = Get-MinActiveIdleMinutes
    `$unattended = (`$idle -eq `$null) -or (`$idle -ge `$IdleMinutes)
    "`$(Get-Date -Format o)  activeIdleMin=`$idle threshold=`$IdleMinutes unattended=`$unattended" | Add-Content `$log

    if (`$unattended) {
        `$meta  = Invoke-RestMethod -Headers @{ Metadata='true' } -Uri 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' -TimeoutSec 30
        `$tok   = (Invoke-RestMethod -Headers @{ Metadata='true' } -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -TimeoutSec 30).access_token
        `$api   = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Compute/virtualMachines/{2}/deallocate?api-version=2023-09-01' -f `$meta.compute.subscriptionId, `$meta.compute.resourceGroupName, `$meta.compute.name
        Invoke-RestMethod -Method Post -Uri `$api -Headers @{ Authorization = "Bearer `$tok" } -TimeoutSec 120 | Out-Null
        "`$(Get-Date -Format o)  DEALLOCATE requested for `$(`$meta.compute.name)" | Add-Content `$log
    }
} catch {
    "`$(Get-Date -Format o)  ERROR: `$(`$_.Exception.Message)" | Add-Content `$log
}
"@
Set-Content -Path $worker -Value $workerBody -Encoding UTF8

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$worker`""

# First run in 1 min, then repeat every $CheckEveryMins minutes, indefinitely.
$trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) `
    -RepetitionInterval (New-TimeSpan -Minutes $CheckEveryMins)

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Output "Registered '$TaskName': deallocate when no interaction for $IdleMinutes min (checks every $CheckEveryMins min)."
