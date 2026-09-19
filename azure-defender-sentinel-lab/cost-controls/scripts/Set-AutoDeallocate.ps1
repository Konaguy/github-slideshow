<#
.SYNOPSIS
    Registers a scheduled task that DEALLOCATES this VM a fixed number of minutes
    after it starts (default 30), using the VM's managed identity.

.DESCRIPTION
    Deallocation (not an in-guest shutdown) is what stops compute billing. This
    task fires:
      * once, 30 minutes from when this script runs (covers the current session), and
      * at every startup + 30 minutes (covers all future boots).

    The worker script pulls the VM's own resource ID from Azure Instance Metadata,
    gets a management token from the VM's system-assigned managed identity, and
    calls the deallocate REST API on itself. The identity must hold a role with
    Microsoft.Compute/virtualMachines/deallocate/action (Virtual Machine
    Contributor) on this VM - apply-cost-controls.sh grants that.

    NOTE: this is a flat timer, not CPU-idle detection - it deallocates whether
    the VM is busy or idle. Raise -DelayMinutes to allow longer sessions.
#>
[CmdletBinding()]
param(
    [int] $DelayMinutes = 30,
    [string] $TaskName = 'LabAutoDeallocate'
)

$ErrorActionPreference = 'Stop'
$labRoot = 'C:\LabSetup'
New-Item -Path $labRoot -ItemType Directory -Force | Out-Null
New-Item -Path 'C:\LabSetup\Logs' -ItemType Directory -Force | Out-Null
$worker = Join-Path $labRoot 'Deallocate-Self.ps1'

$workerBody = @'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $imds = 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
    $meta = Invoke-RestMethod -Headers @{ Metadata = 'true' } -Uri $imds -TimeoutSec 30
    $sub  = $meta.compute.subscriptionId
    $rg   = $meta.compute.resourceGroupName
    $vm   = $meta.compute.name

    $tokUri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
    $token  = (Invoke-RestMethod -Headers @{ Metadata = 'true' } -Uri $tokUri -TimeoutSec 30).access_token

    $api = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Compute/virtualMachines/{2}/deallocate?api-version=2023-09-01' -f $sub, $rg, $vm
    Invoke-RestMethod -Method Post -Uri $api -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 120
    "$(Get-Date -Format o)  Deallocate requested for $vm" | Add-Content 'C:\LabSetup\Logs\auto-deallocate.log'
} catch {
    "$(Get-Date -Format o)  ERROR: $($_.Exception.Message)" | Add-Content 'C:\LabSetup\Logs\auto-deallocate.log'
    throw
}
'@
Set-Content -Path $worker -Value $workerBody -Encoding UTF8

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$worker`""

# Trigger 1: one-time, DelayMinutes from now (covers the running session).
$tOnce = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($DelayMinutes)
# Trigger 2: at every startup, delayed by DelayMinutes (covers future boots).
$tBoot = New-ScheduledTaskTrigger -AtStartup
$tBoot.Delay = "PT${DelayMinutes}M"

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($tOnce, $tBoot) `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Output "Registered '$TaskName': deallocate $DelayMinutes min after start (and once at $((Get-Date).AddMinutes($DelayMinutes).ToString('u')))."
