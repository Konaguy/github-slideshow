<#
.SYNOPSIS
    Scheduled Automation runbook. Deallocates lab VMs whose average CPU over the
    last N minutes is below a threshold - true idle-based shutdown that leaves
    busy VMs running.

.DESCRIPTION
    Runs on a schedule (every 30 min by default, via two offset hourly schedules).
    Uses the Automation account's system-assigned managed identity via REST only.
    The identity needs:
      * Monitoring Reader on the resource group (read CPU metrics)
      * Virtual Machine Contributor on the resource group (deallocate)

    Only running VMs with actual metric data below the threshold are stopped;
    a VM with no data in the window is left alone (can't confirm it's idle).

    Use this INSTEAD of the flat 30-minute auto-deallocate if you want active
    sessions to keep the VM alive. Running both means the flat timer wins.
#>
param(
    [double]   $CpuThresholdPercent = 5,
    [int]      $WindowMinutes       = 30,
    [string]   $ResourceGroup       = 'rg-mdlab',
    [string[]] $VmNames             = @('DC01', 'SRV01', 'WIN11-01', 'WIN11-02', 'WIN11-03')
)

$ErrorActionPreference = 'Stop'

function Get-MiToken {
    $resource = 'https://management.azure.com/'
    $headers  = @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; 'Metadata' = 'true' }
    $uri      = "$($env:IDENTITY_ENDPOINT)?resource=$resource&api-version=2019-08-01"
    return (Invoke-RestMethod -Uri $uri -Headers $headers).access_token
}

$subId = Get-AutomationVariable -Name 'SubscriptionId'
$auth  = @{ Authorization = "Bearer $(Get-MiToken)" }
$base  = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines"

$end   = (Get-Date).ToUniversalTime()
$start = $end.AddMinutes(-$WindowMinutes)
$span  = ('{0}/{1}' -f $start.ToString('o'), $end.ToString('o'))

foreach ($vm in $VmNames) {
    try {
        # Skip VMs that are not running.
        $iv    = Invoke-RestMethod -Uri "$base/$vm/instanceView?api-version=2023-09-01" -Headers $auth -TimeoutSec 60
        $power = ($iv.statuses | Where-Object { $_.code -like 'PowerState/*' } | Select-Object -First 1).code
        if ($power -ne 'PowerState/running') {
            Write-Output "$vm : $power - skip"
            continue
        }

        $mUri = "$base/$vm/providers/microsoft.insights/metrics?api-version=2018-01-01&metricnames=Percentage%20CPU&aggregation=Average&interval=PT${WindowMinutes}M&timespan=$span"
        $m    = Invoke-RestMethod -Uri $mUri -Headers $auth -TimeoutSec 60
        $pts  = @($m.value[0].timeseries[0].data | Where-Object { $_.average -ne $null })

        if ($pts.Count -eq 0) {
            Write-Output "$vm : no CPU data in window - skip"
            continue
        }

        $avg = ($pts | Measure-Object -Property average -Average).Average
        Write-Output ("{0} : avg CPU {1:N1}% over {2}m" -f $vm, $avg, $WindowMinutes)

        if ($avg -lt $CpuThresholdPercent) {
            Invoke-RestMethod -Method Post -Uri "$base/$vm/deallocate?api-version=2023-09-01" -Headers $auth -TimeoutSec 120 | Out-Null
            Write-Output "  idle - deallocate requested: $vm"
        }
    } catch {
        Write-Warning "$vm : $($_.Exception.Message)"
    }
}
