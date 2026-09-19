<#
.SYNOPSIS
    Scheduled Automation runbook. If month-to-date actual cost is at or above the
    threshold, deallocate every lab VM.

.DESCRIPTION
    Runs on a schedule (hourly by default). Authenticates with the Automation
    account's system-assigned managed identity and uses REST only - no Az module
    import required. The identity needs:
      * Cost Management Reader on the subscription (query spend)
      * Virtual Machine Contributor on the resource group (deallocate)

    Budgets only email; this is what actually stops spend at the cap.
#>
param(
    [double]   $ThresholdUsd  = 25,
    [string]   $ResourceGroup = 'rg-mdlab',
    [string[]] $VmNames       = @('DC01', 'SRV01', 'WIN11-01', 'WIN11-02', 'WIN11-03')
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

# Month-to-date actual cost for the subscription.
$costUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.CostManagement/query?api-version=2023-11-01"
$body = @{
    type      = 'ActualCost'
    timeframe = 'MonthToDate'
    dataset   = @{
        granularity = 'None'
        aggregation = @{ totalCost = @{ name = 'Cost'; function = 'Sum' } }
    }
} | ConvertTo-Json -Depth 6

$resp = Invoke-RestMethod -Method Post -Uri $costUri -Headers $auth -Body $body -ContentType 'application/json'
$cost = 0.0
if ($resp.properties.rows.Count -gt 0) { $cost = [double]($resp.properties.rows[0][0]) }

Write-Output ("Month-to-date cost: {0:C2}  (threshold {1:C2})" -f $cost, $ThresholdUsd)

if ($cost -ge $ThresholdUsd) {
    Write-Output "Threshold reached - deallocating all lab VMs."
    foreach ($vm in $VmNames) {
        $u = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$vm/deallocate?api-version=2023-09-01"
        try {
            Invoke-RestMethod -Method Post -Uri $u -Headers $auth -TimeoutSec 120 | Out-Null
            Write-Output "  deallocate requested: $vm"
        } catch {
            Write-Warning "  $vm : $($_.Exception.Message)"
        }
    }
} else {
    Write-Output "Under threshold - no action."
}
