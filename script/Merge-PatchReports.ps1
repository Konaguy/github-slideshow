#Requires -Version 5.1
<#
.SYNOPSIS
    Merges per-machine patch CSVs from a central share into one consolidated report.

.DESCRIPTION
    After Get-MissingWindowsUpdates.ps1 has been deployed via PDQ Deploy to all
    target machines, each machine drops a CSV in the ReportShare folder. Run this
    script on any machine that can reach the share to merge them into a single
    report with summary statistics.

    Run this on your admin workstation or PDQ server after the PDQ Deploy job
    completes. You can also schedule it as a PDQ Deploy "post-step" that runs on
    the PDQ server itself.

.PARAMETER ReportShare
    UNC (or local) path to the folder containing the per-machine CSVs.

.PARAMETER OutputPath
    Where to write the merged CSV. Defaults to <ReportShare>\MergedReport_<date>.csv.

.PARAMETER Date
    Only include CSVs from this date (format YYYYMMDD). Defaults to today.
    Pass '*' to merge all dates in the folder.

.PARAMETER GridView
    Show results in an interactive Out-GridView window (requires Windows desktop).

.EXAMPLE
    # Merge today's reports and open in Grid View
    .\Merge-PatchReports.ps1 -ReportShare '\\fileserver\PatchReports' -GridView

.EXAMPLE
    # Merge all reports, save to a specific file
    .\Merge-PatchReports.ps1 -ReportShare '\\fileserver\PatchReports' -Date '*' -OutputPath C:\Audits\AllPatches.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReportShare,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$Date = (Get-Date -Format 'yyyyMMdd'),

    [Parameter()]
    [switch]$GridView
)

if (-not (Test-Path $ReportShare)) {
    Write-Error "Cannot reach share: $ReportShare"
    exit 1
}

$pattern = if ($Date -eq '*') { '*_*.csv' } else { "*_${Date}.csv" }
$csvFiles = Get-ChildItem -Path $ReportShare -Filter $pattern -File |
            Where-Object { $_.Name -notmatch '^MergedReport_' }

if ($csvFiles.Count -eq 0) {
    Write-Warning "No per-machine CSVs found in '$ReportShare' matching pattern '$pattern'."
    exit 0
}

Write-Host "Merging $($csvFiles.Count) report file(s)..." -ForegroundColor Cyan

$allRows = foreach ($file in $csvFiles) {
    try {
        Import-Csv -Path $file.FullName
    } catch {
        Write-Warning "Skipping unreadable file '$($file.Name)': $_"
    }
}

if (-not $allRows) {
    Write-Warning "No data found in any report file."
    exit 0
}

# --- Console summary ---
$machines       = $allRows | Select-Object -ExpandProperty ComputerName -Unique | Sort-Object
$patchedMachines = $allRows | Where-Object { $_.Title -eq 'FULLY PATCHED' } |
                               Select-Object -ExpandProperty ComputerName -Unique
$missingRows    = $allRows | Where-Object { $_.Title -ne 'FULLY PATCHED' }

Write-Host "`n===== Patch Compliance Report — $Date =====" -ForegroundColor Cyan
Write-Host ("Machines scanned   : {0}"   -f $machines.Count)
Write-Host ("Fully patched      : {0}"   -f $patchedMachines.Count) -ForegroundColor Green
Write-Host ("Machines with gaps : {0}"   -f ($machines.Count - $patchedMachines.Count)) -ForegroundColor Yellow
Write-Host ("Total missing upd. : {0}"   -f $missingRows.Count)

$critCount = ($missingRows | Where-Object { $_.Severity -eq 'Critical' }).Count
if ($critCount -gt 0) {
    Write-Host ("CRITICAL missing   : {0}" -f $critCount) -ForegroundColor Red
}

Write-Host "`n--- Per-machine breakdown ---" -ForegroundColor Cyan
$machines | ForEach-Object {
    $pc   = $_
    $rows = $missingRows | Where-Object { $_.ComputerName -eq $pc }
    if ($rows.Count -eq 0) {
        Write-Host ("  {0,-25} OK" -f $pc) -ForegroundColor Green
    } else {
        $crit = ($rows | Where-Object { $_.Severity -eq 'Critical' }).Count
        $cum  = ($rows | Where-Object { $_.IsCumulative -eq 'True' }).Count
        Write-Host ("  {0,-25} {1,3} missing  ({2} Critical, {3} Cumulative)" -f $pc, $rows.Count, $crit, $cum) -ForegroundColor Yellow
    }
}

# --- Top missing KBs across the fleet ---
Write-Host "`n--- Most common missing updates (top 10) ---" -ForegroundColor Cyan
$missingRows |
    Where-Object { $_.KBArticleIDs -ne 'N/A' } |
    Group-Object KBArticleIDs, Title |
    Sort-Object Count -Descending |
    Select-Object -First 10 |
    ForEach-Object {
        $kb, $title = $_.Name -split ', ', 2
        Write-Host ("  [{0,3} machines] {1}  {2}" -f $_.Count, $kb, $title)
    }

# --- Export merged CSV ---
$resolvedOutput = if ($OutputPath) {
    $OutputPath
} else {
    Join-Path $ReportShare "MergedReport_${Date}.csv"
}

try {
    $allRows | Export-Csv -Path $resolvedOutput -NoTypeInformation -Encoding UTF8
    Write-Host "`nMerged report saved to: $resolvedOutput" -ForegroundColor Green
} catch {
    Write-Warning "Could not save merged report: $_"
}

if ($GridView) {
    $missingRows | Sort-Object ComputerName, Severity, Title | Out-GridView -Title "Missing Updates — $Date"
}
