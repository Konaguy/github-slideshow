#Requires -Version 5.1
<#
.SYNOPSIS
    Queries Windows Update for missing security and cumulative updates on Windows 11 PCs.

.DESCRIPTION
    Uses the Windows Update Agent COM API to find all missing security updates
    and cumulative updates. Can run against the local machine or remote computers.
    Outputs results to the console and optionally to a CSV file.

.PARAMETER ComputerName
    One or more computer names to query. Defaults to the local machine.

.PARAMETER OutputPath
    Optional path to export results as a CSV file.

.PARAMETER IncludeDrivers
    Include driver updates in results (excluded by default).

.EXAMPLE
    # Run against local machine
    .\Get-MissingWindowsUpdates.ps1

.EXAMPLE
    # Run against multiple remote PCs and export to CSV
    .\Get-MissingWindowsUpdates.ps1 -ComputerName PC01,PC02,PC03 -OutputPath C:\Reports\MissingUpdates.csv

.EXAMPLE
    # Read computer names from a text file
    Get-Content .\computers.txt | .\Get-MissingWindowsUpdates.ps1
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeDrivers
)

begin {
    $allResults = [System.Collections.Generic.List[PSObject]]::new()

    # Update type GUIDs used by Windows Update Agent API
    $updateTypeGuids = @{
        Security   = '0FA1201D-4330-4FA8-8AE9-B877473B6441'
        Cumulative = '28BC880E-0592-4CBF-8F95-C79B17911D5F'  # Cumulative Update category
    }

    function Get-UpdatesFromSession {
        param(
            [string]$Computer,
            [bool]$IsLocal
        )

        $results = [System.Collections.Generic.List[PSObject]]::new()

        try {
            if ($IsLocal) {
                $session = New-Object -ComObject Microsoft.Update.Session
                $session.ClientApplicationID = 'MissingUpdatesAudit'
            } else {
                $session = [activator]::CreateInstance(
                    [type]::GetTypeFromProgID('Microsoft.Update.Session', $Computer)
                )
                $session.ClientApplicationID = 'MissingUpdatesAudit'
            }

            $searcher = $session.CreateUpdateSearcher()

            # IsInstalled=0 — not installed
            # IsHidden=0    — not hidden/declined
            # Type='Software' — software updates only (change to 'Driver' for drivers)
            $searchFilter = "IsInstalled=0 and IsHidden=0 and Type='Software'"

            Write-Verbose "[$Computer] Querying Windows Update (this may take a moment)..."
            $searchResult = $searcher.Search($searchFilter)

            foreach ($update in $searchResult.Updates) {
                $categories   = $update.Categories | ForEach-Object { $_.Name }
                $categoryStr  = $categories -join '; '
                $isSecurity   = $categories -match 'Security'  -or
                                $update.MsrcSeverity -in @('Critical','Important','Moderate','Low')
                $isCumulative = $update.Title -match 'Cumulative' -or
                                $categories -match 'Cumulative'

                # Skip if neither security nor cumulative (and not requesting all)
                if (-not $isSecurity -and -not $isCumulative) { continue }

                $kbIds = ($update.KBArticleIDs | ForEach-Object { "KB$_" }) -join ', '

                $row = [PSCustomObject]@{
                    ComputerName   = $Computer
                    Title          = $update.Title
                    KBArticleIDs   = if ($kbIds) { $kbIds } else { 'N/A' }
                    Severity       = if ($update.MsrcSeverity) { $update.MsrcSeverity } else { 'Unspecified' }
                    IsSecurity     = $isSecurity
                    IsCumulative   = $isCumulative
                    Categories     = $categoryStr
                    SizeMB         = if ($update.MaxDownloadSize -gt 0) {
                                         [math]::Round($update.MaxDownloadSize / 1MB, 1)
                                     } else { 'Unknown' }
                    RebootRequired = $update.RebootRequired
                    PublishedDate  = if ($update.LastDeploymentChangeTime) {
                                         $update.LastDeploymentChangeTime.ToString('yyyy-MM-dd')
                                     } else { 'Unknown' }
                    UpdateID       = $update.Identity.UpdateID
                }

                $results.Add($row)
            }

            # Also include driver updates if requested
            if ($IncludeDrivers) {
                $driverFilter   = "IsInstalled=0 and IsHidden=0 and Type='Driver'"
                $driverResult   = $searcher.Search($driverFilter)
                foreach ($update in $driverResult.Updates) {
                    $row = [PSCustomObject]@{
                        ComputerName   = $Computer
                        Title          = $update.Title
                        KBArticleIDs   = 'N/A (Driver)'
                        Severity       = 'Driver'
                        IsSecurity     = $false
                        IsCumulative   = $false
                        Categories     = 'Driver'
                        SizeMB         = if ($update.MaxDownloadSize -gt 0) {
                                             [math]::Round($update.MaxDownloadSize / 1MB, 1)
                                         } else { 'Unknown' }
                        RebootRequired = $update.RebootRequired
                        PublishedDate  = if ($update.LastDeploymentChangeTime) {
                                             $update.LastDeploymentChangeTime.ToString('yyyy-MM-dd')
                                         } else { 'Unknown' }
                        UpdateID       = $update.Identity.UpdateID
                    }
                    $results.Add($row)
                }
            }

        } catch [System.Runtime.InteropServices.COMException] {
            Write-Warning "[$Computer] COM error — Windows Update service may be unavailable: $_"
        } catch [System.UnauthorizedAccessException] {
            Write-Warning "[$Computer] Access denied — run as administrator or check remote permissions."
        } catch {
            Write-Warning "[$Computer] Unexpected error: $_"
        }

        return $results
    }
}

process {
    foreach ($computer in $ComputerName) {
        $computer  = $computer.Trim().ToUpper()
        $isLocal   = ($computer -eq $env:COMPUTERNAME.ToUpper()) -or
                     ($computer -in @('LOCALHOST', '127.0.0.1', '.'))

        Write-Host "`n=== Checking: $computer ===" -ForegroundColor Cyan

        # Verify remote connectivity before querying
        if (-not $isLocal) {
            $pingOk = Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue
            if (-not $pingOk) {
                Write-Warning "[$computer] Host unreachable — skipping."
                continue
            }
        }

        $updates = Get-UpdatesFromSession -Computer $computer -IsLocal $isLocal

        if ($updates.Count -eq 0) {
            Write-Host "[$computer] No missing security or cumulative updates found." -ForegroundColor Green
        } else {
            $secCount  = ($updates | Where-Object IsSecurity).Count
            $cumCount  = ($updates | Where-Object IsCumulative).Count
            $critCount = ($updates | Where-Object { $_.Severity -eq 'Critical' }).Count

            Write-Host "[$computer] Found $($updates.Count) missing update(s): " -NoNewline
            Write-Host "$critCount Critical, " -ForegroundColor Red -NoNewline
            Write-Host "$secCount Security, " -ForegroundColor Yellow -NoNewline
            Write-Host "$cumCount Cumulative" -ForegroundColor Magenta

            # Print a summary table to the console
            $updates |
                Sort-Object Severity, Title |
                Format-Table -AutoSize -Property @(
                    'ComputerName',
                    'KBArticleIDs',
                    @{ Label = 'Severity';  Expression = {
                        $c = switch ($_.Severity) {
                            'Critical'  { 'Red'     }
                            'Important' { 'Yellow'  }
                            default     { 'White'   }
                        }
                        # Format-Table doesn't support per-cell color; use plain text
                        $_.Severity
                    }},
                    @{ Label = 'Cumulative'; Expression = { if ($_.IsCumulative) { 'Yes' } else { 'No' } }},
                    'PublishedDate',
                    'SizeMB',
                    'Title'
                )
        }

        foreach ($u in $updates) { $allResults.Add($u) }
    }
}

end {
    if ($allResults.Count -eq 0) {
        Write-Host "`nAll queried machines are fully patched (security + cumulative)." -ForegroundColor Green
        return
    }

    Write-Host "`n--- Summary ---" -ForegroundColor Cyan
    Write-Host "Total missing updates across all machines: $($allResults.Count)"

    $allResults |
        Group-Object ComputerName |
        ForEach-Object {
            $crit = ($_.Group | Where-Object { $_.Severity -eq 'Critical' }).Count
            Write-Host ("  {0,-20} {1,3} update(s), {2} Critical" -f $_.Name, $_.Count, $crit)
        }

    if ($OutputPath) {
        try {
            $allResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nResults exported to: $OutputPath" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to export CSV: $_"
        }
    }
}
