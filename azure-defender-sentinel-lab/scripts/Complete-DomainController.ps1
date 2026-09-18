<#
.SYNOPSIS
    Post-promotion configuration: DNS forwarders and the lab directory contents.

.DESCRIPTION
    Registered by Initialize-DomainController.ps1 to run at startup as SYSTEM.
    Waits for the directory to come up, builds the OU/user/group structure, then
    removes its own scheduled task so it never runs twice.

    The accounts it creates are deliberately imperfect - a service account with
    an SPN and a guessable password, one account with Kerberos pre-authentication
    disabled - because that is what makes Kerberoasting and AS-REP roasting
    detections fire in the Sentinel rules shipped with this lab.

    This is safe only because the lab domain is isolated and non-routable. Never
    run this against a directory that matters.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $DomainName,
    [Parameter(Mandatory)] [string] $NetbiosName,
    [string] $DnsForwarders = '168.63.129.16',
    [string] $LabUserPassword = 'LabUserP@ssw0rd!2024',
    [string] $ServiceAccountPassword = 'Summer2024!'
)

$ErrorActionPreference = 'Stop'
$LogDir = 'C:\LabSetup\Logs'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
Start-Transcript -Path (Join-Path $LogDir 'Complete-DomainController.log') -Append

function Wait-ForDirectory {
    param([int] $TimeoutMinutes = 30)
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $null = Get-ADDomain -ErrorAction Stop
            Write-Host 'Directory is responding.'
            return $true
        } catch {
            Write-Host "Waiting for AD DS... ($($_.Exception.Message))"
            Start-Sleep -Seconds 20
        }
    }
    return $false
}

try {
    if (-not (Wait-ForDirectory)) { throw 'AD DS did not become available in time.' }

    $domain    = Get-ADDomain
    $domainDn  = $domain.DistinguishedName
    Write-Host "Configuring $domainDn"

    Write-Host '--- DNS forwarders ---'
    $forwarders = $DnsForwarders -split ',' | Where-Object { $_ }
    try {
        Set-DnsServerForwarder -IPAddress $forwarders -PassThru | Out-Null
    } catch {
        Write-Warning "Could not set DNS forwarders: $($_.Exception.Message)"
    }

    Write-Host '--- OU structure ---'
    $labOu = "OU=Lab,$domainDn"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$labOu'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name 'Lab' -Path $domainDn -ProtectedFromAccidentalDeletion $false
    }
    foreach ($child in @('Servers', 'Workstations', 'Users', 'ServiceAccounts')) {
        $dn = "OU=$child,$labOu"
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $child -Path $labOu -ProtectedFromAccidentalDeletion $false
        }
    }

    Write-Host '--- Groups ---'
    $groups = @{
        'Lab-Helpdesk'    = 'Tier 1 support, local admin on workstations'
        'Lab-Finance'     = 'Finance department users'
        'Lab-Engineering' = 'Engineering department users'
        'Lab-ServerAdmins' = 'Administrators of SRV01'
    }
    foreach ($g in $groups.GetEnumerator()) {
        if (-not (Get-ADGroup -Filter "Name -eq '$($g.Key)'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $g.Key -GroupScope Global -GroupCategory Security -Path "OU=Users,$labOu" -Description $g.Value
        }
    }

    Write-Host '--- Users ---'
    $securePwd = ConvertTo-SecureString -String $LabUserPassword -AsPlainText -Force
    $users = @(
        @{ Sam = 'jdoe';    Given = 'Jane';   Sur = 'Doe';     Title = 'Financial Analyst'; Group = 'Lab-Finance' }
        @{ Sam = 'msmith';  Given = 'Mark';   Sur = 'Smith';   Title = 'Software Engineer'; Group = 'Lab-Engineering' }
        @{ Sam = 'aroberts';Given = 'Alex';   Sur = 'Roberts'; Title = 'Service Desk';      Group = 'Lab-Helpdesk' }
        @{ Sam = 'pnguyen'; Given = 'Priya';  Sur = 'Nguyen';  Title = 'Server Admin';      Group = 'Lab-ServerAdmins' }
    )
    foreach ($u in $users) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
            New-ADUser -Name "$($u.Given) $($u.Sur)" `
                -GivenName $u.Given -Surname $u.Sur `
                -SamAccountName $u.Sam `
                -UserPrincipalName "$($u.Sam)@$DomainName" `
                -Title $u.Title `
                -Path "OU=Users,$labOu" `
                -AccountPassword $securePwd `
                -Enabled $true -PasswordNeverExpires $true
        }
        Add-ADGroupMember -Identity $u.Group -Members $u.Sam -ErrorAction SilentlyContinue
    }

    Write-Host '--- Detection targets (intentionally weak - lab only) ---'
    # Kerberoastable: a user account carrying an SPN with a weak password.
    $svcPwd = ConvertTo-SecureString -String $ServiceAccountPassword -AsPlainText -Force
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_sql'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name 'svc_sql' -SamAccountName 'svc_sql' `
            -UserPrincipalName "svc_sql@$DomainName" `
            -Description 'Lab SQL service account - deliberately Kerberoastable' `
            -Path "OU=ServiceAccounts,$labOu" `
            -AccountPassword $svcPwd -Enabled $true -PasswordNeverExpires $true
        Set-ADUser -Identity 'svc_sql' -ServicePrincipalNames @{ Add = "MSSQLSvc/srv01.$($DomainName):1433" }
    }

    # AS-REP roastable: Kerberos pre-authentication turned off.
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_backup'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name 'svc_backup' -SamAccountName 'svc_backup' `
            -UserPrincipalName "svc_backup@$DomainName" `
            -Description 'Lab backup account - pre-auth disabled for AS-REP roasting tests' `
            -Path "OU=ServiceAccounts,$labOu" `
            -AccountPassword $svcPwd -Enabled $true -PasswordNeverExpires $true
        Set-ADAccountControl -Identity 'svc_backup' -DoesNotRequirePreAuth $true
    }

    Write-Host '--- Directory-level auditing ---'
    # Makes 4662/5136 useful for DCSync and object-change detections.
    & auditpol.exe /set /subcategory:"Directory Service Access"  /success:enable /failure:enable
    & auditpol.exe /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
    & auditpol.exe /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
    & auditpol.exe /set /subcategory:"Kerberos Authentication Service"    /success:enable /failure:enable

    Write-Host '--- Done. Removing completion task. ---'
    Unregister-ScheduledTask -TaskName 'LabCompleteDomainController' -Confirm:$false -ErrorAction SilentlyContinue
    New-Item -Path 'C:\LabSetup\dc-complete.marker' -ItemType File -Force | Out-Null
}
catch {
    Write-Error "DC completion failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}
finally {
    Stop-Transcript
}
