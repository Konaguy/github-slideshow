#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Server Certificate Authority Health and Security Analysis

.DESCRIPTION
    Analyzes PKI infrastructure health and security posture including:
      - CA certificate expiration and key/algorithm strength
      - CRL and OCSP validity
      - CDP and AIA endpoint reachability
      - Offline vs online CA hierarchy validation
      - Certificate template misconfigurations (ESC1-ESC9)
      - CA-level security flags and ACLs
      - Unauthorized trusted CA certificates
      - CA operational best practices (HSM, role separation, enrollment agents)
      - Issued certificate anomaly detection (privileged accounts, bulk
        issuance, off-hours, unusual SANs, excessive validity)

    Must be run from a domain-joined machine. Read access to AD is sufficient
    for most checks; CA-direct checks require the CA host to be reachable.
    Issued certificate audit requires CA database read rights (CA Admin or
    Auditor role on the target CA).

.PARAMETER OutputPath
    Path for the HTML report. Defaults to the current directory.

.PARAMETER CsvPath
    Optional path to export all findings as a CSV file.

.PARAMETER SkipTemplateAcls
    Skip the slow per-template ACL check (ESC4). Useful in large environments.

.PARAMETER AuditDays
    Days of certificate issuance history to examine (default: 90).

.PARAMETER SkipIssuedCertAudit
    Skip the CA database query for issued certificate anomalies. Use if you
    lack CA Auditor rights or the CA database is very large.

.EXAMPLE
    .\Analyze-CAHealth.ps1
    .\Analyze-CAHealth.ps1 -OutputPath C:\Reports\PKI.html -CsvPath C:\Reports\findings.csv
    .\Analyze-CAHealth.ps1 -AuditDays 30 -SkipIssuedCertAudit

.NOTES
    References:
      - "Certified Pre-Owned" (SpecterOps, 2021) - ESC1-ESC8 research
      - Microsoft PKI best practices: https://aka.ms/pki
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\CA_HealthReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [string]$CsvPath,
    [switch]$SkipTemplateAcls,
    [int]$AuditDays = 90,
    [switch]$SkipIssuedCertAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ---- Constants -------------------------------------------------------

# msPKI-Certificate-Name-Flag bits
$ENROLLEE_SUPPLIES_SUBJECT     = 0x00000001
$SUBJECT_ALT_NAME_2            = 0x00010000

# msPKI-Enrollment-Flag bits
$PEND_ALL_REQUESTS             = 0x00000002
$NO_SECURITY_EXTENSION         = 0x00080000

# msPKI-Private-Key-Flag bits
$REQUIRE_PRIVATE_KEY_ARCHIVAL  = 0x00000001
$EXPORTABLE_KEY                = 0x00000010

# Well-known EKU OIDs
$EKU_ANY_PURPOSE               = '2.5.29.37.0'
$EKU_CLIENT_AUTH               = '1.3.6.1.5.5.7.3.2'
$EKU_SERVER_AUTH               = '1.3.6.1.5.5.7.3.1'
$EKU_CERT_REQUEST_AGENT        = '1.3.6.1.4.1.311.20.2.1'
$EKU_SMART_CARD_LOGON          = '1.3.6.1.4.1.311.20.2.2'
$EKU_CODE_SIGNING              = '1.3.6.1.5.5.7.3.3'
$EKU_PKIX_TIMESTAMPING         = '1.3.6.1.5.5.7.3.8'

# X.509 extension OIDs
$OID_CDP                       = '2.5.29.31'
$OID_AIA                       = '1.3.6.1.5.5.7.1.1'

# CA flags
$IF_ATTRIBUTESUBJECTALTNAME2   = 0x00040000

# Known HSM CSP/KSP name fragments
$HSM_PROVIDER_PATTERNS = @(
    'nCipher', 'nShield', 'SafeNet', 'Luna', 'Utimaco', 'Thales',
    'Entrust', 'AWS CloudHSM', 'Azure Key Vault', 'YubiHSM'
)

# Low-privilege principals to check enrollment rights against
$LOW_PRIV_TRUSTEES = @(
    'S-1-1-0', 'S-1-5-11', 'S-1-5-7',
    'Domain Users', 'Domain Computers', 'Everyone', 'Authenticated Users'
)

# Severity levels
$SEV_CRITICAL = 'CRITICAL'
$SEV_HIGH     = 'HIGH'
$SEV_MEDIUM   = 'MEDIUM'
$SEV_LOW      = 'LOW'
$SEV_INFO     = 'INFO'

# Issued cert audit thresholds
$BULK_THRESHOLD_PER_HOUR = 100   # certs from same template in one hour = bulk issuance
$MAX_AUDIT_ROWS          = 5000  # cap to keep runtime reasonable

#endregion

#region ---- State -----------------------------------------------------------

$script:Findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Sections  = [System.Collections.Generic.List[string]]::new()
$script:StartTime = Get-Date

#endregion

#region ---- Helper functions ------------------------------------------------

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Target,
        [string]$Title,
        [string]$Detail
    )
    $script:Findings.Add([PSCustomObject]@{
        Severity = $Severity
        Category = $Category
        Target   = $Target
        Title    = $Title
        Detail   = $Detail
        Time     = (Get-Date -Format 'HH:mm:ss')
    })
    $color = switch ($Severity) {
        $SEV_CRITICAL { 'Red'     }
        $SEV_HIGH     { 'DarkRed' }
        $SEV_MEDIUM   { 'Yellow'  }
        $SEV_LOW      { 'Cyan'    }
        default       { 'Gray'    }
    }
    Write-Host "  [$Severity] $Title" -ForegroundColor $color
    if ($Detail) { Write-Host "           $Detail" -ForegroundColor DarkGray }
}

function Write-Section {
    param([string]$Title)
    $line = '=' * 70
    Write-Host "`n$line" -ForegroundColor Green
    Write-Host "  $Title" -ForegroundColor Green
    Write-Host $line -ForegroundColor Green
    $script:Sections.Add($Title)
}

function Get-ADConfigRoot {
    $root = [ADSI]'LDAP://RootDSE'
    return $root.configurationNamingContext
}

function Expand-FileTimeToDateTime {
    param([object]$Value)
    try {
        if ($Value -is [System.DirectoryServices.PropertyValueCollection]) { $Value = $Value.Value }
        $ticks = [Int64]$Value
        if ($ticks -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($ticks)
    } catch { return $null }
}

function Get-ADObject {
    param([string]$Path, [string[]]$Properties)
    try {
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Path")
        $props = if ($Properties) { $Properties } else { @('*') }
        $de.RefreshCache($props)
        return $de
    } catch {
        Write-Warning "Could not read AD object: $Path — $($_.Exception.Message)"
        return $null
    }
}

function Search-ADObjects {
    param(
        [string]$BaseDN,
        [string]$Filter,
        [string[]]$Properties,
        [string]$Scope = 'Subtree'
    )
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$BaseDN")
        $searcher.Filter      = $Filter
        $searcher.SearchScope = $Scope
        $searcher.PageSize    = 500
        if ($Properties) { $Properties | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) } }
        return $searcher.FindAll()
    } catch {
        Write-Warning "AD search failed under $BaseDN — $($_.Exception.Message)"
        return @()
    }
}

function Test-IsLowPrivTrustee {
    param([string]$TrusteeName)
    foreach ($lp in $LOW_PRIV_TRUSTEES) {
        if ($TrusteeName -like "*$lp*") { return $true }
    }
    return $false
}

function Get-CertExpiry {
    param([byte[]]$RawCert)
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($RawCert)
        return $cert
    } catch { return $null }
}

function Format-TimeSpan {
    param([TimeSpan]$ts)
    if ($ts.TotalDays -gt 365) { return "$([int]($ts.TotalDays/365))y $([int]($ts.TotalDays%365))d" }
    if ($ts.TotalDays -gt 1)   { return "$([int]$ts.TotalDays)d $($ts.Hours)h" }
    return "$($ts.Hours)h $($ts.Minutes)m"
}

function Invoke-CertUtil {
    param([string]$Arguments)
    try {
        $result = & certutil.exe $Arguments.Split(' ') 2>&1
        return $result -join "`n"
    } catch { return $null }
}

# Extract all HTTP/LDAP/FILE URLs from a certificate extension (CDP or AIA)
function Get-CertExtensionUrls {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$OID
    )
    $ext = $Cert.Extensions | Where-Object { $_.Oid.Value -eq $OID }
    if (-not $ext) { return @() }
    $formatted = $ext.Format($false)
    $urls = [regex]::Matches($formatted, '(https?://[^\s,\[\]<>]+|ldap://[^\s,\[\]<>]+|file://[^\s,\[\]<>]+)') |
            ForEach-Object { $_.Value.TrimEnd('.,)') }
    return $urls | Sort-Object -Unique
}

# Test whether a URL endpoint is reachable
function Test-UrlReachable {
    param([string]$Url, [int]$TimeoutMs = 8000)
    $result = [PSCustomObject]@{ Reachable = $false; Status = 'Unknown'; Url = $Url }
    try {
        if ($Url -match '^https?://') {
            $req         = [System.Net.WebRequest]::Create($Url)
            $req.Timeout = $TimeoutMs
            $req.Method  = 'GET'
            $resp        = $req.GetResponse()
            $result.Reachable = $true
            $result.Status    = "HTTP $([int]$resp.StatusCode)"
            $resp.Close()
        } elseif ($Url -match '^ldap://') {
            $de = New-Object System.DirectoryServices.DirectoryEntry($Url)
            $de.RefreshCache()
            $result.Reachable = $true
            $result.Status    = 'LDAP OK'
        } elseif ($Url -match '^file://') {
            $path = ($Url -replace '^file://', '') -replace '/', '\'
            $result.Reachable = (Test-Path $path)
            $result.Status    = if ($result.Reachable) { 'File exists' } else { 'File not found' }
        } else {
            $result.Status = 'Unsupported scheme'
        }
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            # A 401/403/404 still means the server is reachable
            $result.Reachable = $code -in @(200, 401, 403, 404)
            $result.Status    = "HTTP $code"
        } else {
            $result.Status = $_.Exception.Message.Substring(0, [Math]::Min(80, $_.Exception.Message.Length))
        }
    } catch {
        $result.Status = $_.Exception.Message.Substring(0, [Math]::Min(80, $_.Exception.Message.Length))
    }
    return $result
}

# Query the CA issued-certificate database via ICertView COM
function Get-IssuedCertsFromCA {
    param([string]$CAConfig, [int]$DaysBack, [int]$MaxRows = $MAX_AUDIT_ROWS)

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $view    = $null
    $rowEnum = $null

    try {
        $view = New-Object -ComObject CertificateAuthority.View
        $view.OpenConnection($CAConfig)

        $wantedCols = @('RequestID', 'Request.RequesterName', 'Request.CallerMachineName',
                        'NotBefore', 'NotAfter', 'CertificateTemplate', 'SubjectAltName', 'CommonName')
        foreach ($col in $wantedCols) {
            try { $view.SetResultColumn($view.GetColumnIndex(0, $col)) } catch { }
        }

        # Restrict: Disposition = 20 (issued)
        $dispIdx = $view.GetColumnIndex(0, 'Disposition')
        $view.SetRestriction($dispIdx, 1, 0, 20)

        # Restrict: NotBefore >= (today - AuditDays), sort ascending
        $dateIdx = $view.GetColumnIndex(0, 'NotBefore')
        $since   = (Get-Date).AddDays(-$DaysBack)
        $view.SetRestriction($dateIdx, 8, 1, $since)

        $rowEnum = $view.OpenView()
        $count   = 0

        while (($rowEnum.Next() -ne -1) -and ($count -lt $MaxRows)) {
            $row     = @{}
            $colEnum = $rowEnum.EnumCertViewColumn()
            while ($colEnum.Next() -ne -1) {
                $name = $colEnum.GetDisplayName()
                $val  = try { $colEnum.GetValue(0) } catch { $null }
                # COM DATE comes back as a double; convert to DateTime
                if ($val -is [double]) { $val = [DateTime]::FromOADate($val) }
                $row[$name] = $val
            }
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($colEnum)
            $results.Add([PSCustomObject]$row)
            $count++
        }
        Write-Host "    Fetched $count certificate records (cap: $MaxRows)" -ForegroundColor DarkGray
    } catch {
        Write-Warning "Cannot query CA database ($CAConfig): $($_.Exception.Message)"
    } finally {
        if ($rowEnum) { try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($rowEnum) } catch { } }
        if ($view)    { try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($view)    } catch { } }
    }
    return $results
}

# Return samAccountName list for direct members of an AD group by DN
function Get-GroupMemberNames {
    param([string]$GroupDN)
    $names = @()
    try {
        $grp = [ADSI]"LDAP://$GroupDN"
        foreach ($memberDN in $grp.member) {
            try {
                $memberDE = [ADSI]"LDAP://$memberDN"
                $sam = $memberDE.sAMAccountName
                if ($sam) { $names += $sam[0].ToString() }
            } catch { }
        }
    } catch { }
    return $names
}

#endregion

#region ---- 1. Environment discovery ----------------------------------------

Write-Section "1. Environment Discovery"

$configRoot = $null
$domainName = $null
try {
    $configRoot = Get-ADConfigRoot
    $domainName = ([ADSI]'LDAP://RootDSE').defaultNamingContext.ToString()
    Write-Host "  Domain DN      : $domainName"
    Write-Host "  Config root    : $configRoot"
    Add-Finding $SEV_INFO 'Discovery' 'Domain' 'Domain located' "DN: $domainName"
} catch {
    Add-Finding $SEV_CRITICAL 'Discovery' 'Domain' 'Cannot reach AD' $_.Exception.Message
    Write-Error "Cannot connect to Active Directory. Ensure you are on a domain-joined machine."
    exit 1
}

$pkiBase       = "CN=Public Key Services,CN=Services,$configRoot"
$enrollSvcBase = "CN=Enrollment Services,$pkiBase"
$templateBase  = "CN=Certificate Templates,$pkiBase"
$aiaBase       = "CN=AIA,$pkiBase"
$cdpBase       = "CN=CDP,$pkiBase"
$ntAuthBase    = "CN=NTAuthCertificates,$pkiBase"
$rootCABase    = "CN=Certification Authorities,$pkiBase"

#endregion

#region ---- 2. Enterprise CA Enumeration ------------------------------------

Write-Section "2. Enterprise CA Enumeration"

$enterpriseCAs = @()
$caResults = Search-ADObjects -BaseDN $enrollSvcBase `
    -Filter '(objectClass=pKIEnrollmentService)' `
    -Properties @('cn','cACertificate','dNSHostName','certificateTemplates',
                   'cACertificateDN','flags','msPKI-EnrollmentServers')

foreach ($r in $caResults) {
    $p       = $r.Properties
    $name    = if ($p['cn'].Count)          { $p['cn'][0] }          else { 'Unknown' }
    $host    = if ($p['dnsHostName'].Count) { $p['dnsHostName'][0] } else { 'Unknown' }
    $rawCert = if ($p['caCertificate'].Count) { [byte[]]$p['caCertificate'][0] } else { $null }
    $templates = if ($p['certificateTemplates'].Count) { @($p['certificateTemplates']) } else { @() }
    $cert    = if ($rawCert) { Get-CertExpiry $rawCert } else { $null }

    $caObj = [PSCustomObject]@{
        Name      = $name
        Host      = $host
        DN        = $r.Path -replace 'LDAP://',''
        Cert      = $cert
        Templates = $templates
        Reachable = $false
        Flags     = 0
    }
    $enterpriseCAs += $caObj
    Write-Host "  Found CA : $name  (host: $host)"

    if ($cert) {
        $expiry = $cert.NotAfter
        $left   = $expiry - (Get-Date)
        Write-Host "    Cert subject  : $($cert.Subject)"
        Write-Host "    Expires       : $expiry  ($( if($left.TotalDays -gt 0){"in $(Format-TimeSpan $left)"}else{'EXPIRED'} ))"
        Write-Host "    Key algorithm : $($cert.PublicKey.Oid.FriendlyName)  ($($cert.PublicKey.Key.KeySize)-bit)"
        Write-Host "    Sig algorithm : $($cert.SignatureAlgorithm.FriendlyName)"

        if ($cert.PublicKey.Key.KeySize -lt 2048) {
            Add-Finding $SEV_CRITICAL 'CA-Certificate' $name `
                'Weak key size' "Key size $($cert.PublicKey.Key.KeySize)-bit is below the 2048-bit minimum."
        } elseif ($cert.PublicKey.Key.KeySize -lt 4096) {
            Add-Finding $SEV_LOW 'CA-Certificate' $name `
                'Key size < 4096' 'Consider upgrading to 4096-bit for long-lived CA certificates.'
        }

        if ($cert.SignatureAlgorithm.FriendlyName -match 'sha1|md5|md2') {
            Add-Finding $SEV_HIGH 'CA-Certificate' $name `
                'Weak signature algorithm' "Algorithm: $($cert.SignatureAlgorithm.FriendlyName). SHA-1/MD5 are deprecated."
        }

        if ($left.TotalDays -le 0) {
            Add-Finding $SEV_CRITICAL 'CA-Certificate' $name 'CA certificate EXPIRED' "Expired: $expiry"
        } elseif ($left.TotalDays -le 30) {
            Add-Finding $SEV_CRITICAL 'CA-Certificate' $name `
                'CA certificate expires in <30 days' "Expires: $expiry ($(Format-TimeSpan $left) remaining)"
        } elseif ($left.TotalDays -le 180) {
            Add-Finding $SEV_HIGH 'CA-Certificate' $name `
                'CA certificate expires in <180 days' "Expires: $expiry ($(Format-TimeSpan $left) remaining)"
        } else {
            Add-Finding $SEV_INFO 'CA-Certificate' $name `
                'CA certificate valid' "Expires: $expiry ($(Format-TimeSpan $left) remaining)"
        }
    } else {
        Add-Finding $SEV_HIGH 'CA-Certificate' $name 'Could not read CA certificate from AD' ''
    }
}

if ($enterpriseCAs.Count -eq 0) {
    Add-Finding $SEV_HIGH 'Discovery' 'PKI' 'No Enterprise CAs found in AD' `
        "Check CN=Enrollment Services. The CA service may be offline or not domain-joined."
    Write-Host "  No Enterprise CAs found." -ForegroundColor Yellow
}

#endregion

#region ---- 3. PKI Hierarchy / Offline Root CA check ------------------------

Write-Section "3. PKI Hierarchy & Offline Root CA"

$rootCAResults = Search-ADObjects -BaseDN $rootCABase `
    -Filter '(objectClass=certificationAuthority)' `
    -Properties @('cn','cACertificate')

$rootCAs = @()
foreach ($r in $rootCAResults) {
    $p    = $r.Properties
    $name = if ($p['cn'].Count) { $p['cn'][0] } else { 'Unknown' }
    $raw  = if ($p['caCertificate'].Count) { [byte[]]$p['caCertificate'][0] } else { $null }
    $cert = if ($raw) { Get-CertExpiry $raw } else { $null }
    $rootCAs += [PSCustomObject]@{ Name = $name; Cert = $cert }
    Write-Host "  Root CA: $name"
}

foreach ($rca in $rootCAs) {
    $isOnlineIssuing = $enterpriseCAs | Where-Object { $_.Name -eq $rca.Name }
    if ($isOnlineIssuing) {
        Add-Finding $SEV_HIGH 'Hierarchy' $rca.Name `
            'Root CA appears to be online and issuing certificates' `
            'Best practice: Root CA should be offline. Issue only via subordinate CAs.'
    } else {
        Add-Finding $SEV_INFO 'Hierarchy' $rca.Name `
            'Root CA is offline (not in Enrollment Services)' `
            'Good: Root CA is not listed as an active enrollment service.'
    }

    if ($rca.Cert) {
        $left = $rca.Cert.NotAfter - (Get-Date)
        if ($left.TotalDays -le 0) {
            Add-Finding $SEV_CRITICAL 'Hierarchy' $rca.Name 'Root CA certificate EXPIRED' ''
        } elseif ($left.TotalDays -le 365) {
            Add-Finding $SEV_HIGH 'Hierarchy' $rca.Name `
                'Root CA cert expires within 1 year' "Expires: $($rca.Cert.NotAfter)"
        }
        if ($rca.Cert.SignatureAlgorithm.FriendlyName -match 'sha1|md5') {
            Add-Finding $SEV_HIGH 'Hierarchy' $rca.Name `
                'Root CA uses weak signature algorithm' $rca.Cert.SignatureAlgorithm.FriendlyName
        }
        if ($rca.Cert.PublicKey.Key.KeySize -lt 2048) {
            Add-Finding $SEV_CRITICAL 'Hierarchy' $rca.Name `
                'Root CA key size below 2048-bit' "$($rca.Cert.PublicKey.Key.KeySize)-bit"
        }
    }
}

foreach ($ca in $enterpriseCAs) {
    if ($ca.Cert) {
        $isSelfSigned = $ca.Cert.Subject -eq $ca.Cert.Issuer
        $isRoot       = $rootCAs | Where-Object { $_.Name -eq $ca.Name }
        if ($isSelfSigned -and -not $isRoot) {
            Add-Finding $SEV_HIGH 'Hierarchy' $ca.Name `
                'Issuing CA certificate appears self-signed but is not a known Root CA' `
                'Verify certificate chain integrity.'
        }
    }
}

if ($rootCAs.Count -eq 0) {
    Add-Finding $SEV_MEDIUM 'Hierarchy' 'PKI' 'No root CAs found in CN=Certification Authorities' `
        'Ensure root CA certificates are published to AD.'
}

#endregion

#region ---- 4. CRL Health ---------------------------------------------------

Write-Section "4. CRL and OCSP Health"

$cdpResults = Search-ADObjects -BaseDN $cdpBase `
    -Filter '(objectClass=cRLDistributionPoint)' `
    -Properties @('cn','certificateRevocationList','deltaRevocationList','whenChanged')

$crlCount = 0
foreach ($r in $cdpResults) {
    $p    = $r.Properties
    $name = if ($p['cn'].Count) { $p['cn'][0] } else { '(unknown)' }

    $checkCRL = {
        param($rawCRL, $type, $caName)
        if (-not $rawCRL -or $rawCRL.Count -eq 0) { return }
        $tmpFile = [System.IO.Path]::GetTempFileName() + '.crl'
        try {
            [System.IO.File]::WriteAllBytes($tmpFile, [byte[]]$rawCRL[0])
            $info = Invoke-CertUtil "-dump $tmpFile"
            if ($info -match 'Next CRL Publish\s*:\s*(.+)') {
                $nextStr = $matches[1].Trim()
                try {
                    $next = [DateTime]::Parse($nextStr)
                    $diff = $next - (Get-Date)
                    if ($diff.TotalHours -lt 0) {
                        Add-Finding $SEV_CRITICAL 'CRL' $caName `
                            "$type CRL is OVERDUE for publishing" "Was due: $next"
                    } elseif ($diff.TotalHours -lt 4) {
                        Add-Finding $SEV_HIGH 'CRL' $caName `
                            "$type CRL publish window almost expired" "Due in: $(Format-TimeSpan $diff)"
                    } elseif ($diff.TotalHours -lt 24) {
                        Add-Finding $SEV_MEDIUM 'CRL' $caName `
                            "$type CRL publish window < 24 hours" "Due in: $(Format-TimeSpan $diff)"
                    } else {
                        Add-Finding $SEV_INFO 'CRL' $caName `
                            "$type CRL is current" "Next publish: $next (in $(Format-TimeSpan $diff))"
                    }
                } catch { }
            }
            if ($info -match 'Next Update\s*:\s*(.+)') {
                $nextStr = $matches[1].Trim()
                try {
                    $next = [DateTime]::Parse($nextStr)
                    $diff = $next - (Get-Date)
                    if ($diff.TotalHours -lt 0) {
                        Add-Finding $SEV_CRITICAL 'CRL' $caName "$type CRL has EXPIRED" "Expired: $next"
                    } elseif ($diff.TotalHours -lt 24) {
                        Add-Finding $SEV_HIGH 'CRL' $caName `
                            "$type CRL expiring within 24 hours" "Expires: $next"
                    }
                } catch { }
            }
        } finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
    }

    & $checkCRL $p['certificateRevocationList'] 'Base' $name
    & $checkCRL $p['deltaRevocationList'] 'Delta' $name
    $crlCount++
}

if ($crlCount -eq 0) {
    Add-Finding $SEV_MEDIUM 'CRL' 'PKI' `
        'No CRL objects found in AD CDP container' `
        'Ensure CRLs are published to Active Directory.'
}

$aiaResults = Search-ADObjects -BaseDN $aiaBase `
    -Filter '(objectClass=certificationAuthority)' `
    -Properties @('cn','cACertificate')
Write-Host "  AIA entries found: $(@($aiaResults).Count)"

#endregion

#region ---- 5. Certificate Template Security --------------------------------

Write-Section "5. Certificate Template Security Analysis"

$templateResults = Search-ADObjects -BaseDN $templateBase `
    -Filter '(objectClass=pKICertificateTemplate)' `
    -Properties @('cn','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag',
                   'msPKI-RA-Signature','msPKI-Template-Schema-Version',
                   'pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy',
                   'msPKI-Private-Key-Flag','pKIDefaultKeySpec',
                   'pKIExpirationPeriod','pKIOverlapPeriod',
                   'nTSecurityDescriptor','displayName','revision')

$allTemplates   = @()
$publishedNames = $enterpriseCAs | ForEach-Object { $_.Templates } | Sort-Object -Unique

Write-Host "  Templates found in AD       : $(@($templateResults).Count)"
Write-Host "  Templates published to a CA : $(@($publishedNames).Count)"

foreach ($r in $templateResults) {
    $p        = $r.Properties
    $tName    = if ($p['cn'].Count)          { $p['cn'][0] }          else { 'Unknown' }
    $dispName = if ($p['displayName'].Count) { $p['displayName'][0] } else { $tName }
    $schemaVer = if ($p['msPKI-Template-Schema-Version'].Count) { [int]$p['msPKI-Template-Schema-Version'][0] } else { 1 }
    $isPublished = $publishedNames -contains $tName

    $nameFlag   = if ($p['msPKI-Certificate-Name-Flag'].Count)  { [int]$p['msPKI-Certificate-Name-Flag'][0] }  else { 0 }
    $enrollFlag = if ($p['msPKI-Enrollment-Flag'].Count)        { [int]$p['msPKI-Enrollment-Flag'][0] }        else { 0 }
    $raSig      = if ($p['msPKI-RA-Signature'].Count)           { [int]$p['msPKI-RA-Signature'][0] }           else { 0 }
    $pkiFlag    = if ($p['msPKI-Private-Key-Flag'].Count)       { [int]$p['msPKI-Private-Key-Flag'][0] }       else { 0 }

    $ekus = @()
    if ($p['pKIExtendedKeyUsage'].Count -gt 0)               { $ekus = @($p['pKIExtendedKeyUsage']) }
    elseif ($p['msPKI-Certificate-Application-Policy'].Count) { $ekus = @($p['msPKI-Certificate-Application-Policy']) }

    $enrolleeSuppliesSubject = ($nameFlag   -band $ENROLLEE_SUPPLIES_SUBJECT) -ne 0
    $requiresApproval        = ($enrollFlag -band $PEND_ALL_REQUESTS)         -ne 0
    $noSecurityExtension     = ($enrollFlag -band $NO_SECURITY_EXTENSION)     -ne 0
    $hasAnyPurpose           = $ekus -contains $EKU_ANY_PURPOSE
    $hasClientAuth           = $ekus -contains $EKU_CLIENT_AUTH
    $hasRAAgent              = $ekus -contains $EKU_CERT_REQUEST_AGENT
    $noEku                   = $ekus.Count -eq 0
    $isExportable            = ($pkiFlag    -band $EXPORTABLE_KEY)            -ne 0

    $validityDays = 0
    if ($p['pKIExpirationPeriod'].Count) {
        try {
            $raw  = [byte[]]$p['pKIExpirationPeriod'][0]
            $val  = [BitConverter]::ToInt64($raw, 0)
            $validityDays = [Math]::Abs($val / 864000000000)
        } catch { }
    }

    Write-Host "  Template: $tName  (schema v$schemaVer, $(if($isPublished){'PUBLISHED'}else{'not published'}))"

    # ESC1
    if ($enrolleeSuppliesSubject -and (-not $requiresApproval) -and ($hasClientAuth -or $hasAnyPurpose -or $noEku)) {
        if ($isPublished) {
            Add-Finding $SEV_CRITICAL 'Template-ESC1' $tName `
                'ESC1: Enrollee can specify SAN with no manager approval' `
                "Flags: NameFlag=0x$($nameFlag.ToString('X')) EnrollFlag=0x$($enrollFlag.ToString('X')). EKUs: $($ekus -join ', '). Allows domain privilege escalation via SAN spoofing."
        } else {
            Add-Finding $SEV_MEDIUM 'Template-ESC1' $tName `
                'ESC1 conditions present (template not currently published)' `
                'Would be exploitable if published.'
        }
    }

    # ESC2
    if ($hasAnyPurpose -and $isPublished -and (-not $requiresApproval)) {
        Add-Finding $SEV_HIGH 'Template-ESC2' $tName `
            'ESC2: Template has Any Purpose EKU' `
            'Certificate can be used for any purpose including client authentication.'
    }
    if ($noEku -and $isPublished -and (-not $requiresApproval) -and $schemaVer -gt 1) {
        Add-Finding $SEV_HIGH 'Template-ESC2' $tName `
            'ESC2: Template has no EKU (unrestricted use)' `
            'No EKU means the certificate is valid for any purpose.'
    }

    # ESC3
    if ($hasRAAgent -and $isPublished -and (-not $requiresApproval)) {
        Add-Finding $SEV_HIGH 'Template-ESC3' $tName `
            'ESC3: Certificate Request Agent EKU present' `
            'Allows on-behalf-of enrollment to impersonate other users.'
    }

    # ESC4
    if (-not $SkipTemplateAcls) {
        try {
            $de  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($r.Path -replace 'LDAP://','')")
            $sec = $de.ObjectSecurity
            if ($sec) {
                foreach ($ace in $sec.Access) {
                    $rights    = $ace.ActiveDirectoryRights.ToString()
                    $principal = try { $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $ace.IdentityReference.Value }
                    $isLowPriv = Test-IsLowPrivTrustee -TrusteeName $principal
                    $isDangerous = ($rights -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner') -and
                                   ($ace.AccessControlType -eq 'Allow')
                    if ($isLowPriv -and $isDangerous) {
                        Add-Finding $SEV_HIGH 'Template-ESC4' $tName `
                            'ESC4: Low-privilege principal has write rights on template' `
                            "Principal: $principal  Rights: $rights"
                    }
                }
            }
        } catch {
            Write-Warning "  Could not read ACL for template $tName : $($_.Exception.Message)"
        }
    }

    # Excessive validity
    if ($validityDays -gt 3650 -and $isPublished) {
        Add-Finding $SEV_MEDIUM 'Template-Validity' $tName `
            'Template validity period exceeds 10 years' `
            "Validity: $([int]$validityDays) days."
    } elseif ($validityDays -gt 1825 -and $isPublished) {
        Add-Finding $SEV_LOW 'Template-Validity' $tName `
            'Template validity period exceeds 5 years' `
            "Validity: $([int]$validityDays) days."
    }

    # Exportable key
    if ($isExportable -and $isPublished) {
        Add-Finding $SEV_LOW 'Template-Key' $tName `
            'Template allows exportable private keys' `
            'Allows key material to be exported and potentially exfiltrated.'
    }

    # No security extension (ESC9)
    if ($noSecurityExtension -and $isPublished) {
        Add-Finding $SEV_MEDIUM 'Template-ESC9' $tName `
            'Template has CT_FLAG_NO_SECURITY_EXTENSION set' `
            'ESC9/ESC10 risk: szOID_NTDS_CA_SECURITY_EXT not included in issued certificates.'
    }

    if ($requiresApproval) {
        Add-Finding $SEV_INFO 'Template-Approval' $tName `
            'Manager approval required (mitigates some ESC risks)' ''
    }

    if ($schemaVer -eq 1 -and $isPublished) {
        Add-Finding $SEV_LOW 'Template-Schema' $tName `
            'V1 template schema (lacks V2/V3 security controls)' `
            'Consider migrating to V2 or V3 template schema for enhanced security.'
    }

    $allTemplates += [PSCustomObject]@{
        Name                    = $tName
        DisplayName             = $dispName
        Published               = $isPublished
        SchemaVersion           = $schemaVer
        EKUs                    = ($ekus -join '; ')
        EnrolleeSuppliesSubject = $enrolleeSuppliesSubject
        RequiresApproval        = $requiresApproval
        HasAnyPurpose           = $hasAnyPurpose
        HasClientAuth           = $hasClientAuth
        HasRAAgent              = $hasRAAgent
        ExportableKey           = $isExportable
        ValidityDays            = [int]$validityDays
    }
}

#endregion

#region ---- 6. CA-level security flags (ESC6, ESC7, ESC8) ------------------

Write-Section "6. CA-Level Security Configuration"

foreach ($ca in $enterpriseCAs) {
    Write-Host "  Checking CA: $($ca.Name) on $($ca.Host)"

    try {
        $ca.Reachable = (Test-Connection -ComputerName $ca.Host -Count 1 -Quiet -ErrorAction Stop)
    } catch { $ca.Reachable = $false }

    if (-not $ca.Reachable) {
        Add-Finding $SEV_MEDIUM 'CA-Config' $ca.Name `
            'CA host not reachable (skipping live checks)' `
            "Host: $($ca.Host). Ensure the CA service is running."
        continue
    }

    # ESC6
    try {
        $regOut = & certutil.exe -config "$($ca.Host)\$($ca.Name)" -getreg policy\EditFlags 2>&1
        $regStr = $regOut -join ' '
        if ($regStr -match 'EditFlags\s*=\s*(0x[0-9a-fA-F]+)') {
            $flags = [Convert]::ToInt32($matches[1], 16)
            if ($flags -band $IF_ATTRIBUTESUBJECTALTNAME2) {
                Add-Finding $SEV_CRITICAL 'CA-ESC6' $ca.Name `
                    'ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag is SET' `
                    'Any CSR can include an arbitrary SAN regardless of template settings.'
            } else {
                Add-Finding $SEV_INFO 'CA-ESC6' $ca.Name 'EDITF_ATTRIBUTESUBJECTALTNAME2 is NOT set (good)' ''
            }
        }
    } catch {
        Add-Finding $SEV_LOW 'CA-Config' $ca.Name 'Could not read CA EditFlags via certutil' $_.Exception.Message
    }

    # Audit settings
    try {
        $auditOut = & certutil.exe -config "$($ca.Host)\$($ca.Name)" -getreg CA\AuditFilter 2>&1
        if (($auditOut -join ' ') -match 'AuditFilter\s*=\s*(0x[0-9a-fA-F]+|\d+)') {
            $auditVal = try { [Convert]::ToInt32($matches[1], 16) } catch { [int]$matches[1] }
            if ($auditVal -eq 0) {
                Add-Finding $SEV_MEDIUM 'CA-Audit' $ca.Name `
                    'CA auditing is DISABLED' `
                    'Enable CA auditing to log certificate requests, issuance, and revocation events.'
            } else {
                Add-Finding $SEV_INFO 'CA-Audit' $ca.Name "CA auditing enabled (filter: 0x$($auditVal.ToString('X')))" ''
            }
        }
    } catch { }

    # ESC8: HTTP web enrollment
    $webEnrollUrl = "http://$($ca.Host)/certsrv/"
    try {
        $resp = Invoke-WebRequest -Uri $webEnrollUrl -UseDefaultCredentials -TimeoutSec 5 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            Add-Finding $SEV_HIGH 'CA-ESC8' $ca.Name `
                'ESC8: HTTP web enrollment endpoint is accessible' `
                "URL: $webEnrollUrl. Enforce HTTPS and enable channel binding (EPA)."
        }
    } catch [System.Net.WebException] {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 401) {
            Add-Finding $SEV_MEDIUM 'CA-ESC8' $ca.Name `
                'ESC8: Web enrollment endpoint exists and requires auth (verify HTTPS)' `
                "URL: $webEnrollUrl. Verify HTTPS is enforced and Extended Protection is enabled."
        }
    } catch {
        Add-Finding $SEV_INFO 'CA-ESC8' $ca.Name 'Web enrollment endpoint not reachable' $webEnrollUrl
    }

    # ESC7: CA ACL
    try {
        $caDE  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($ca.DN)")
        $caSec = $caDE.ObjectSecurity
        if ($caSec) {
            foreach ($ace in $caSec.Access) {
                $principal = try { $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $ace.IdentityReference.Value }
                $rights    = $ace.ActiveDirectoryRights.ToString()
                $isLow     = Test-IsLowPrivTrustee -TrusteeName $principal
                $isDanger  = ($rights -match 'GenericAll|ManageCA|ManageCertificates|WriteDacl|WriteOwner') -and
                             ($ace.AccessControlType -eq 'Allow')
                if ($isLow -and $isDanger) {
                    Add-Finding $SEV_CRITICAL 'CA-ESC7' $ca.Name `
                        'ESC7: Low-privilege principal has CA management rights' `
                        "Principal: $principal  Rights: $rights"
                }
            }
        }
    } catch {
        Write-Warning "  Could not read ACL for CA $($ca.Name): $($_.Exception.Message)"
    }
}

#endregion

#region ---- 7. NTAuthCertificates -------------------------------------------

Write-Section "7. NTAuthCertificates Store"

$ntAuthCertSubjects = @()
try {
    $ntAuth = Get-ADObject -Path $ntAuthBase -Properties @('cACertificate')
    if ($ntAuth) {
        $certs = $ntAuth.Properties['cACertificate']
        Write-Host "  Certificates in NTAuth store: $($certs.Count)"
        foreach ($rawC in $certs) {
            $c = Get-CertExpiry ([byte[]]$rawC)
            if ($c) {
                $ntAuthCertSubjects += $c.Subject
                $left = $c.NotAfter - (Get-Date)
                Write-Host "    Subject: $($c.Subject)  Expires: $($c.NotAfter)"
                if ($left.TotalDays -le 0) {
                    Add-Finding $SEV_CRITICAL 'NTAuth' $c.Subject 'NTAuth certificate EXPIRED' ''
                } elseif ($left.TotalDays -le 90) {
                    Add-Finding $SEV_HIGH 'NTAuth' $c.Subject `
                        'NTAuth certificate expires within 90 days' "Expires: $($c.NotAfter)"
                }
                if ($c.SignatureAlgorithm.FriendlyName -match 'sha1|md5') {
                    Add-Finding $SEV_HIGH 'NTAuth' $c.Subject `
                        'NTAuth cert uses weak signature algorithm' $c.SignatureAlgorithm.FriendlyName
                }
            }
        }
    }
} catch {
    Write-Warning "Could not read NTAuthCertificates: $($_.Exception.Message)"
}

#endregion

#region ---- 8. CDP and AIA URL Reachability ---------------------------------

Write-Section "8. CDP and AIA URL Reachability"

$script:UrlResults = [System.Collections.Generic.List[PSCustomObject]]::new()

$allCACerts = @()
foreach ($ca in $enterpriseCAs)  { if ($ca.Cert)  { $allCACerts += @{ Name = $ca.Name; Cert = $ca.Cert } } }
foreach ($rca in $rootCAs)       { if ($rca.Cert) { $allCACerts += @{ Name = $rca.Name; Cert = $rca.Cert } } }

$testedUrls = @{}

foreach ($entry in $allCACerts) {
    $caName = $entry.Name
    $cert   = $entry.Cert

    # CDP URLs
    $cdpUrls = Get-CertExtensionUrls -Cert $cert -OID $OID_CDP
    # AIA / OCSP URLs
    $aiaUrls = Get-CertExtensionUrls -Cert $cert -OID $OID_AIA

    foreach ($url in ($cdpUrls + $aiaUrls)) {
        if ($testedUrls.ContainsKey($url)) { continue }
        $testedUrls[$url] = $true

        $urlType = if ($url -in $cdpUrls) { 'CDP' } else { 'AIA/OCSP' }
        Write-Host "  Testing $urlType : $url" -NoNewline

        $res = Test-UrlReachable -Url $url
        Write-Host "  [$($res.Status)]" -ForegroundColor (if ($res.Reachable) { 'Green' } else { 'Red' })

        $script:UrlResults.Add([PSCustomObject]@{
            CA        = $caName
            Type      = $urlType
            Url       = $url
            Reachable = $res.Reachable
            Status    = $res.Status
        })

        if (-not $res.Reachable) {
            $sev = if ($urlType -eq 'CDP') { $SEV_HIGH } else { $SEV_MEDIUM }
            Add-Finding $sev 'URL-Reachability' $caName `
                "$urlType endpoint unreachable: $url" `
                "Status: $($res.Status). Clients cannot obtain revocation data — certificates may fail validation."
        } else {
            Add-Finding $SEV_INFO 'URL-Reachability' $caName "$urlType endpoint reachable" $url
        }
    }

    if ($cdpUrls.Count -eq 0) {
        Add-Finding $SEV_HIGH 'URL-Reachability' $caName `
            'No CDP URLs found in CA certificate' `
            'Clients will not be able to check certificate revocation status.'
    }
    if ($aiaUrls.Count -eq 0) {
        Add-Finding $SEV_LOW 'URL-Reachability' $caName `
            'No AIA/OCSP URLs found in CA certificate' `
            'Consider adding an OCSP responder URL for online revocation checking.'
    }

    # Check for HTTP-only CDP (not HTTPS) — LDAP is acceptable for internal
    $httpOnlyCdp = $cdpUrls | Where-Object { $_ -match '^http://' }
    if ($httpOnlyCdp) {
        Add-Finding $SEV_LOW 'URL-Reachability' $caName `
            'CDP uses plain HTTP (not HTTPS)' `
            "CRL is served over unencrypted HTTP: $($httpOnlyCdp -join ', '). Consider HTTPS or LDAP."
    }
}

if ($allCACerts.Count -eq 0) {
    Write-Host "  No CA certificates available to check URLs." -ForegroundColor Yellow
}

#endregion

#region ---- 9. Unauthorized Trusted Certificates ----------------------------

Write-Section "9. Unauthorized Trusted Certificates"

# Build a fingerprint set of all known CA certs (Enterprise + Root)
$knownThumbprints = @{}
foreach ($entry in $allCACerts) {
    $knownThumbprints[$entry.Cert.Thumbprint] = $entry.Name
}

# Check NTAuthCertificates for certs not matching any known Enterprise or Root CA
try {
    $ntAuthRaw = Get-ADObject -Path $ntAuthBase -Properties @('cACertificate')
    if ($ntAuthRaw) {
        foreach ($rawC in $ntAuthRaw.Properties['cACertificate']) {
            $c = Get-CertExpiry ([byte[]]$rawC)
            if (-not $c) { continue }
            if (-not $knownThumbprints.ContainsKey($c.Thumbprint)) {
                Add-Finding $SEV_CRITICAL 'Unauthorized-Cert' $c.Subject `
                    'NTAuthCertificates contains an UNRECOGNIZED CA certificate' `
                    "Thumbprint: $($c.Thumbprint). This CA can issue domain authentication certificates. Verify immediately."
            } else {
                Add-Finding $SEV_INFO 'Unauthorized-Cert' $c.Subject `
                    'NTAuth certificate matches known CA' "Thumbprint: $($c.Thumbprint)"
            }
        }
    }
} catch {
    Write-Warning "Could not re-read NTAuthCertificates: $($_.Exception.Message)"
}

# Check AIA container for unexpected or weak CA certs
foreach ($r in @($aiaResults)) {
    $p   = $r.Properties
    $raw = if ($p['caCertificate'].Count) { [byte[]]$p['caCertificate'][0] } else { $null }
    if (-not $raw) { continue }
    $c = Get-CertExpiry $raw
    if (-not $c) { continue }

    if ($c.SignatureAlgorithm.FriendlyName -match 'sha1|md5') {
        Add-Finding $SEV_HIGH 'Unauthorized-Cert' $c.Subject `
            'AIA store contains a CA cert with a weak signature algorithm' `
            "Algorithm: $($c.SignatureAlgorithm.FriendlyName). Thumbprint: $($c.Thumbprint)"
    }
    $left = $c.NotAfter - (Get-Date)
    if ($left.TotalDays -le 0) {
        Add-Finding $SEV_MEDIUM 'Unauthorized-Cert' $c.Subject `
            'AIA store contains an EXPIRED CA certificate' `
            "Expired: $($c.NotAfter). Remove stale certificates to keep the AIA store clean."
    }
    if (-not $knownThumbprints.ContainsKey($c.Thumbprint)) {
        Add-Finding $SEV_MEDIUM 'Unauthorized-Cert' $c.Subject `
            'AIA store contains a certificate not matching any known CA' `
            "Thumbprint: $($c.Thumbprint). Verify this is expected."
    }
}

#endregion

#region ---- 10. CA Operational Best Practices --------------------------------

Write-Section "10. CA Operational Best Practices"

foreach ($ca in ($enterpriseCAs | Where-Object { $_.Reachable })) {
    $caConfig = "$($ca.Host)\$($ca.Name)"
    Write-Host "  Checking operational config: $($ca.Name)"

    # ---- HSM key protection ----
    try {
        $cspOut = & certutil.exe -config $caConfig -getreg CA\CSP\Provider 2>&1
        $cspStr = ($cspOut -join ' ')
        if ($cspStr -match 'Provider\s*=\s*REG_SZ\s*=\s*(.+)') {
            $providerName = $matches[1].Trim()
            Write-Host "    CSP/KSP: $providerName"
            $isHSM = $HSM_PROVIDER_PATTERNS | Where-Object { $providerName -like "*$_*" }
            if ($isHSM) {
                Add-Finding $SEV_INFO 'CA-Operational' $ca.Name `
                    'CA private key protected by HSM' "Provider: $providerName"
            } else {
                Add-Finding $SEV_MEDIUM 'CA-Operational' $ca.Name `
                    'CA private key may NOT be HSM-protected' `
                    "Provider: $providerName. HSM-based key storage is required for enterprise CAs under most compliance frameworks."
            }
        }
    } catch { }

    # ---- Role separation: who holds ManageCA vs ManageCertificates ----
    # These are DCOM rights, checked via certutil -cainfo
    try {
        $infoOut = & certutil.exe -config $caConfig -cainfo 2>&1
        $infoStr = $infoOut -join "`n"

        $caAdmins   = @()
        $certMgrs   = @()
        if ($infoStr -match '(?ms)CA Admins:(.*?)(?=CA Officers:|$)') {
            $caAdmins = ($matches[1] -split "`n" | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() })
        }
        if ($infoStr -match '(?ms)CA Officers:(.*?)(?=\n\w|$)') {
            $certMgrs = ($matches[1] -split "`n" | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() })
        }

        if ($caAdmins.Count -gt 0 -or $certMgrs.Count -gt 0) {
            $overlap = $caAdmins | Where-Object { $certMgrs -contains $_ }
            if ($overlap.Count -gt 0) {
                Add-Finding $SEV_LOW 'CA-Operational' $ca.Name `
                    'Same accounts hold both CA Admin and Certificate Manager roles' `
                    "Accounts: $($overlap -join ', '). Role separation is a PKI best practice."
            } else {
                Add-Finding $SEV_INFO 'CA-Operational' $ca.Name `
                    'CA Admin and Certificate Manager roles appear to be separated' ''
            }
        }
    } catch { }

    # ---- Enrollment agent restrictions ----
    try {
        $eaOut = & certutil.exe -config $caConfig -getreg CA\EnrollmentAgentPolicy 2>&1
        $eaStr = ($eaOut -join ' ')
        if ($eaStr -match 'EnrollmentAgentPolicy\s*=\s*(0x[0-9a-fA-F]+|\d+)') {
            $eaPolicy = try { [Convert]::ToInt32($matches[1], 16) } catch { [int]$matches[1] }
            if ($eaPolicy -eq 0) {
                Add-Finding $SEV_MEDIUM 'CA-Operational' $ca.Name `
                    'Enrollment agent restrictions are NOT configured' `
                    'Any holder of an enrollment agent certificate can enroll on behalf of any user. Configure enrollment agent restrictions in the CA properties.'
            } else {
                Add-Finding $SEV_INFO 'CA-Operational' $ca.Name `
                    'Enrollment agent restrictions are configured' "Policy value: $eaPolicy"
            }
        }
    } catch { }

    # ---- Last backup check ----
    try {
        $backupOut = & certutil.exe -config $caConfig -getreg CA\DBLastFullBackup 2>&1
        $backupStr = ($backupOut -join ' ')
        if ($backupStr -match 'DBLastFullBackup\s*=\s*REG_DWORD\s*=\s*(0x[0-9a-fA-F]+|\d+)') {
            $backupTicks = [Convert]::ToInt64($matches[1], 16)
            if ($backupTicks -gt 0) {
                $backupDate = [DateTime]::FromFileTime($backupTicks)
                $daysSince  = ((Get-Date) - $backupDate).TotalDays
                Write-Host "    Last backup: $backupDate ($([int]$daysSince) days ago)"
                if ($daysSince -gt 30) {
                    Add-Finding $SEV_HIGH 'CA-Operational' $ca.Name `
                        'CA database not backed up in >30 days' `
                        "Last backup: $backupDate ($([int]$daysSince) days ago). Back up the CA database and private key regularly."
                } elseif ($daysSince -gt 7) {
                    Add-Finding $SEV_MEDIUM 'CA-Operational' $ca.Name `
                        'CA database not backed up in >7 days' `
                        "Last backup: $backupDate ($([int]$daysSince) days ago)."
                } else {
                    Add-Finding $SEV_INFO 'CA-Operational' $ca.Name `
                        'CA database backed up recently' "Last backup: $backupDate"
                }
            } else {
                Add-Finding $SEV_HIGH 'CA-Operational' $ca.Name `
                    'No CA database backup recorded' `
                    'Ensure CA database and private key are backed up regularly.'
            }
        }
    } catch { }

    # ---- Validity period sanity: CA cert should cover all issued certs ----
    if ($ca.Cert) {
        $caLifeRemaining = ($ca.Cert.NotAfter - (Get-Date)).TotalDays
        foreach ($t in ($allTemplates | Where-Object { $_.Published -and $ca.Templates -contains $_.Name })) {
            if ($t.ValidityDays -gt 0 -and ($t.ValidityDays * 2) -gt $caLifeRemaining) {
                Add-Finding $SEV_MEDIUM 'CA-Operational' $ca.Name `
                    "Template '$($t.Name)' validity may exceed remaining CA certificate life" `
                    "Template validity: $($t.ValidityDays)d, CA cert remaining: $([int]$caLifeRemaining)d. Issued certs could outlive the CA cert."
            }
        }
    }
}

#endregion

#region ---- 11. Issued Certificate Anomaly Detection ------------------------

Write-Section "11. Issued Certificate Anomaly Detection"

$script:AnomalousIssuances = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($SkipIssuedCertAudit) {
    Write-Host "  Skipped (SkipIssuedCertAudit switch set)." -ForegroundColor Yellow
    Add-Finding $SEV_INFO 'IssuedCerts' 'N/A' 'Issued certificate audit was skipped' '-SkipIssuedCertAudit was set.'
} else {
    # Resolve privileged account names from well-known groups
    $privGroupDNs = @(
        "CN=Domain Admins,CN=Users,$domainName",
        "CN=Enterprise Admins,CN=Users,$domainName",
        "CN=Schema Admins,CN=Users,$domainName",
        "CN=Administrators,CN=Builtin,$domainName"
    )
    $privAccounts = @('Administrator', 'krbtgt')
    foreach ($dn in $privGroupDNs) {
        $members = Get-GroupMemberNames -GroupDN $dn
        $privAccounts += $members
    }
    $privAccounts = $privAccounts | Sort-Object -Unique
    Write-Host "  Privileged accounts to check: $($privAccounts.Count)"

    foreach ($ca in ($enterpriseCAs | Where-Object { $_.Reachable })) {
        $caConfig = "$($ca.Host)\$($ca.Name)"
        Write-Host "  Querying CA database: $caConfig (last $AuditDays days, cap $MAX_AUDIT_ROWS certs)"

        $issuedCerts = Get-IssuedCertsFromCA -CAConfig $caConfig -DaysBack $AuditDays

        if ($issuedCerts.Count -eq 0) {
            Add-Finding $SEV_INFO 'IssuedCerts' $ca.Name `
                "No issued certificates found in last $AuditDays days (or access denied)" ''
            continue
        }

        Add-Finding $SEV_INFO 'IssuedCerts' $ca.Name `
            "Issued certificate audit: $($issuedCerts.Count) certs retrieved" `
            "Period: last $AuditDays days"

        # Group for bulk issuance detection (template + hour bucket)
        $bulkGroups = $issuedCerts | Where-Object { $_.'Certificate Template' -and $_.'NotBefore' } |
            Group-Object {
                $t = $_.'Certificate Template'
                $d = $_.'NotBefore'
                $h = if ($d -is [DateTime]) { $d.ToString('yyyyMMddHH') } else { 'unknown' }
                "$t|$h"
            }

        foreach ($grp in $bulkGroups) {
            if ($grp.Count -ge $BULK_THRESHOLD_PER_HOUR) {
                $parts    = $grp.Name -split '\|'
                $tmplName = $parts[0]
                $hourStr  = if ($parts.Count -gt 1) { $parts[1] } else { 'unknown' }
                Add-Finding $SEV_HIGH 'IssuedCerts' $ca.Name `
                    "Bulk issuance detected: $($grp.Count) certs from template '$tmplName' in one hour" `
                    "Hour: $hourStr. Investigate whether this represents an automated enrollment, attack, or misconfiguration."
                $script:AnomalousIssuances.Add([PSCustomObject]@{
                    CA = $ca.Name; Type = 'Bulk Issuance'
                    Detail = "Template: $tmplName | Hour: $hourStr | Count: $($grp.Count)"
                })
            }
        }

        foreach ($row in $issuedCerts) {
            $requester = $row.'Requester Name'
            $san       = $row.'SubjectAltName'
            $template  = $row.'Certificate Template'
            $notBefore = $row.'NotBefore'
            $notAfter  = $row.'NotAfter'
            $cn        = $row.'CommonName'

            # ---- Privileged account requester ----
            if ($requester) {
                $samName = ($requester -split '\\')[-1]
                if ($privAccounts -contains $samName) {
                    Add-Finding $SEV_HIGH 'IssuedCerts' $ca.Name `
                        "Certificate issued to privileged account: $requester" `
                        "Template: $template | CN: $cn | NotBefore: $notBefore. Verify this issuance was authorized."
                    $script:AnomalousIssuances.Add([PSCustomObject]@{
                        CA = $ca.Name; Type = 'Privileged Account'
                        Detail = "Requester: $requester | Template: $template | NotBefore: $notBefore"
                    })
                }
            }

            # ---- Off-hours issuance (11 PM – 5 AM local, or weekends) ----
            if ($notBefore -is [DateTime]) {
                $h   = $notBefore.Hour
                $dow = $notBefore.DayOfWeek
                $isOffHours = ($h -ge 23 -or $h -lt 5) -or ($dow -eq 'Saturday' -or $dow -eq 'Sunday')
                if ($isOffHours) {
                    Add-Finding $SEV_LOW 'IssuedCerts' $ca.Name `
                        "Certificate issued outside business hours" `
                        "IssuedAt: $notBefore ($dow) | Requester: $requester | Template: $template"
                    $script:AnomalousIssuances.Add([PSCustomObject]@{
                        CA = $ca.Name; Type = 'Off-Hours Issuance'
                        Detail = "IssuedAt: $notBefore | Requester: $requester | Template: $template"
                    })
                }
            }

            # ---- Unusual SAN values ----
            if ($san) {
                # IP address SAN
                if ($san -match 'IP Address=[\d\.]+') {
                    Add-Finding $SEV_MEDIUM 'IssuedCerts' $ca.Name `
                        "Certificate contains an IP address SAN" `
                        "SAN: $san | Requester: $requester | Template: $template"
                    $script:AnomalousIssuances.Add([PSCustomObject]@{
                        CA = $ca.Name; Type = 'IP SAN'
                        Detail = "SAN: $san | Requester: $requester"
                    })
                }
                # Wildcard SAN
                if ($san -match '\*\.') {
                    Add-Finding $SEV_MEDIUM 'IssuedCerts' $ca.Name `
                        "Certificate contains a wildcard SAN" `
                        "SAN: $san | Requester: $requester | Template: $template"
                    $script:AnomalousIssuances.Add([PSCustomObject]@{
                        CA = $ca.Name; Type = 'Wildcard SAN'
                        Detail = "SAN: $san | Requester: $requester"
                    })
                }
                # UPN that doesn't match the domain
                $domainShort = ($domainName -replace 'DC=','' -split ',' | ForEach-Object { $_.Trim() }) -join '.'
                if ($san -match 'Principal Name=([^,\s]+)') {
                    $upn = $matches[1]
                    if ($upn -notmatch [regex]::Escape($domainShort)) {
                        Add-Finding $SEV_MEDIUM 'IssuedCerts' $ca.Name `
                            "Certificate UPN SAN does not match domain: $upn" `
                            "SAN: $san | Requester: $requester | Template: $template"
                        $script:AnomalousIssuances.Add([PSCustomObject]@{
                            CA = $ca.Name; Type = 'Foreign UPN SAN'
                            Detail = "UPN: $upn | Requester: $requester"
                        })
                    }
                }
            }

            # ---- Excessive validity in issued certificate (> 3 years) ----
            if ($notBefore -is [DateTime] -and $notAfter -is [DateTime]) {
                $certLifeDays = ($notAfter - $notBefore).TotalDays
                if ($certLifeDays -gt 1095) {
                    Add-Finding $SEV_LOW 'IssuedCerts' $ca.Name `
                        "Issued certificate has validity > 3 years ($([int]$certLifeDays) days)" `
                        "Requester: $requester | Template: $template | Expires: $notAfter"
                    $script:AnomalousIssuances.Add([PSCustomObject]@{
                        CA = $ca.Name; Type = 'Long Validity'
                        Detail = "Days: $([int]$certLifeDays) | Requester: $requester | Template: $template"
                    })
                }
            }
        }

        Write-Host "  Anomalies detected for $($ca.Name): $($script:AnomalousIssuances.Count)" -ForegroundColor (if ($script:AnomalousIssuances.Count -gt 0) { 'Yellow' } else { 'Green' })
    }

    $reachableCAs = @($enterpriseCAs | Where-Object { $_.Reachable })
    if ($reachableCAs.Count -eq 0) {
        Write-Host "  No reachable Enterprise CAs — issued cert audit skipped." -ForegroundColor Yellow
    }
}

#endregion

#region ---- 12. Summary & Report generation ---------------------------------

Write-Section "12. Summary"

$bySeverity = $script:Findings | Group-Object Severity
Write-Host ""
Write-Host "  Findings summary:" -ForegroundColor White
foreach ($grp in $bySeverity | Sort-Object { @($SEV_CRITICAL,$SEV_HIGH,$SEV_MEDIUM,$SEV_LOW,$SEV_INFO).IndexOf($_.Name) }) {
    $color = switch ($grp.Name) {
        $SEV_CRITICAL { 'Red'     }
        $SEV_HIGH     { 'DarkRed' }
        $SEV_MEDIUM   { 'Yellow'  }
        $SEV_LOW      { 'Cyan'    }
        default       { 'Gray'    }
    }
    Write-Host "    $($grp.Name.PadRight(10)) : $($grp.Count)" -ForegroundColor $color
}

# ---- CSV export ----
if ($CsvPath) {
    $script:Findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n  CSV exported to: $CsvPath" -ForegroundColor Cyan
}

# ---- HTML report ----
$severityStyle = @{
    $SEV_CRITICAL = 'background:#c0392b;color:#fff;font-weight:bold'
    $SEV_HIGH     = 'background:#e67e22;color:#fff;font-weight:bold'
    $SEV_MEDIUM   = 'background:#f1c40f;color:#333'
    $SEV_LOW      = 'background:#3498db;color:#fff'
    $SEV_INFO     = 'background:#95a5a6;color:#fff'
}

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

$rows = $script:Findings | ForEach-Object {
    $style = if ($severityStyle.ContainsKey($_.Severity)) { $severityStyle[$_.Severity] } else { '' }
    "<tr>
      <td style='$style;padding:4px 8px'>$($_.Severity)</td>
      <td style='padding:4px 8px'>$($_.Category)</td>
      <td style='padding:4px 8px'>$([System.Web.HttpUtility]::HtmlEncode($_.Target))</td>
      <td style='padding:4px 8px;font-weight:bold'>$([System.Web.HttpUtility]::HtmlEncode($_.Title))</td>
      <td style='padding:4px 8px;font-size:0.9em;color:#555'>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td>
    </tr>"
}

$templateRows = $allTemplates | Where-Object { $_.Published } | ForEach-Object {
    "<tr>
      <td style='padding:4px 8px'>$([System.Web.HttpUtility]::HtmlEncode($_.Name))</td>
      <td style='padding:4px 8px'>$($_.SchemaVersion)</td>
      <td style='padding:4px 8px'>$(if($_.EnrolleeSuppliesSubject){'<b style=color:red>YES</b>'}else{'No'})</td>
      <td style='padding:4px 8px'>$(if($_.RequiresApproval){'<span style=color:green>YES</span>'}else{'No'})</td>
      <td style='padding:4px 8px'>$(if($_.HasAnyPurpose){'<b style=color:red>YES</b>'}else{'No'})</td>
      <td style='padding:4px 8px'>$(if($_.HasClientAuth){'Yes'}else{'No'})</td>
      <td style='padding:4px 8px'>$($_.ValidityDays)d</td>
      <td style='padding:4px 8px;font-size:0.8em'>$([System.Web.HttpUtility]::HtmlEncode($_.EKUs))</td>
    </tr>"
}

$urlRows = $script:UrlResults | ForEach-Object {
    $bg = if ($_.Reachable) { '' } else { "background:#fdecea;" }
    "<tr>
      <td style='padding:4px 8px'>$([System.Web.HttpUtility]::HtmlEncode($_.CA))</td>
      <td style='padding:4px 8px'>$($_.Type)</td>
      <td style='padding:4px 8px;font-family:monospace;font-size:0.85em'>$([System.Web.HttpUtility]::HtmlEncode($_.Url))</td>
      <td style='${bg}padding:4px 8px;font-weight:bold'>$(if($_.Reachable){'<span style=color:green>OK</span>'}else{'<span style=color:red>FAIL</span>'})</td>
      <td style='padding:4px 8px;font-size:0.9em'>$([System.Web.HttpUtility]::HtmlEncode($_.Status))</td>
    </tr>"
}

$anomalyRows = $script:AnomalousIssuances | ForEach-Object {
    "<tr>
      <td style='padding:4px 8px'>$([System.Web.HttpUtility]::HtmlEncode($_.CA))</td>
      <td style='padding:4px 8px;font-weight:bold'>$([System.Web.HttpUtility]::HtmlEncode($_.Type))</td>
      <td style='padding:4px 8px;font-size:0.9em'>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td>
    </tr>"
}

$statsRows = $bySeverity | Sort-Object { @($SEV_CRITICAL,$SEV_HIGH,$SEV_MEDIUM,$SEV_LOW,$SEV_INFO).IndexOf($_.Name) } | ForEach-Object {
    $col = switch ($_.Name) { $SEV_CRITICAL {'#c0392b'} $SEV_HIGH {'#e67e22'} $SEV_MEDIUM {'#f1c40f'} $SEV_LOW {'#3498db'} default {'#95a5a6'} }
    "<tr><td style='background:$col;color:#fff;padding:4px 8px;font-weight:bold'>$($_.Name)</td><td style='padding:4px 8px;font-size:1.2em;font-weight:bold'>$($_.Count)</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CA Health Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
<style>
  body  { font-family: Segoe UI, Arial, sans-serif; margin: 30px; background:#f5f5f5; color:#222; }
  h1    { color:#2c3e50; border-bottom:3px solid #2980b9; padding-bottom:10px; }
  h2    { color:#2980b9; margin-top:30px; }
  table { border-collapse:collapse; width:100%; background:#fff;
          box-shadow:0 1px 3px rgba(0,0,0,0.1); margin-bottom:20px; }
  th    { background:#2c3e50; color:#fff; padding:8px 12px; text-align:left; }
  tr:nth-child(even) td { background:#f9f9f9; }
  .meta { background:#2980b9; color:#fff; border-radius:4px; padding:10px 16px; margin-bottom:20px; font-size:0.95em; }
</style>
</head>
<body>
<h1>Windows CA Health &amp; Security Report</h1>
<div class="meta">
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  &nbsp;|&nbsp; Domain: $domainName
  &nbsp;|&nbsp; Enterprise CAs: $($enterpriseCAs.Count)
  &nbsp;|&nbsp; Root CAs: $($rootCAs.Count)
  &nbsp;|&nbsp; Templates analyzed: $($allTemplates.Count)
  &nbsp;|&nbsp; Audit window: $AuditDays days
  &nbsp;|&nbsp; Run by: $($env:USERDOMAIN)\$($env:USERNAME) on $($env:COMPUTERNAME)
</div>

<h2>Finding Counts</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
$($statsRows -join "`n")
</table>

<h2>All Findings</h2>
<table>
<tr><th>Severity</th><th>Category</th><th>Target</th><th>Title</th><th>Detail</th></tr>
$($rows -join "`n")
</table>

<h2>Published Template Details</h2>
<table>
<tr><th>Template Name</th><th>Schema</th><th>Enrollee Supplies Subject</th><th>Requires Approval</th><th>Any Purpose EKU</th><th>Client Auth EKU</th><th>Validity</th><th>EKUs</th></tr>
$($templateRows -join "`n")
</table>

<h2>CDP / AIA URL Reachability</h2>
<table>
<tr><th>CA</th><th>Type</th><th>URL</th><th>Reachable</th><th>Status</th></tr>
$($urlRows -join "`n")
</table>

<h2>Issued Certificate Anomalies</h2>
$(if ($SkipIssuedCertAudit) { '<p><em>Audit skipped (-SkipIssuedCertAudit).</em></p>' }
  elseif ($script:AnomalousIssuances.Count -eq 0) { '<p style="color:green;font-weight:bold">No anomalies detected in the audit window.</p>' }
  else {
"<table>
<tr><th>CA</th><th>Type</th><th>Detail</th></tr>
$($anomalyRows -join "`n")
</table>"
  })

<h2>Vulnerability Reference</h2>
<table>
<tr><th>ID</th><th>Name</th><th>Description</th></tr>
<tr><td>ESC1</td><td>Misconfigured Template SAN</td><td>Enrollee can supply Subject Alternative Name; no approval required; client auth EKU present. Allows impersonation of any domain user.</td></tr>
<tr><td>ESC2</td><td>Any Purpose / No EKU</td><td>Certificate can be used for any purpose including authentication.</td></tr>
<tr><td>ESC3</td><td>Enrollment Agent</td><td>Certificate Request Agent EKU allows on-behalf-of enrollment for other identities.</td></tr>
<tr><td>ESC4</td><td>Vulnerable Template ACL</td><td>Low-privilege user has write rights on a template object, allowing modification.</td></tr>
<tr><td>ESC6</td><td>EDITF_ATTRIBUTESUBJECTALTNAME2</td><td>CA flag that allows any request to embed arbitrary SANs regardless of template settings.</td></tr>
<tr><td>ESC7</td><td>Vulnerable CA ACL</td><td>Low-privilege user has ManageCA or ManageCertificates rights on the CA object.</td></tr>
<tr><td>ESC8</td><td>NTLM Relay to HTTP Enroll</td><td>HTTP (non-HTTPS) web enrollment endpoint can be abused via NTLM relay to obtain certificates.</td></tr>
<tr><td>ESC9</td><td>No Security Extension</td><td>CT_FLAG_NO_SECURITY_EXTENSION omits the security SID extension, breaking mapping protections.</td></tr>
<tr><td>—</td><td>Unauthorized NTAuth Cert</td><td>Unrecognized CA certificate in NTAuthCertificates can issue domain authentication credentials.</td></tr>
<tr><td>—</td><td>Bulk Issuance</td><td>Large number of certs issued in a short window may indicate automated attack or misconfiguration.</td></tr>
<tr><td>—</td><td>Privileged Account Cert</td><td>Certificate issued to a Domain/Enterprise Admin account warrants verification.</td></tr>
<tr><td>—</td><td>Off-Hours Issuance</td><td>Certificates issued late at night or on weekends may warrant investigation.</td></tr>
</table>

</body></html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
Write-Host "`n  HTML report saved to : $OutputPath" -ForegroundColor Green

#endregion
