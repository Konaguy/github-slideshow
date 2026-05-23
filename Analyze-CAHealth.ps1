#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Server Certificate Authority Health and Security Analysis

.DESCRIPTION
    Analyzes PKI infrastructure health and security posture including:
      - CA certificate expiration and key/algorithm strength
      - CRL and OCSP validity
      - Offline vs online CA hierarchy validation
      - Certificate template misconfigurations (ESC1-ESC8)
      - CA-level security flags and ACLs

    Must be run from a domain-joined machine. Read access to AD is sufficient
    for most checks; some CA-direct checks require the CA to be reachable.

.PARAMETER OutputPath
    Path for the HTML report. Defaults to the current directory.

.PARAMETER CsvPath
    Optional path to export all findings as a CSV file.

.PARAMETER SkipTemplateAcls
    Skip the slow per-template ACL check (ESC4). Useful for large environments.

.EXAMPLE
    .\Analyze-CAHealth.ps1
    .\Analyze-CAHealth.ps1 -OutputPath C:\Reports\PKI.html -CsvPath C:\Reports\findings.csv

.NOTES
    References:
      - "Certified Pre-Owned" (SpecterOps, 2021) - ESC1-ESC8 research
      - Microsoft PKI best practices: https://aka.ms/pki
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\CA_HealthReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [string]$CsvPath,
    [switch]$SkipTemplateAcls
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ---- Constants -------------------------------------------------------

# msPKI-Certificate-Name-Flag bits
$ENROLLEE_SUPPLIES_SUBJECT     = 0x00000001
$SUBJECT_ALT_NAME_2            = 0x00010000   # same bit used for V1 templates supplying SAN

# msPKI-Enrollment-Flag bits
$PEND_ALL_REQUESTS             = 0x00000002   # manager approval required
$NO_SECURITY_EXTENSION         = 0x00080000

# msPKI-RA-Signature: number of RA counter-signatures required
# msPKI-Private-Key-Flag bits
$REQUIRE_PRIVATE_KEY_ARCHIVAL  = 0x00000001
$EXPORTABLE_KEY                = 0x00000010   # not ideal but not critical alone

# Well-known EKU OIDs
$EKU_ANY_PURPOSE               = '2.5.29.37.0'
$EKU_CLIENT_AUTH               = '1.3.6.1.5.5.7.3.2'
$EKU_SERVER_AUTH               = '1.3.6.1.5.5.7.3.1'
$EKU_CERT_REQUEST_AGENT        = '1.3.6.1.4.1.311.20.2.1'
$EKU_SMART_CARD_LOGON          = '1.3.6.1.4.1.311.20.2.2'
$EKU_CODE_SIGNING              = '1.3.6.1.5.5.7.3.3'
$EKU_PKIX_TIMESTAMPING         = '1.3.6.1.5.5.7.3.8'

# CA flags (certutil -getreg CA\InterfaceFlags)
$IF_ATTRIBUTESUBJECTALTNAME2   = 0x00040000   # EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)

# Well-known low-privilege SIDs / group names to check for enrollment rights
$LOW_PRIV_TRUSTEES = @(
    'S-1-1-0',          # Everyone
    'S-1-5-11',         # Authenticated Users
    'S-1-5-7',          # Anonymous Logon
    'Domain Users',
    'Domain Computers'
)

# Severity levels
$SEV_CRITICAL = 'CRITICAL'
$SEV_HIGH     = 'HIGH'
$SEV_MEDIUM   = 'MEDIUM'
$SEV_LOW      = 'LOW'
$SEV_INFO     = 'INFO'

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
        $SEV_CRITICAL { 'Red'    }
        $SEV_HIGH     { 'DarkRed'}
        $SEV_MEDIUM   { 'Yellow' }
        $SEV_LOW      { 'Cyan'   }
        default       { 'Gray'   }
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

function Get-DomainNetBIOS {
    try {
        $root = [ADSI]'LDAP://RootDSE'
        $dn   = $root.defaultNamingContext.ToString()
        # Convert DC=contoso,DC=com -> CONTOSO
        return ($dn -replace 'DC=','' -split ',' | Select-Object -First 1).ToUpper()
    } catch { return $env:USERDOMAIN }
}

function Expand-FileTimeToDateTime {
    param([object]$Value)
    # AD stores some intervals as negative 100-ns ticks (FILETIME)
    try {
        if ($Value -is [System.DirectoryServices.PropertyValueCollection]) {
            $Value = $Value.Value
        }
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
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$BaseDN")
        $searcher.Filter     = $Filter
        $searcher.SearchScope = $Scope
        $searcher.PageSize   = 500
        if ($Properties) { $Properties | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) } }
        return $searcher.FindAll()
    } catch {
        Write-Warning "AD search failed under $BaseDN — $($_.Exception.Message)"
        return @()
    }
}

function Get-TrusteeNames {
    # Returns display names for SID-based principals
    param([System.Security.AccessControl.AuthorizationRuleCollection]$Rules)
    $names = @()
    foreach ($rule in $Rules) {
        try { $names += $rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value }
        catch { $names += $rule.IdentityReference.Value }
    }
    return $names
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

$pkiBase        = "CN=Public Key Services,CN=Services,$configRoot"
$enrollSvcBase  = "CN=Enrollment Services,$pkiBase"
$templateBase   = "CN=Certificate Templates,$pkiBase"
$aiaBase        = "CN=AIA,$pkiBase"
$cdpBase        = "CN=CDP,$pkiBase"
$ntAuthBase     = "CN=NTAuthCertificates,$pkiBase"

#endregion

#region ---- 2. Enumerate Enterprise CAs -------------------------------------

Write-Section "2. Enterprise CA Enumeration"

$enterpriseCAs = @()
$caResults = Search-ADObjects -BaseDN $enrollSvcBase `
    -Filter '(objectClass=pKIEnrollmentService)' `
    -Properties @('cn','cACertificate','dNSHostName','certificateTemplates',
                   'cACertificateDN','flags','msPKI-EnrollmentServers')

foreach ($r in $caResults) {
    $p    = $r.Properties
    $name = if ($p['cn'].Count)          { $p['cn'][0] }          else { 'Unknown' }
    $host = if ($p['dnsHostName'].Count)  { $p['dnsHostName'][0] } else { 'Unknown' }
    $rawCert = if ($p['caCertificate'].Count) { [byte[]]$p['caCertificate'][0] } else { $null }
    $templates = if ($p['certificateTemplates'].Count) { @($p['certificateTemplates']) } else { @() }

    $cert = if ($rawCert) { Get-CertExpiry $rawCert } else { $null }

    $caObj = [PSCustomObject]@{
        Name        = $name
        Host        = $host
        DN          = $r.Path -replace 'LDAP://',''
        Cert        = $cert
        Templates   = $templates
        Reachable   = $false
        Flags       = 0
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

        # Key size check
        if ($cert.PublicKey.Key.KeySize -lt 2048) {
            Add-Finding $SEV_CRITICAL 'CA-Certificate' $name `
                'Weak key size' "Key size $($cert.PublicKey.Key.KeySize)-bit is below 2048-bit minimum."
        } elseif ($cert.PublicKey.Key.KeySize -lt 4096) {
            Add-Finding $SEV_LOW 'CA-Certificate' $name `
                'Key size < 4096' "Consider upgrading to 4096-bit for long-lived CA certificates."
        }

        # Signature algorithm
        if ($cert.SignatureAlgorithm.FriendlyName -match 'sha1|md5|md2') {
            Add-Finding $SEV_HIGH 'CA-Certificate' $name `
                'Weak signature algorithm' "Algorithm: $($cert.SignatureAlgorithm.FriendlyName). SHA-1/MD5 are deprecated."
        }

        # Expiration thresholds
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

#region ---- 3. PKI Hierarchy / Offline Root CA check -------------------------

Write-Section "3. PKI Hierarchy & Offline Root CA"

# Root CAs are stored in CN=Certification Authorities,$pkiBase
$rootCAResults = Search-ADObjects -BaseDN "CN=Certification Authorities,$pkiBase" `
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

# A root CA present in Enrollment Services = it is online and issuing = BAD practice
foreach ($rca in $rootCAs) {
    $isOnlineIssuing = $enterpriseCAs | Where-Object { $_.Name -eq $rca.Name }
    if ($isOnlineIssuing) {
        Add-Finding $SEV_HIGH 'Hierarchy' $rca.Name `
            'Root CA appears to be online and issuing certificates' `
            'Best practice: Root CA should be offline. Issue certs only via subordinate CAs.'
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

# Subordinate CA check: should chain to a root, not self-signed
foreach ($ca in $enterpriseCAs) {
    if ($ca.Cert) {
        $isSelfSigned = $ca.Cert.Subject -eq $ca.Cert.Issuer
        if ($isSelfSigned) {
            $isRoot = $rootCAs | Where-Object { $_.Name -eq $ca.Name }
            if (-not $isRoot) {
                Add-Finding $SEV_HIGH 'Hierarchy' $ca.Name `
                    'Issuing CA certificate appears self-signed but is not a known Root CA' `
                    'Verify certificate chain integrity.'
            }
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

# Check each CA's CRL via certutil where possible
# Also check CDP containers in AD
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

# Check AIA for OCSP entries
$aiaResults = Search-ADObjects -BaseDN $aiaBase `
    -Filter '(objectClass=certificationAuthority)' `
    -Properties @('cn','cACertificate')
Write-Host "  AIA entries found: $(@($aiaResults).Count)"

#endregion

#region ---- 5. Certificate Template Security ---------------------------------

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
    $p         = $r.Properties
    $tName     = if ($p['cn'].Count)          { $p['cn'][0] }          else { 'Unknown' }
    $dispName  = if ($p['displayName'].Count) { $p['displayName'][0] } else { $tName }
    $schemaVer = if ($p['msPKI-Template-Schema-Version'].Count) { [int]$p['msPKI-Template-Schema-Version'][0] } else { 1 }
    $isPublished = $publishedNames -contains $tName

    # Raw flag values
    $nameFlag    = if ($p['msPKI-Certificate-Name-Flag'].Count)  { [int]$p['msPKI-Certificate-Name-Flag'][0] }  else { 0 }
    $enrollFlag  = if ($p['msPKI-Enrollment-Flag'].Count)        { [int]$p['msPKI-Enrollment-Flag'][0] }        else { 0 }
    $raSig       = if ($p['msPKI-RA-Signature'].Count)           { [int]$p['msPKI-RA-Signature'][0] }           else { 0 }
    $pkiFlag     = if ($p['msPKI-Private-Key-Flag'].Count)       { [int]$p['msPKI-Private-Key-Flag'][0] }       else { 0 }

    # EKU list (pKIExtendedKeyUsage or msPKI-Certificate-Application-Policy)
    $ekus = @()
    if ($p['pKIExtendedKeyUsage'].Count -gt 0) {
        $ekus = @($p['pKIExtendedKeyUsage'])
    } elseif ($p['msPKI-Certificate-Application-Policy'].Count -gt 0) {
        $ekus = @($p['msPKI-Certificate-Application-Policy'])
    }

    # Derived flags
    $enrolleeSuppliesSubject = ($nameFlag  -band $ENROLLEE_SUPPLIES_SUBJECT) -ne 0
    $requiresApproval        = ($enrollFlag -band $PEND_ALL_REQUESTS)         -ne 0
    $noSecurityExtension     = ($enrollFlag -band $NO_SECURITY_EXTENSION)     -ne 0
    $hasAnyPurpose           = $ekus -contains $EKU_ANY_PURPOSE
    $hasClientAuth           = $ekus -contains $EKU_CLIENT_AUTH
    $hasRAAgent              = $ekus -contains $EKU_CERT_REQUEST_AGENT
    $noEku                   = $ekus.Count -eq 0
    $isExportable            = ($pkiFlag -band $EXPORTABLE_KEY)               -ne 0

    # Validity period from pKIExpirationPeriod (stored as negative FILETIME interval)
    $validityDays = 0
    if ($p['pKIExpirationPeriod'].Count) {
        try {
            $raw  = [byte[]]$p['pKIExpirationPeriod'][0]
            $val  = [BitConverter]::ToInt64($raw, 0)
            $validityDays = [Math]::Abs($val / 864000000000)  # 100-ns ticks per day
        } catch { }
    }

    Write-Host "  Template: $tName  (schema v$schemaVer, $(if($isPublished){'PUBLISHED'}else{'not published'}))"

    # ---- ESC1: Enrollee supplies subject + client auth/any + low priv enroll ----
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

    # ---- ESC2: Any Purpose EKU or no EKU at all ----
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

    # ---- ESC3: Certificate Request Agent template ----
    if ($hasRAAgent -and $isPublished -and (-not $requiresApproval)) {
        Add-Finding $SEV_HIGH 'Template-ESC3' $tName `
            'ESC3: Certificate Request Agent EKU present' `
            'Allows on-behalf-of enrollment to impersonate other users.'
    }

    # ---- ESC4: Template ACL (checked later if -SkipTemplateAcls not set) ----
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
                            "ESC4: Low-privilege principal has write rights on template" `
                            "Principal: $principal  Rights: $rights"
                    }
                }
            }
        } catch {
            Write-Warning "  Could not read ACL for template $tName : $($_.Exception.Message)"
        }
    }

    # ---- Excessive validity period ----
    if ($validityDays -gt 3650 -and $isPublished) {   # > 10 years
        Add-Finding $SEV_MEDIUM 'Template-Validity' $tName `
            'Template validity period exceeds 10 years' `
            "Validity: $([int]$validityDays) days. Long-lived certificates extend the window of compromise."
    } elseif ($validityDays -gt 1825 -and $isPublished) {   # > 5 years
        Add-Finding $SEV_LOW 'Template-Validity' $tName `
            'Template validity period exceeds 5 years' `
            "Validity: $([int]$validityDays) days."
    }

    # ---- Exportable private key ----
    if ($isExportable -and $isPublished) {
        Add-Finding $SEV_LOW 'Template-Key' $tName `
            'Template allows exportable private keys' `
            'Allows key material to be exported and potentially exfiltrated.'
    }

    # ---- No security extension ----
    if ($noSecurityExtension -and $isPublished) {
        Add-Finding $SEV_MEDIUM 'Template-ESC9' $tName `
            'Template has CT_FLAG_NO_SECURITY_EXTENSION set' `
            'ESC9/ESC10 risk: szOID_NTDS_CA_SECURITY_EXT not included in issued certificates.'
    }

    # ---- Manager approval bypass check ----
    if ($requiresApproval) {
        Add-Finding $SEV_INFO 'Template-Approval' $tName `
            'Manager approval required (mitigates some ESC risks)' ''
    }

    # ---- V1 template (no security features) ----
    if ($schemaVer -eq 1 -and $isPublished) {
        Add-Finding $SEV_LOW 'Template-Schema' $tName `
            'V1 template schema (lacks V2/V3 security controls)' `
            'Consider migrating to V2 or V3 template schema for enhanced security.'
    }

    $allTemplates += [PSCustomObject]@{
        Name                   = $tName
        DisplayName            = $dispName
        Published              = $isPublished
        SchemaVersion          = $schemaVer
        EKUs                   = ($ekus -join '; ')
        EnrolleeSuppliesSubject= $enrolleeSuppliesSubject
        RequiresApproval       = $requiresApproval
        HasAnyPurpose          = $hasAnyPurpose
        HasClientAuth          = $hasClientAuth
        HasRAAgent             = $hasRAAgent
        ExportableKey          = $isExportable
        ValidityDays           = [int]$validityDays
    }
}

#endregion

#region ---- 6. CA-level security flags (ESC6, ESC7) -------------------------

Write-Section "6. CA-Level Security Configuration"

foreach ($ca in $enterpriseCAs) {
    Write-Host "  Checking CA: $($ca.Name) on $($ca.Host)"

    # Test CA reachability
    try {
        $testConn = Test-Connection -ComputerName $ca.Host -Count 1 -Quiet -ErrorAction Stop
        $ca.Reachable = $testConn
    } catch { $ca.Reachable = $false }

    if (-not $ca.Reachable) {
        Add-Finding $SEV_MEDIUM 'CA-Config' $ca.Name `
            'CA host not reachable (skipping live checks)' `
            "Host: $($ca.Host). Ensure the CA service is running."
        continue
    }

    # ---- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 ----
    # certutil -config "CAHost\CAName" -getreg policy\EditFlags
    try {
        $regOut = & certutil.exe -config "$($ca.Host)\$($ca.Name)" -getreg policy\EditFlags 2>&1
        $regStr = $regOut -join ' '
        if ($regStr -match 'EditFlags\s*=\s*(0x[0-9a-fA-F]+)') {
            $flags = [Convert]::ToInt32($matches[1], 16)
            if ($flags -band $IF_ATTRIBUTESUBJECTALTNAME2) {
                Add-Finding $SEV_CRITICAL 'CA-ESC6' $ca.Name `
                    'ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag is SET' `
                    'Any CSR can include an arbitrary SAN. This allows any low-priv user to enroll as any identity.'
            } else {
                Add-Finding $SEV_INFO 'CA-ESC6' $ca.Name 'EDITF_ATTRIBUTESUBJECTALTNAME2 is NOT set (good)' ''
            }
        }
    } catch {
        Add-Finding $SEV_LOW 'CA-Config' $ca.Name 'Could not read CA EditFlags via certutil' $_.Exception.Message
    }

    # ---- Audit settings ----
    try {
        $auditOut = & certutil.exe -config "$($ca.Host)\$($ca.Name)" -getreg CA\AuditFilter 2>&1
        $auditStr = $auditOut -join ' '
        if ($auditStr -match 'AuditFilter\s*=\s*(0x[0-9a-fA-F]+|\d+)') {
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

    # ---- ESC8: Web enrollment endpoint exposure ----
    $webEnrollUrl = "http://$($ca.Host)/certsrv/"
    try {
        $resp = Invoke-WebRequest -Uri $webEnrollUrl -UseDefaultCredentials -TimeoutSec 5 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            Add-Finding $SEV_HIGH 'CA-ESC8' $ca.Name `
                'ESC8: HTTP web enrollment endpoint is accessible' `
                "URL: $webEnrollUrl. If NTLM is enabled, this can be abused via relay attacks. Enforce HTTPS and consider disabling if unused."
        }
    } catch [System.Net.WebException] {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 401) {
            Add-Finding $SEV_MEDIUM 'CA-ESC8' $ca.Name `
                'ESC8: Web enrollment endpoint exists and requires auth (check HTTPS)' `
                "URL: $webEnrollUrl. Verify HTTPS is enforced and EPA/channel binding is enabled."
        }
    } catch {
        Add-Finding $SEV_INFO 'CA-ESC8' $ca.Name 'Web enrollment endpoint not reachable' $webEnrollUrl
    }

    # ---- ESC7: CA ACL check ----
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
                        "ESC7: Low-privilege principal has CA management rights" `
                        "Principal: $principal  Rights: $rights. Can approve pending requests or modify CA config."
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

try {
    $ntAuth = Get-ADObject -Path $ntAuthBase -Properties @('cACertificate')
    if ($ntAuth) {
        $certs = $ntAuth.Properties['cACertificate']
        Write-Host "  Certificates in NTAuth store: $($certs.Count)"
        foreach ($rawC in $certs) {
            $c = Get-CertExpiry ([byte[]]$rawC)
            if ($c) {
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

#region ---- 8. Summary & Report generation ----------------------------------

Write-Section "8. Summary"

$bySeverity = $script:Findings | Group-Object Severity
Write-Host ""
Write-Host "  Findings summary:" -ForegroundColor White
foreach ($grp in $bySeverity | Sort-Object { @($SEV_CRITICAL,$SEV_HIGH,$SEV_MEDIUM,$SEV_LOW,$SEV_INFO).IndexOf($_.Name) }) {
    $color = switch ($grp.Name) {
        $SEV_CRITICAL { 'Red'    }
        $SEV_HIGH     { 'DarkRed'}
        $SEV_MEDIUM   { 'Yellow' }
        $SEV_LOW      { 'Cyan'   }
        default       { 'Gray'   }
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

$statsRows = $bySeverity | Sort-Object { @($SEV_CRITICAL,$SEV_HIGH,$SEV_MEDIUM,$SEV_LOW,$SEV_INFO).IndexOf($_.Name) } | ForEach-Object {
    $col = switch ($_.Name) { $SEV_CRITICAL {'#c0392b'} $SEV_HIGH {'#e67e22'} $SEV_MEDIUM {'#f1c40f'} $SEV_LOW {'#3498db'} default {'#95a5a6'} }
    "<tr><td style='background:$col;color:#fff;padding:4px 8px;font-weight:bold'>$($_.Name)</td><td style='padding:4px 8px;font-size:1.2em;font-weight:bold'>$($_.Count)</td></tr>"
}

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

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
</table>

</body></html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
Write-Host "`n  HTML report saved to : $OutputPath" -ForegroundColor Green

#endregion
