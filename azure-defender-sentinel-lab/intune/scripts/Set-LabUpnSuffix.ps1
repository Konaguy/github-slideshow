<#
.SYNOPSIS
    Adds a routable UPN suffix to the lab forest and repoints the lab users at it.

.DESCRIPTION
    Entra Connect will not sync users whose UPN suffix is non-routable (lab.local),
    and hybrid Entra join needs users to sign in with a UPN that matches a verified
    domain in the tenant. This adds the routable suffix to the AD forest and updates
    every user under OU=Lab to samAccountName@<suffix>.

    Run on DC01 (elevated). The suffix MUST already be a *verified* custom domain in
    your Entra tenant (e.g. 3ch3lon.com), or use <tenant>.onmicrosoft.com.

.EXAMPLE
    .\Set-LabUpnSuffix.ps1 -UpnSuffix 3ch3lon.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $UpnSuffix = '__UPN_SUFFIX__'
)

$ErrorActionPreference = 'Stop'
if ($UpnSuffix -eq '__UPN_SUFFIX__' -or [string]::IsNullOrWhiteSpace($UpnSuffix)) {
    throw 'Pass -UpnSuffix <routable-verified-domain>, e.g. 3ch3lon.com'
}

Import-Module ActiveDirectory

$forest = Get-ADForest
if ($forest.UPNSuffixes -notcontains $UpnSuffix) {
    Write-Output "Adding UPN suffix '$UpnSuffix' to forest $($forest.Name)."
    Set-ADForest -Identity $forest.Name -UPNSuffixes @{ Add = $UpnSuffix }
} else {
    Write-Output "UPN suffix '$UpnSuffix' already present."
}

$domain = Get-ADDomain
$labOu = "OU=Lab,$($domain.DistinguishedName)"

$users = Get-ADUser -Filter * -SearchBase $labOu -ErrorAction Stop
foreach ($u in $users) {
    $newUpn = "$($u.SamAccountName)@$UpnSuffix"
    if ($u.UserPrincipalName -ne $newUpn) {
        Set-ADUser -Identity $u -UserPrincipalName $newUpn
        Write-Output "  $($u.SamAccountName)  ->  $newUpn"
    }
}
Write-Output "Done. Users under $labOu now use @$UpnSuffix."
