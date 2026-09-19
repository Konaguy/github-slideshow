<#
.SYNOPSIS
    Creates and links a GPO that auto-enrolls hybrid Entra-joined devices into Intune.

.DESCRIPTION
    Equivalent of the ADMX policy "Enable automatic MDM enrollment using default
    Azure AD credentials". Once a device is hybrid Entra joined and this policy
    applies, the device enrolls into Intune on its own using the device credential.

    Run on DC01 (elevated). Requires the GroupPolicy module (installed with RSAT,
    which the lab DC bootstrap already added).

.EXAMPLE
    .\New-MdmAutoEnrollGpo.ps1
#>
[CmdletBinding()]
param(
    [string] $GpoName = 'Lab - Intune Auto Enrollment'
)

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy
Import-Module ActiveDirectory

$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    $gpo = New-GPO -Name $GpoName -Comment 'Auto-enroll hybrid Entra joined devices into Intune'
    Write-Output "Created GPO '$GpoName'."
} else {
    Write-Output "GPO '$GpoName' already exists; updating settings."
}

$key = 'HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\MDM'
# 1 = enabled. UseAADCredentialType 1 = User credential (standard for Intune auto-enroll).
Set-GPRegistryValue -Name $GpoName -Key $key -ValueName 'AutoEnrollMDM' -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $GpoName -Key $key -ValueName 'UseAADCredentialType' -Type DWord -Value 1 | Out-Null

$target = (Get-ADDomain).DistinguishedName
$existingLinks = (Get-GPInheritance -Target $target).GpoLinks.DisplayName
if ($existingLinks -notcontains $GpoName) {
    New-GPLink -Name $GpoName -Target $target -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
    Write-Output "Linked '$GpoName' to $target."
} else {
    Write-Output "'$GpoName' already linked to $target."
}
Write-Output "Done. Devices auto-enroll after hybrid join + 'gpupdate /force' + a sync."
