<#
.SYNOPSIS
    Reports hybrid Entra join and MDM enrollment status on a client.

.DESCRIPTION
    Wraps 'dsregcmd /status' and surfaces the fields that matter. Run on any client
    (e.g. WIN11-01). After a successful hybrid join you want:
        AzureAdJoined : YES
        DomainJoined  : YES
    and, once auto-enrolled, an MDM URL / enrollment present.
#>
$ErrorActionPreference = 'Continue'
$raw = & dsregcmd /status
$want = 'AzureAdJoined|EnterpriseJoined|DomainJoined|TenantName|TenantId|DeviceId|MdmUrl|MdmEnrollmentUrl|DeviceCertificateValidity'
$raw | Select-String -Pattern $want | ForEach-Object { $_.Line.Trim() }
