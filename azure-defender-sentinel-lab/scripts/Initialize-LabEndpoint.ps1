<#
.SYNOPSIS
    Bootstraps SRV01 and the Windows 11 clients: telemetry settings, Sysmon, and
    optionally Microsoft Defender for Endpoint onboarding.

.DESCRIPTION
    Runs from the Azure Custom Script Extension after the machine has joined the
    domain.

    Defender for Endpoint onboarding differs by OS, and this is the part of the
    lab that cannot be fully automated from a template:

      Windows Server (SRV01, DC01)
        Covered by Defender for Servers. With the plan enabled, Defender for
        Cloud auto-provisions the MDE.Windows extension - nothing to do here.

      Windows 11 clients
        Not covered by Defender for Servers. They need a Defender for Endpoint
        or Defender for Business licence and an onboarding package that is
        generated per tenant. Download the local-script package from
        security.microsoft.com > Settings > Endpoints > Onboarding, put it
        somewhere the VMs can read (a storage blob with a SAS token works), and
        pass the URI as -MdeOnboardingPackageUri.

    Without that URI the script skips onboarding and says so, rather than
    failing the deployment.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ScriptsBaseUri,

    [ValidateSet('Server', 'Client')]
    [string] $Role = 'Client',

    [ValidateSet('Audit', 'Block', 'Disabled')]
    [string] $AsrMode = 'Audit',

    [string] $MdeOnboardingPackageUri = ''
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LabRoot = 'C:\LabSetup'
$LogDir  = Join-Path $LabRoot 'Logs'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
Start-Transcript -Path (Join-Path $LogDir 'Initialize-LabEndpoint.log') -Append

function Get-LabScript {
    param([string] $Name)
    $dest = Join-Path $LabRoot $Name
    $uri  = ($ScriptsBaseUri.TrimEnd('/')) + '/' + $Name
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            Invoke-WebRequest -Uri $uri -OutFile $dest -UseBasicParsing -TimeoutSec 60
            return $dest
        } catch {
            Write-Warning "Attempt $attempt for $Name failed: $($_.Exception.Message)"
            Start-Sleep -Seconds ([Math]::Pow(2, $attempt))
        }
    }
    throw "Could not download $Name from $ScriptsBaseUri"
}

try {
    Write-Host "=== Lab endpoint bootstrap ($Role) on $env:COMPUTERNAME ==="

    $telemetryScript = Get-LabScript -Name 'Set-LabTelemetry.ps1'
    $sysmonScript    = Get-LabScript -Name 'Install-Sysmon.ps1'

    Write-Host '--- Audit policy, PowerShell logging, Defender settings ---'
    & $telemetryScript -Role $Role -AsrMode $AsrMode

    Write-Host '--- Sysmon ---'
    & $sysmonScript

    if ($Role -eq 'Client') {
        Write-Host '--- Client conveniences ---'
        # Domain Users can sign in over RDP through Bastion without being local admins.
        try {
            $rdpGroup = (Get-LocalGroup -SID 'S-1-5-32-555').Name
            Add-LocalGroupMember -Group $rdpGroup -Member "$env:USERDOMAIN\Domain Users" -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Could not add Domain Users to Remote Desktop Users: $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($MdeOnboardingPackageUri)) {
        Write-Host 'MDE onboarding package URI not supplied.'
        if ($Role -eq 'Server') {
            Write-Host 'Server role: Defender for Servers will auto-provision the MDE.Windows extension.'
        } else {
            Write-Warning 'Client role: this machine is NOT onboarded to Defender for Endpoint. See the README for the manual step.'
        }
    } else {
        Write-Host '--- Defender for Endpoint onboarding ---'
        $mdeDir = Join-Path $LabRoot 'MDE'
        New-Item -Path $mdeDir -ItemType Directory -Force | Out-Null
        $pkg = Join-Path $mdeDir 'onboarding.zip'

        Invoke-WebRequest -Uri $MdeOnboardingPackageUri -OutFile $pkg -UseBasicParsing -TimeoutSec 180
        Expand-Archive -Path $pkg -DestinationPath $mdeDir -Force

        $cmd = Get-ChildItem -Path $mdeDir -Filter '*OnboardingScript*.cmd' -Recurse | Select-Object -First 1
        if (-not $cmd) { throw 'No onboarding .cmd found inside the package.' }

        Write-Host "Running $($cmd.FullName)"
        $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$($cmd.FullName)`"" -Wait -PassThru -NoNewWindow
        Write-Host "Onboarding script exit code: $($proc.ExitCode)"

        $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        if ($sense) {
            Write-Host "Sense service status: $($sense.Status)"
        } else {
            Write-Warning 'Sense service not present - onboarding may not have completed.'
        }

        Remove-Item -Path $pkg -Force -ErrorAction SilentlyContinue
    }

    New-Item -Path (Join-Path $LabRoot 'endpoint-complete.marker') -ItemType File -Force | Out-Null
    Write-Host 'Endpoint bootstrap complete.'
    exit 0
}
catch {
    Write-Error "Endpoint bootstrap failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
}
finally {
    Stop-Transcript
}
