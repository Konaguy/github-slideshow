/*
  Blocks the deployment until the domain controller is actually serving the
  directory.

  Initialize-DomainController.ps1 has to reboot to finish promotion, and a
  Custom Script Extension cannot survive a reboot - it reports success and the
  machine goes down. Without this gate ARM would race ahead and try to domain
  join SRV01 and the clients against a forest that is still building.

  A run command is a separate extension from the Custom Script Extension, so it
  can coexist on the same VM. It is queued while the DC reboots and runs as soon
  as the guest agent comes back, polling for the marker file that
  Complete-DomainController.ps1 drops when seeding has finished.
*/

param location string
param dcVmName string

@description('How long to wait for the forest before failing the deployment.')
param timeoutMinutes int = 45

resource dcVm 'Microsoft.Compute/virtualMachines@2024-07-01' existing = {
  name: dcVmName
}

resource waitForDomain 'Microsoft.Compute/virtualMachines/runCommands@2024-07-01' = {
  parent: dcVm
  name: 'WaitForDomainReady'
  location: location
  properties: {
    asyncExecution: false
    timeoutInSeconds: timeoutMinutes * 60
    parameters: [
      { name: 'TimeoutMinutes', value: string(timeoutMinutes) }
    ]
    source: {
      script: '''
param([string] $TimeoutMinutes = '45')

$ErrorActionPreference = 'Continue'
$deadline = (Get-Date).AddMinutes([int] $TimeoutMinutes)

while ((Get-Date) -lt $deadline) {
    if (Test-Path 'C:\LabSetup\dc-complete.marker') {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $domain = Get-ADDomain -ErrorAction Stop
            $dc = Get-ADDomainController -Discover -Service ADWS, KDC -ErrorAction Stop
            Write-Output "Domain $($domain.DNSRoot) is ready on $($dc.HostName)."
            exit 0
        } catch {
            Write-Output "Marker present but directory not answering yet: $($_.Exception.Message)"
        }
    } else {
        Write-Output 'Waiting for promotion and seeding to finish...'
    }
    Start-Sleep -Seconds 30
}

Write-Error "Domain controller was not ready within $TimeoutMinutes minutes. Check C:\LabSetup\Logs on the DC."
exit 1
'''
    }
  }
}

output dcReady bool = true
