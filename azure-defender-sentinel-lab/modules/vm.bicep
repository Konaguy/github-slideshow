/*
  One Windows VM, wired for the lab:
    NIC -> Azure Monitor Agent -> DCR associations -> (optional) domain join
        -> (optional) Custom Script Extension -> auto-shutdown schedule

  Trusted Launch (Gen2 + vTPM + Secure Boot) is on for every VM: Windows 11
  requires it, and Server 2022 Azure Edition supports it.
*/

param location string
param tags object = {}

param vmName string
param vmSize string
param subnetId string

@secure()
param adminUsername string
@secure()
param adminPassword string

@description('Static private IP. Empty string = dynamic. The DC needs a static IP so the VNet can point DNS at it.')
param staticPrivateIp string = ''

@description('DNS servers to pin directly on this VM NIC. Members set this to the DC IP so domain join resolves the forest without waiting on VNet-level DNS propagation. Empty = inherit VNet DNS.')
param nicDnsServers array = []

@description('Guest patch mode. Windows Server supports AutomaticByPlatform; Windows 11 client images do not, so clients must use AutomaticByOS.')
@allowed([ 'AutomaticByPlatform', 'AutomaticByOS', 'Manual' ])
param patchMode string = 'AutomaticByPlatform'

param imagePublisher string
param imageOffer string
param imageSku string

@description('Windows_Server enables Hybrid Benefit; Windows_Client is required for Windows 11 client images.')
@allowed([ 'Windows_Server', 'Windows_Client', 'None' ])
param licenseType string = 'None'

param osDiskType string = 'StandardSSD_LRS'
param osDiskSizeGb int = 128

@description('Data Collection Rule resource IDs to associate with this VM.')
param dcrIds array = []

// --- Domain join -----------------------------------------------------------
param domainJoin bool = false
param domainName string = ''
param domainJoinUserUpn string = ''
@secure()
param domainJoinPassword string = ''
@description('Target OU distinguished name. Empty = default Computers container.')
param ouPath string = ''

// --- Custom Script Extension ----------------------------------------------
@description('Script file URIs for the Custom Script Extension. Empty = extension not deployed.')
param scriptFileUris array = []
@description('Command line to run. Secrets belong here, not in scriptFileUris - this field is protected.')
@secure()
param scriptCommand string = ''

// --- Defender for Endpoint -------------------------------------------------
@description('Deploy the MDE.Windows extension explicitly. Leave false to let Defender for Servers auto-provision it (server OS only).')
param deployMdeExtension bool = false

// --- Cost control ----------------------------------------------------------
param enableAutoShutdown bool = true
@description('24h local time, HHmm.')
param autoShutdownTime string = '1900'
param autoShutdownTimeZone string = 'UTC'

var computerName = toUpper(vmName)

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${vmName}-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: subnetId }
          privateIPAllocationMethod: empty(staticPrivateIp) ? 'Dynamic' : 'Static'
          privateIPAddress: empty(staticPrivateIp) ? null : staticPrivateIp
        }
      }
    ]
    dnsSettings: empty(nicDnsServers) ? null : { dnsServers: nicDnsServers }
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    licenseType: licenseType == 'None' ? null : licenseType
    storageProfile: {
      imageReference: {
        publisher: imagePublisher
        offer: imageOffer
        sku: imageSku
        version: 'latest'
      }
      osDisk: {
        name: '${vmName}-osdisk'
        createOption: 'FromImage'
        caching: 'ReadWrite'
        diskSizeGB: osDiskSizeGb
        managedDisk: { storageAccountType: osDiskType }
        deleteOption: 'Delete'
      }
    }
    osProfile: {
      computerName: computerName
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        enableAutomaticUpdates: true
        patchSettings: {
          patchMode: patchMode
          assessmentMode: 'ImageDefault'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [ { id: nic.id, properties: { deleteOption: 'Delete' } } ]
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: { secureBootEnabled: true, vTpmEnabled: true }
    }
    diagnosticsProfile: { bootDiagnostics: { enabled: true } }
  }
}

resource ama 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = {
  parent: vm
  name: 'AzureMonitorWindowsAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {}
  }
}

resource dcrAssociations 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = [for (dcrId, i) in dcrIds: {
  name: 'dcra-${i}'
  scope: vm
  properties: {
    description: 'Lab DCR association'
    dataCollectionRuleId: dcrId
  }
  dependsOn: [ ama ]
}]

resource domainJoinExt 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = if (domainJoin) {
  parent: vm
  name: 'JoinDomain'
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'JsonADDomainExtension'
    typeHandlerVersion: '1.3'
    autoUpgradeMinorVersion: true
    settings: {
      Name: domainName
      User: domainJoinUserUpn
      // 3 = JOIN_DOMAIN (1) + ACCT_CREATE (2); 32 = restart after join.
      Options: '35'
      OUPath: ouPath
      Restart: 'true'
    }
    protectedSettings: {
      Password: domainJoinPassword
    }
  }
  dependsOn: [ ama ]
}

resource customScript 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = if (!empty(scriptFileUris)) {
  parent: vm
  name: 'LabBootstrap'
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    settings: {
      fileUris: scriptFileUris
    }
    protectedSettings: {
      commandToExecute: scriptCommand
    }
  }
  // Join the domain first so the bootstrap script runs against the final identity.
  // ARM ignores a dependency on a resource whose condition evaluated false, so
  // listing domainJoinExt here is safe on the DC, which never domain joins.
  dependsOn: [ ama, domainJoinExt ]
}

resource mde 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = if (deployMdeExtension) {
  parent: vm
  name: 'MDE.Windows'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.AzureDefenderForServers'
    type: 'MDE.Windows'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    settings: {
      azureResourceId: vm.id
      vNextEnabled: 'true'
      forceReOnboarding: false
      autoUpdate: true
    }
  }
  dependsOn: [ ama ]
}

resource shutdownSchedule 'Microsoft.DevTestLab/schedules@2018-09-15' = if (enableAutoShutdown) {
  name: 'shutdown-computevm-${vmName}'
  location: location
  tags: tags
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: autoShutdownTime }
    timeZoneId: autoShutdownTimeZone
    notificationSettings: { status: 'Disabled', timeInMinutes: 30 }
    targetResourceId: vm.id
  }
}

output vmId string = vm.id
output vmName string = vm.name
output privateIp string = nic.properties.ipConfigurations[0].properties.privateIPAddress
output principalId string = vm.identity.principalId
