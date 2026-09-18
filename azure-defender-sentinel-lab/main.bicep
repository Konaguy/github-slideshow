/*
===============================================================================
  Microsoft Defender + Microsoft Sentinel lab
===============================================================================
  Builds, in one subscription-scope deployment:

    Resource group
    VNet 10.10.0.0/16   snet-lab 10.10.10.0/24, AzureBastionSubnet 10.10.250.0/26
    NAT Gateway         outbound internet (mandatory since default outbound
                        access was retired on 2025-09-30)
    Azure Bastion       inbound RDP, no public IPs on any VM
    Log Analytics + Microsoft Sentinel
    2 Data Collection Rules   Security Events, and Sysmon/PowerShell/Defender
    DC01     Windows Server 2022, new AD forest, DNS, static 10.10.10.4
    SRV01    Windows Server 2022, domain joined, file/app server
    WIN11-01..03  Windows 11 Enterprise, domain joined
    Defender for Cloud plans + Sentinel connectors + 4 starter analytics rules

  Deploy:
    az deployment sub create \
      --name mdlab \
      --location eastus \
      --template-file main.bicep \
      --parameters main.bicepparam

  Order matters and is enforced with dependsOn: the VNet is deployed once with
  Azure DNS so DC01 can reach the internet while it promotes, then a second time
  with DNS pointed at DC01 so the member machines can find the domain.
===============================================================================
*/

targetScope = 'subscription'

// --- Naming and placement ---------------------------------------------------
@description('Short prefix for every resource name. Lowercase letters and digits.')
@minLength(3)
@maxLength(10)
param prefix string = 'mdlab'

@description('Azure region for the lab.')
param location string = 'eastus'

@description('Resource group name. Everything except the Defender plans lands here.')
param resourceGroupName string = 'rg-${prefix}'

param tags object = {
  environment: 'lab'
  purpose: 'defender-sentinel-lab'
  autoDelete: 'true'
}

// --- Credentials ------------------------------------------------------------
@description('Local admin on every VM, and the first Domain Admin. Must not be "administrator", "admin", "root" etc.')
@minLength(5)
@maxLength(20)
param adminUsername string = 'labadmin'

@description('Password for the admin account. 12-123 chars, 3 of 4 complexity classes.')
@secure()
@minLength(12)
param adminPassword string

@description('Directory Services Restore Mode password for the forest. Use a different value from adminPassword.')
@secure()
@minLength(12)
param dsrmPassword string

// --- Domain -----------------------------------------------------------------
@description('AD DS forest root FQDN.')
param domainName string = 'lab.local'

@description('NetBIOS name. 15 chars max, uppercase.')
@maxLength(15)
param domainNetbiosName string = 'LAB'

@description('OU distinguished name to join member machines into. Empty = default Computers container.')
param computerOuPath string = ''

// --- Sizing -----------------------------------------------------------------
@description('VM size for DC01 and SRV01. Must support Trusted Launch.')
param serverVmSize string = 'Standard_D2s_v5'

@description('VM size for the Windows 11 clients. Must support Trusted Launch.')
param clientVmSize string = 'Standard_D2s_v5'

@description('How many Windows 11 clients to build.')
@minValue(1)
@maxValue(10)
param clientCount int = 3

@description('Windows 11 image SKU. Client images require Windows_Client licence attestation (see README).')
param windows11Sku string = 'win11-24h2-ent'

@description('Windows Server image SKU.')
param windowsServerSku string = '2022-datacenter-azure-edition'

// --- Networking -------------------------------------------------------------
param addressSpace string = '10.10.0.0/16'
param labSubnetPrefix string = '10.10.10.0/24'
param bastionSubnetPrefix string = '10.10.250.0/26'

@description('Static private IP for DC01. Must sit inside labSubnetPrefix and above the four addresses Azure reserves.')
param dcPrivateIp string = '10.10.10.4'

@description('Deploy Azure Bastion. Basic SKU is roughly $0.19/hour - delete the lab when idle.')
param enableBastion bool = true

// --- Monitoring and security ------------------------------------------------
@minValue(30)
@maxValue(730)
param logRetentionInDays int = 30

@description('Daily ingestion cap in GB. Keeps a misbehaving lab off your bill.')
param dailyQuotaGb int = 5

@description('Defender for Servers tier. P2 bills per protected server - see README cost notes.')
@allowed([ 'Free', 'P1', 'P2' ])
param defenderForServersPlan string = 'P2'

param enableDefenderCspm bool = false
param enableAncillaryDefenderPlans bool = false

@description('Connect Defender for Cloud alerts to Sentinel.')
param deployDefenderForCloudConnector bool = true

@description('Connect Defender XDR incidents to Sentinel. The XDR connector is not reliably deployable via ARM (Sentinel rejects the kind), so it is off by default - connect it from the portal in two clicks (see README). Flip to true only if you want to attempt the ARM path.')
param deployDefenderXdrConnector bool = false

@description('Deploy the starter analytics rules.')
param deployAnalyticsRules bool = true

// --- Bootstrap scripts ------------------------------------------------------
@description('Base URI the Custom Script Extension pulls the PowerShell bootstrap scripts from. Must end with a slash and be reachable from the VMs.')
param scriptsBaseUri string = 'https://raw.githubusercontent.com/konaguy/github-slideshow/refs/heads/claude/exciting-curie-806ybx/azure-defender-sentinel-lab/scripts/'

// --- Cost control -----------------------------------------------------------
param enableAutoShutdown bool = true
@description('Daily auto-shutdown time, HHmm, in autoShutdownTimeZone.')
param autoShutdownTime string = '1900'
param autoShutdownTimeZone string = 'UTC'

// ===========================================================================

var dcName = 'DC01'
var srvName = 'SRV01'
var clientNames = [for i in range(0, clientCount): 'WIN11-${padLeft(i + 1, 2, '0')}']
var domainJoinUpn = '${adminUsername}@${domainName}'

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

// --- Pass 1: network with Azure-provided DNS -------------------------------
module networkInitial 'modules/network.bicep' = {
  name: 'network-initial'
  scope: rg
  params: {
    location: location
    prefix: prefix
    tags: tags
    addressSpace: addressSpace
    labSubnetPrefix: labSubnetPrefix
    bastionSubnetPrefix: bastionSubnetPrefix
    dnsServers: []
    enableBastion: enableBastion
    enableNatGateway: true
  }
}

module workspace 'modules/workspace.bicep' = {
  name: 'workspace'
  scope: rg
  params: {
    location: location
    prefix: prefix
    tags: tags
    retentionInDays: logRetentionInDays
    dailyQuotaGb: dailyQuotaGb
  }
}

module dataCollection 'modules/dataCollection.bicep' = {
  name: 'data-collection'
  scope: rg
  params: {
    location: location
    prefix: prefix
    tags: tags
    workspaceResourceId: workspace.outputs.workspaceResourceId
  }
}

// --- Domain controller ------------------------------------------------------
module dc 'modules/vm.bicep' = {
  name: 'vm-${toLower(dcName)}'
  scope: rg
  params: {
    location: location
    tags: tags
    vmName: dcName
    vmSize: serverVmSize
    subnetId: networkInitial.outputs.labSubnetId
    staticPrivateIp: dcPrivateIp
    adminUsername: adminUsername
    adminPassword: adminPassword
    imagePublisher: 'MicrosoftWindowsServer'
    imageOffer: 'WindowsServer'
    imageSku: windowsServerSku
    licenseType: 'Windows_Server'
    dcrIds: dataCollection.outputs.dcrIds
    domainJoin: false
    scriptFileUris: [
      '${scriptsBaseUri}Initialize-DomainController.ps1'
    ]
    scriptCommand: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\\Initialize-DomainController.ps1 -DomainName "${domainName}" -NetbiosName "${domainNetbiosName}" -SafeModePassword "${dsrmPassword}" -ScriptsBaseUri "${scriptsBaseUri}"'
    enableAutoShutdown: enableAutoShutdown
    autoShutdownTime: autoShutdownTime
    autoShutdownTimeZone: autoShutdownTimeZone
  }
}

// --- Gate: wait for the forest to actually be serving ----------------------
module dcReady 'modules/dcReadyGate.bicep' = {
  name: 'dc-ready-gate'
  scope: rg
  params: {
    location: location
    dcVmName: dcName
  }
  dependsOn: [ dc ]
}

// --- Pass 2: same VNet, DNS now pointed at the DC --------------------------
module networkWithDomainDns 'modules/network.bicep' = {
  name: 'network-domain-dns'
  scope: rg
  params: {
    location: location
    prefix: prefix
    tags: tags
    addressSpace: addressSpace
    labSubnetPrefix: labSubnetPrefix
    bastionSubnetPrefix: bastionSubnetPrefix
    dnsServers: [ dcPrivateIp ]
    enableBastion: enableBastion
    enableNatGateway: true
  }
  dependsOn: [ dcReady ]
}

// --- Member server ----------------------------------------------------------
module srv 'modules/vm.bicep' = {
  name: 'vm-${toLower(srvName)}'
  scope: rg
  params: {
    location: location
    tags: tags
    vmName: srvName
    vmSize: serverVmSize
    subnetId: networkWithDomainDns.outputs.labSubnetId
    adminUsername: adminUsername
    adminPassword: adminPassword
    imagePublisher: 'MicrosoftWindowsServer'
    imageOffer: 'WindowsServer'
    imageSku: windowsServerSku
    licenseType: 'Windows_Server'
    dcrIds: dataCollection.outputs.dcrIds
    domainJoin: true
    domainName: domainName
    domainJoinUserUpn: domainJoinUpn
    domainJoinPassword: adminPassword
    ouPath: computerOuPath
    scriptFileUris: [
      '${scriptsBaseUri}Initialize-LabEndpoint.ps1'
    ]
    scriptCommand: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\\Initialize-LabEndpoint.ps1 -ScriptsBaseUri "${scriptsBaseUri}" -Role Server'
    enableAutoShutdown: enableAutoShutdown
    autoShutdownTime: autoShutdownTime
    autoShutdownTimeZone: autoShutdownTimeZone
  }
}

// --- Windows 11 clients -----------------------------------------------------
module clients 'modules/vm.bicep' = [for name in clientNames: {
  name: 'vm-${toLower(name)}'
  scope: rg
  params: {
    location: location
    tags: tags
    vmName: name
    vmSize: clientVmSize
    subnetId: networkWithDomainDns.outputs.labSubnetId
    adminUsername: adminUsername
    adminPassword: adminPassword
    imagePublisher: 'MicrosoftWindowsDesktop'
    imageOffer: 'windows-11'
    imageSku: windows11Sku
    licenseType: 'Windows_Client'
    dcrIds: dataCollection.outputs.dcrIds
    domainJoin: true
    domainName: domainName
    domainJoinUserUpn: domainJoinUpn
    domainJoinPassword: adminPassword
    ouPath: computerOuPath
    scriptFileUris: [
      '${scriptsBaseUri}Initialize-LabEndpoint.ps1'
    ]
    scriptCommand: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\\Initialize-LabEndpoint.ps1 -ScriptsBaseUri "${scriptsBaseUri}" -Role Client'
    enableAutoShutdown: enableAutoShutdown
    autoShutdownTime: autoShutdownTime
    autoShutdownTimeZone: autoShutdownTimeZone
  }
}]

// --- Security posture -------------------------------------------------------
module defenderPlans 'modules/defenderPlans.bicep' = {
  name: 'defender-plans'
  params: {
    serversPlan: defenderForServersPlan
    enableDefenderCspm: enableDefenderCspm
    enableAncillaryPlans: enableAncillaryDefenderPlans
  }
}

module connectors 'modules/sentinelConnectors.bicep' = {
  name: 'sentinel-connectors'
  scope: rg
  params: {
    workspaceName: workspace.outputs.workspaceName
    deployDefenderForCloudConnector: deployDefenderForCloudConnector
    deployDefenderXdrConnector: deployDefenderXdrConnector
  }
  dependsOn: [ defenderPlans ]
}

module rules 'modules/analyticsRules.bicep' = if (deployAnalyticsRules) {
  name: 'sentinel-rules'
  scope: rg
  params: {
    workspaceName: workspace.outputs.workspaceName
  }
  dependsOn: [ connectors ]
}

// --- Outputs ----------------------------------------------------------------
output resourceGroup string = rg.name
output workspaceName string = workspace.outputs.workspaceName
output workspaceCustomerId string = workspace.outputs.workspaceCustomerId
output domainFqdn string = domainName
output domainControllerIp string = dcPrivateIp
output bastionName string = enableBastion ? '${prefix}-bastion' : 'not deployed'
output vmNames array = concat([ dcName, srvName ], clientNames)
output connectHint string = enableBastion
  ? 'Portal > ${resourceGroupName} > DC01 > Connect > Bastion, sign in as ${domainNetbiosName}\\${adminUsername}'
  : 'Bastion disabled - no inbound path is deployed.'
