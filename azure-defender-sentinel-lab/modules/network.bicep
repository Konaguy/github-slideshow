/*
  Lab network: VNet, subnets, NSG, NAT Gateway (outbound) and Azure Bastion (inbound).

  Deployed twice by main.bicep:
    pass 1 - dnsServers = []            (Azure-provided DNS, so the DC can reach the internet
                                         to pull its bootstrap script while it promotes)
    pass 2 - dnsServers = [ dcPrivateIp ] (after the DC is up, so members can find the domain)
  Re-deploying the same VNet with the full subnet list is idempotent.
*/

param location string
param prefix string
param tags object = {}

param addressSpace string = '10.10.0.0/16'
param labSubnetPrefix string = '10.10.10.0/24'
param bastionSubnetPrefix string = '10.10.250.0/26'

@description('Custom DNS servers for the VNet. Empty array = Azure-provided DNS.')
param dnsServers array = []

param enableBastion bool = true
param enableNatGateway bool = true

var vnetName = '${prefix}-vnet'
var nsgName = '${prefix}-lab-nsg'
var natName = '${prefix}-nat'
var bastionName = '${prefix}-bastion'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        // Bastion reaches the VMs on 3389 from its own subnet.
        name: 'Allow-Bastion-RDP-In'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: bastionSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: labSubnetPrefix
          destinationPortRanges: [ '3389', '22' ]
        }
      }
      {
        // AD replication, DNS, Kerberos, LDAP, SMB between lab machines.
        name: 'Allow-Intra-Lab'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: labSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: labSubnetPrefix
          destinationPortRange: '*'
        }
      }
      {
        name: 'Deny-Internet-Inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// Outbound. Default outbound access for new VNets was retired on 2025-09-30,
// so a NAT Gateway is REQUIRED for the VMs to reach Windows Update, the
// Custom Script Extension payloads, AMA ingestion and MDE onboarding.
// ---------------------------------------------------------------------------
resource natPip 'Microsoft.Network/publicIPAddresses@2023-11-01' = if (enableNatGateway) {
  name: '${natName}-pip'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    idleTimeoutInMinutes: 10
  }
}

resource natGateway 'Microsoft.Network/natGateways@2023-11-01' = if (enableNatGateway) {
  name: natName
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    idleTimeoutInMinutes: 10
    publicIpAddresses: [ { id: natPip.id } ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [ addressSpace ] }
    dhcpOptions: empty(dnsServers) ? null : { dnsServers: dnsServers }
    subnets: concat(
      [
        {
          name: 'snet-lab'
          properties: {
            addressPrefix: labSubnetPrefix
            networkSecurityGroup: { id: nsg.id }
            natGateway: enableNatGateway ? { id: natGateway.id } : null
            privateEndpointNetworkPolicies: 'Disabled'
          }
        }
      ],
      enableBastion ? [
        {
          // Name is fixed by Azure. Basic SKU Bastion needs /26 or larger.
          name: 'AzureBastionSubnet'
          properties: { addressPrefix: bastionSubnetPrefix }
        }
      ] : []
    )
  }
}

resource bastionPip 'Microsoft.Network/publicIPAddresses@2023-11-01' = if (enableBastion) {
  name: '${bastionName}-pip'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource bastion 'Microsoft.Network/bastionHosts@2023-11-01' = if (enableBastion) {
  name: bastionName
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: {
    ipConfigurations: [
      {
        name: 'ipconf'
        properties: {
          subnet: { id: '${vnet.id}/subnets/AzureBastionSubnet' }
          publicIPAddress: { id: bastionPip.id }
        }
      }
    ]
  }
}

output vnetId string = vnet.id
output vnetName string = vnet.name
output labSubnetId string = '${vnet.id}/subnets/snet-lab'
