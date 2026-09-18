/*
  Microsoft Defender for Cloud plans. Subscription scope.

  COST: Defender for Servers Plan 2 bills per server per hour (~$15/server/month
  at list). Five lab VMs is roughly $75/month if you leave the plan on, and it
  bills on protected servers whether or not they are running. Turn the plan back
  to 'Free' when you are finished, or run teardown.sh.
*/

targetScope = 'subscription'

@description('Defender for Servers. P2 adds vulnerability assessment, agentless scanning, FIM and the MDE integration.')
@allowed([ 'Free', 'P1', 'P2' ])
param serversPlan string = 'P2'

@description('Defender CSPM. Foundational posture management is free; this is the paid tier.')
param enableDefenderCspm bool = false

@description('Defender for Storage / Key Vault / Resource Manager. Off by default - not needed for an endpoint lab.')
param enableAncillaryPlans bool = false

resource servers 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: serversPlan == 'Free' ? 'Free' : 'Standard'
    subPlan: serversPlan == 'Free' ? null : serversPlan
    extensions: serversPlan == 'P2' ? [
      {
        name: 'AgentlessVmScanning'
        isEnabled: 'True'
        additionalExtensionProperties: { ExclusionTags: '[]' }
      }
    ] : null
  }
}

// Streams Defender for Endpoint alerts into Defender for Cloud, which is what
// then feeds the Sentinel AzureSecurityCenter connector.
resource mdeIntegration 'Microsoft.Security/settings@2022-05-01' = {
  name: 'WDATP'
  kind: 'DataExportSettings'
  properties: {
    enabled: true
  }
}

resource mdeUnifiedSolution 'Microsoft.Security/settings@2022-05-01' = {
  name: 'WDATP_UNIFIED_SOLUTION'
  kind: 'DataExportSettings'
  properties: {
    enabled: true
  }
}

resource cspm 'Microsoft.Security/pricings@2024-01-01' = if (enableDefenderCspm) {
  name: 'CloudPosture'
  properties: { pricingTier: 'Standard' }
}

resource arm 'Microsoft.Security/pricings@2024-01-01' = if (enableAncillaryPlans) {
  name: 'Arm'
  properties: { pricingTier: 'Standard' }
}

resource keyVaults 'Microsoft.Security/pricings@2024-01-01' = if (enableAncillaryPlans) {
  name: 'KeyVaults'
  properties: { pricingTier: 'Standard', subPlan: 'PerKeyVault' }
}

resource storage 'Microsoft.Security/pricings@2024-01-01' = if (enableAncillaryPlans) {
  name: 'StorageAccounts'
  properties: { pricingTier: 'Standard', subPlan: 'DefenderForStorageV2' }
}
