/*
  Microsoft Sentinel data connectors.

  PERMISSIONS: the Defender XDR (MicrosoftThreatProtection) connector is a
  tenant-level integration. The deploying principal needs Security Administrator
  or Global Administrator in Entra ID, plus Sentinel Contributor on the
  workspace. If you deploy as a plain subscription Owner this resource fails -
  set deployDefenderXdrConnector=false and connect it from the portal instead.
*/

param workspaceName string

@description('Defender for Cloud alerts -> Sentinel.')
param deployDefenderForCloudConnector bool = true

@description('Defender XDR incidents -> Sentinel. Requires tenant-level rights (see above).')
param deployDefenderXdrConnector bool = true

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource defenderForCloud 'Microsoft.SecurityInsights/dataConnectors@2024-03-01' = if (deployDefenderForCloudConnector) {
  scope: law
  name: guid(law.id, 'AzureSecurityCenter')
  kind: 'AzureSecurityCenter'
  properties: {
    subscriptionId: subscription().subscriptionId
    dataTypes: {
      alerts: { state: 'Enabled' }
    }
  }
}

resource defenderXdr 'Microsoft.SecurityInsights/dataConnectors@2024-03-01' = if (deployDefenderXdrConnector) {
  scope: law
  name: guid(law.id, 'MicrosoftThreatProtection')
  // The ARM API accepts this kind at 2024-03-01; Bicep's type index for the
  // resource is stale and does not list it yet.
  #disable-next-line BCP036
  kind: 'MicrosoftThreatProtection'
  properties: {
    tenantId: subscription().tenantId
    dataTypes: {
      incidents: { state: 'Enabled' }
    }
  }
}
