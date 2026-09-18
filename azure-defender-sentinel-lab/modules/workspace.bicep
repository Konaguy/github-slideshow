/*
  Log Analytics workspace + Microsoft Sentinel onboarding.
*/

param location string
param prefix string
param tags object = {}

@description('Retention in days. 31 days and under is included in the workspace price.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 30

@description('Hard daily ingestion cap in GB. Protects a lab from a runaway bill. -1 = uncapped.')
param dailyQuotaGb int = 5

var workspaceName = '${prefix}-law'

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: json(string(dailyQuotaGb))
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Turns the workspace into a Microsoft Sentinel workspace.
resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: law
  name: 'default'
  properties: {}
}

output workspaceResourceId string = law.id
output workspaceName string = law.name
output workspaceCustomerId string = law.properties.customerId
