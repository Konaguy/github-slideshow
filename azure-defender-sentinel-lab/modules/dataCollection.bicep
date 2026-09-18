/*
  Data Collection Rules for AMA.

  DCR 1 - Windows Security Events  -> SecurityEvent table (stream Microsoft-SecurityEvent)
  DCR 2 - Sysmon / PowerShell /
          Defender / Scheduled Task -> Event table        (stream Microsoft-Event)

  No Data Collection Endpoint is needed: both rules write to a Log Analytics
  workspace over the public ingestion endpoint.
*/

param location string
param prefix string
param tags object = {}
param workspaceResourceId string

resource dcrSecurityEvents 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${prefix}-dcr-securityevents'
  location: location
  tags: tags
  kind: 'Windows'
  properties: {
    description: 'Windows Security Events - Common set plus Kerberos ticket events for AD attack detection.'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityEvents'
          streams: [ 'Microsoft-SecurityEvent' ]
          xPathQueries: [
            // Common set: logon/logoff, account & group management, process creation, policy change.
            'Security!*[System[(EventID=1102 or EventID=4624 or EventID=4625 or EventID=4657 or EventID=4663 or EventID=4688 or EventID=4700 or EventID=4702 or EventID=4719 or EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4727 or EventID=4728 or EventID=4732 or EventID=4735 or EventID=4737 or EventID=4738 or EventID=4740 or EventID=4755 or EventID=4756 or EventID=4767 or EventID=4772 or EventID=4777 or EventID=4782 or EventID=4793 or EventID=4796 or EventID=4798 or EventID=4799 or EventID=4825 or EventID=4946 or EventID=4948 or EventID=4956 or EventID=5024 or EventID=5033 or EventID=8222)]]'
            // Kerberos: 4768 TGT, 4769 service ticket (Kerberoasting), 4771 pre-auth failure (AS-REP roasting).
            'Security!*[System[(EventID=4768 or EventID=4769 or EventID=4771 or EventID=4776)]]'
            // Directory service changes / replication (DCSync shows as 4662 on the DC).
            'Security!*[System[(EventID=4662 or EventID=5136 or EventID=5137 or EventID=5141)]]'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        { name: 'laDestination', workspaceResourceId: workspaceResourceId }
      ]
    }
    dataFlows: [
      { streams: [ 'Microsoft-SecurityEvent' ], destinations: [ 'laDestination' ] }
    ]
  }
}

resource dcrEndpointTelemetry 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${prefix}-dcr-endpoint'
  location: location
  tags: tags
  kind: 'Windows'
  properties: {
    description: 'Sysmon, PowerShell, Microsoft Defender Antivirus and Scheduled Task operational logs.'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'endpointTelemetry'
          streams: [ 'Microsoft-Event' ]
          xPathQueries: [
            'Microsoft-Windows-Sysmon/Operational!*'
            'Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4103 or EventID=4104)]]'
            'Windows PowerShell!*[System[(EventID=400 or EventID=800)]]'
            'Microsoft-Windows-Windows Defender/Operational!*[System[(EventID=1006 or EventID=1007 or EventID=1008 or EventID=1009 or EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=5001 or EventID=5007)]]'
            'Microsoft-Windows-TaskScheduler/Operational!*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201)]]'
            'System!*[System[(EventID=7045 or EventID=7040)]]'
            'Microsoft-Windows-WMI-Activity/Operational!*[System[(EventID=5857 or EventID=5860 or EventID=5861)]]'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        { name: 'laDestination', workspaceResourceId: workspaceResourceId }
      ]
    }
    dataFlows: [
      { streams: [ 'Microsoft-Event' ], destinations: [ 'laDestination' ] }
    ]
  }
}

output dcrIds array = [ dcrSecurityEvents.id, dcrEndpointTelemetry.id ]
