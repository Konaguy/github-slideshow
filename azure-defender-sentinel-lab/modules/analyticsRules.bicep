/*
  Starter Sentinel analytics rules for the lab. These fire on telemetry the DCRs
  in this deployment actually collect, so you get incidents without waiting on
  content-hub installs.
*/

param workspaceName string

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// Turn Defender for Cloud alerts into Sentinel incidents.
resource mdcIncidents 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: law
  name: guid(law.id, 'mdc-incident-creation')
  kind: 'MicrosoftSecurityIncidentCreation'
  properties: {
    displayName: 'Create incidents from Microsoft Defender for Cloud alerts'
    enabled: true
    // The API expects the legacy product token; 'Microsoft Defender for Cloud' is rejected.
    productFilter: 'Azure Security Center'
    severitiesFilter: [ 'High', 'Medium', 'Low', 'Informational' ]
  }
}

resource kerberoasting 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: law
  name: guid(law.id, 'kerberoasting-rc4')
  kind: 'Scheduled'
  properties: {
    displayName: '[Lab] Possible Kerberoasting - RC4 service ticket burst'
    description: 'A single account requesting many RC4-encrypted (0x17) Kerberos service tickets is the classic Kerberoasting signature. Event 4769 from the domain controller.'
    severity: 'Medium'
    enabled: true
    query: '''
SecurityEvent
| where EventID == 4769
| extend TicketEncryptionType = columnifexists("TicketEncryptionType", "")
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| where TargetUserName !endswith "$"
| summarize
    ServiceCount = dcount(ServiceName),
    Services = make_set(ServiceName, 50),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated)
    by TargetUserName, IpAddress, Computer
| where ServiceCount >= 4
| extend AccountCustomEntity = TargetUserName, IPCustomEntity = IpAddress, HostCustomEntity = Computer
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1558' ]
    entityMappings: [
      { entityType: 'Account', fieldMappings: [ { identifier: 'Name', columnName: 'AccountCustomEntity' } ] }
      { entityType: 'IP', fieldMappings: [ { identifier: 'Address', columnName: 'IPCustomEntity' } ] }
      { entityType: 'Host', fieldMappings: [ { identifier: 'FullName', columnName: 'HostCustomEntity' } ] }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: { enabled: true, reopenClosedIncident: false, lookbackDuration: 'PT5H', matchingMethod: 'AllEntities' }
    }
  }
}

resource passwordSpray 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: law
  name: guid(law.id, 'password-spray')
  kind: 'Scheduled'
  properties: {
    displayName: '[Lab] Password spray - one source failing against many accounts'
    description: 'A single source host or IP producing 4625 failures against five or more distinct accounts in an hour.'
    severity: 'Medium'
    enabled: true
    query: '''
SecurityEvent
| where EventID == 4625
| where AccountType == "User"
| summarize
    AccountsTargeted = dcount(TargetUserName),
    Accounts = make_set(TargetUserName, 50),
    Attempts = count(),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated)
    by IpAddress, WorkstationName, Computer
| where AccountsTargeted >= 5
| extend IPCustomEntity = IpAddress, HostCustomEntity = Computer
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1110' ]
    entityMappings: [
      { entityType: 'IP', fieldMappings: [ { identifier: 'Address', columnName: 'IPCustomEntity' } ] }
      { entityType: 'Host', fieldMappings: [ { identifier: 'FullName', columnName: 'HostCustomEntity' } ] }
    ]
    incidentConfiguration: { createIncident: true }
  }
}

resource lsassAccess 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: law
  name: guid(law.id, 'sysmon-lsass-access')
  kind: 'Scheduled'
  properties: {
    displayName: '[Lab] Credential dumping - suspicious LSASS process access (Sysmon 10)'
    description: 'Sysmon event 10 showing a non-system process opening lsass.exe with read/query access rights typical of Mimikatz-style dumping.'
    severity: 'High'
    enabled: true
    query: '''
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 10
| extend Parsed = parse_xml(EventData)
| extend Fields = Parsed.DataItem.EventData.Data
| mv-apply F = Fields on (
    extend k = tostring(F["@Name"]), v = tostring(F["#text"])
    | summarize Bag = make_bag(pack(k, v))
  )
| extend TargetImage = tostring(Bag.TargetImage),
         SourceImage = tostring(Bag.SourceImage),
         GrantedAccess = tostring(Bag.GrantedAccess),
         SourceUser = tostring(Bag.SourceUser)
| where TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1f0fff", "0x1fffff")
| where SourceImage !startswith "C:\\Windows\\System32\\"
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess, SourceUser
| extend HostCustomEntity = Computer, AccountCustomEntity = SourceUser
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [ 'CredentialAccess' ]
    techniques: [ 'T1003' ]
    entityMappings: [
      { entityType: 'Host', fieldMappings: [ { identifier: 'FullName', columnName: 'HostCustomEntity' } ] }
      { entityType: 'Account', fieldMappings: [ { identifier: 'Name', columnName: 'AccountCustomEntity' } ] }
    ]
    incidentConfiguration: { createIncident: true }
  }
}

resource newLocalAdmin 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: law
  name: guid(law.id, 'privileged-group-add')
  kind: 'Scheduled'
  properties: {
    displayName: '[Lab] Account added to a privileged group'
    description: 'Event 4728/4732/4756 adding a member to Domain Admins, Enterprise Admins, Administrators or similar.'
    severity: 'High'
    enabled: true
    query: '''
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TargetUserName has_any ("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins", "Account Operators", "Backup Operators")
| project TimeGenerated, Computer, Activity, GroupName = TargetUserName, AddedMember = MemberName, Actor = SubjectUserName
| extend AccountCustomEntity = Actor, HostCustomEntity = Computer
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [ 'PrivilegeEscalation', 'Persistence' ]
    techniques: [ 'T1098' ]
    entityMappings: [
      { entityType: 'Account', fieldMappings: [ { identifier: 'Name', columnName: 'AccountCustomEntity' } ] }
      { entityType: 'Host', fieldMappings: [ { identifier: 'FullName', columnName: 'HostCustomEntity' } ] }
    ]
    incidentConfiguration: { createIncident: true }
  }
}
