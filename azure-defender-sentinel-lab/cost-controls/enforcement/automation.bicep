/*
  Enforcement automation: an Automation account whose managed identity runs two
  scheduled runbooks against the lab.

    Enforce-Budget   hourly            deallocate all VMs when MTD cost >= $25
    Stop-IdleVms     every 30 min      deallocate VMs idle below a CPU threshold

  The runbook bodies are pulled from raw GitHub (publishContentLink), same as the
  lab bootstrap scripts. Role assignments here cover the resource group (VM
  Contributor + Monitoring Reader). The subscription-scope Cost Management Reader
  is granted by deploy-enforcement.sh, because it is outside this RG scope.
*/

param location string = resourceGroup().location
param prefix string = 'mdlab'

@description('Budget threshold in USD that triggers a full deallocate.')
param budgetThresholdUsd int = 25

@description('Average CPU %% under which a VM is considered idle.')
param idleCpuThresholdPercent int = 5

@description('Idle-detection window in minutes.')
param idleWindowMinutes int = 30

@description('Raw base URI the runbook bodies are pulled from. Must end with a slash.')
param runbooksBaseUri string = 'https://raw.githubusercontent.com/konaguy/github-slideshow/refs/heads/claude/exciting-curie-806ybx/azure-defender-sentinel-lab/cost-controls/enforcement/runbooks/'

@description('Schedule base start time; must be >5 min in the future. Leave default.')
param scheduleStart string = dateTimeAdd(utcNow(), 'PT1H')

var automationName = '${prefix}-automation'
var vmContributorRoleId = '9980e02c-c2be-4d73-94e8-173b1dc7cf3c'
var monitoringReaderRoleId = '43d0d8ad-25c7-4714-9337-8ba259a9fe05'

resource automation 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    sku: { name: 'Basic' }
    publicNetworkAccess: true
  }
}

resource subIdVar 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  parent: automation
  name: 'SubscriptionId'
  properties: {
    isEncrypted: false
    value: '"${subscription().subscriptionId}"'
  }
}

resource rbBudget 'Microsoft.Automation/automationAccounts/runbooks@2023-11-01' = {
  parent: automation
  name: 'Enforce-Budget'
  location: location
  properties: {
    runbookType: 'PowerShell'
    logProgress: false
    logVerbose: false
    publishContentLink: { uri: '${runbooksBaseUri}Enforce-Budget.ps1' }
  }
}

resource rbIdle 'Microsoft.Automation/automationAccounts/runbooks@2023-11-01' = {
  parent: automation
  name: 'Stop-IdleVms'
  location: location
  properties: {
    runbookType: 'PowerShell'
    logProgress: false
    logVerbose: false
    publishContentLink: { uri: '${runbooksBaseUri}Stop-IdleVms.ps1' }
  }
}

// Hourly budget check.
resource schedBudget 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {
  parent: automation
  name: 'sched-budget-hourly'
  properties: {
    frequency: 'Hour'
    interval: 1
    startTime: scheduleStart
    timeZone: 'UTC'
  }
}

// Two hourly idle checks offset by 30 min => effectively every 30 min.
resource schedIdleA 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {
  parent: automation
  name: 'sched-idle-A'
  properties: {
    frequency: 'Hour'
    interval: 1
    startTime: scheduleStart
    timeZone: 'UTC'
  }
}

resource schedIdleB 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {
  parent: automation
  name: 'sched-idle-B'
  properties: {
    frequency: 'Hour'
    interval: 1
    startTime: dateTimeAdd(scheduleStart, 'PT30M')
    timeZone: 'UTC'
  }
}

resource jsBudget 'Microsoft.Automation/automationAccounts/jobSchedules@2023-11-01' = {
  parent: automation
  name: guid(automation.id, 'js-budget')
  properties: {
    runbook: { name: rbBudget.name }
    schedule: { name: schedBudget.name }
    parameters: {
      ThresholdUsd: string(budgetThresholdUsd)
    }
  }
}

resource jsIdleA 'Microsoft.Automation/automationAccounts/jobSchedules@2023-11-01' = {
  parent: automation
  name: guid(automation.id, 'js-idle-a')
  properties: {
    runbook: { name: rbIdle.name }
    schedule: { name: schedIdleA.name }
    parameters: {
      CpuThresholdPercent: string(idleCpuThresholdPercent)
      WindowMinutes: string(idleWindowMinutes)
    }
  }
}

resource jsIdleB 'Microsoft.Automation/automationAccounts/jobSchedules@2023-11-01' = {
  parent: automation
  name: guid(automation.id, 'js-idle-b')
  properties: {
    runbook: { name: rbIdle.name }
    schedule: { name: schedIdleB.name }
    parameters: {
      CpuThresholdPercent: string(idleCpuThresholdPercent)
      WindowMinutes: string(idleWindowMinutes)
    }
  }
}

// The automation identity can deallocate and read metrics across the RG.
resource raVmContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, automation.id, vmContributorRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', vmContributorRoleId)
    principalId: automation.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raMonitoringReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, automation.id, monitoringReaderRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringReaderRoleId)
    principalId: automation.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output automationName string = automation.name
output automationPrincipalId string = automation.identity.principalId
