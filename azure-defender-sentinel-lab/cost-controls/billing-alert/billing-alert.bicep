/*
  Billing alert: a subscription budget that emails AND texts when the Azure bill
  approaches / reaches the amount.

  Notifications:
    * 90%  of amount (actual)     -> "approaching"
    * 100% of amount (actual)     -> "reached"
    * 100% of amount (forecast)   -> "projected to reach this month"
  Each fires the action group (email + optional SMS).

  Deploy:
    az deployment sub create --location eastus \
      --template-file billing-alert.bicep \
      --parameters startDate=2026-09-01 smsPhoneNumber=5551234567
*/
targetScope = 'subscription'

@description('Monthly budget amount (USD).')
param amount int = 100

@description('First of the month the budget starts, YYYY-MM-01.')
param startDate string

@description('Budget end date, YYYY-MM-01.')
param endDate string = '2031-09-01'

@description('Resource group that holds the action group.')
param resourceGroupName string = 'rg-mdlab'

@description('Email recipients.')
param contactEmails array = [
  'ed.cleveland@3ch3lon.com'
  'escleveland@outlook.com'
]

@description('SMS country code without +, e.g. 1 for US/Canada.')
param smsCountryCode string = '1'

@description('SMS mobile number, digits only. Empty = email only.')
param smsPhoneNumber string = ''

param budgetName string = 'lab-budget-usd${amount}'

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' existing = {
  name: resourceGroupName
}

module ag 'modules/actionGroup.bicep' = {
  name: 'billing-actiongroup'
  scope: rg
  params: {
    contactEmails: contactEmails
    smsCountryCode: smsCountryCode
    smsPhoneNumber: smsPhoneNumber
  }
}

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: budgetName
  properties: {
    category: 'Cost'
    amount: amount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: startDate
      endDate: endDate
    }
    notifications: {
      Actual_Approaching_90: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 90
        thresholdType: 'Actual'
        contactEmails: contactEmails
        contactGroups: [ ag.outputs.actionGroupId ]
      }
      Actual_Reached_100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: contactEmails
        contactGroups: [ ag.outputs.actionGroupId ]
      }
      Forecast_100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: contactEmails
        contactGroups: [ ag.outputs.actionGroupId ]
      }
    }
  }
}

output budgetId string = budget.id
output actionGroupId string = ag.outputs.actionGroupId
