/*
  Subscription-scope cost budget with email alerts.

  Emails the listed addresses when actual spend crosses 90% and 100% of the
  amount, and when *forecast* spend is projected to hit 100%. Budgets are
  informational - they alert, they do not stop spend. The 30-minute
  auto-deallocate (see README) is what actually caps the burn.

  Deploy:
    az deployment sub create --location eastus \
      --template-file budget.bicep \
      --parameters startDate=2026-09-01
*/
targetScope = 'subscription'

@description('Monthly budget amount in the billing currency (USD here).')
param amount int = 25

@description('First day of the month the budget starts, YYYY-MM-01.')
param startDate string

@description('Budget end date, YYYY-MM-01. Default ~5 years out.')
param endDate string = '2031-09-01'

@description('Addresses that receive the alert emails.')
param contactEmails array = [
  'ed.cleveland@3ch3lon.com'
  'escleveland@outlook.com'
]

param budgetName string = 'lab-budget-usd${amount}'

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
      Actual_GE_90_Percent: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 90
        thresholdType: 'Actual'
        contactEmails: contactEmails
      }
      Actual_GE_100_Percent: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: contactEmails
      }
      Forecasted_GE_100_Percent: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: contactEmails
      }
    }
  }
}

output budgetId string = budget.id
