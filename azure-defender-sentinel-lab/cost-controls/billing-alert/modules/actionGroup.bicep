/*
  Action group used by the billing budget: email to the listed addresses and,
  when a phone number is supplied, an SMS. Deployed at resource-group scope.
*/
param actionGroupName string = 'ag-lab-billing'

@description('Email recipients.')
param contactEmails array

@description('SMS country code without +, e.g. 1 for US/Canada.')
param smsCountryCode string = '1'

@description('SMS mobile number, digits only (e.g. 5551234567). Empty = no SMS.')
param smsPhoneNumber string = ''

resource ag 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: actionGroupName
  location: 'global'
  properties: {
    // <=12 chars; prefixes the SMS/email so you know what fired.
    groupShortName: 'labbilling'
    enabled: true
    emailReceivers: [for (email, i) in contactEmails: {
      name: 'email${i}'
      emailAddress: email
      useCommonAlertSchema: true
    }]
    smsReceivers: empty(smsPhoneNumber) ? [] : [
      {
        name: 'sms0'
        countryCode: smsCountryCode
        phoneNumber: smsPhoneNumber
      }
    ]
  }
}

output actionGroupId string = ag.id
