using 'main.bicep'

// --- Placement --------------------------------------------------------------
param prefix = 'mdlab'
param location = 'eastus'

// --- Credentials ------------------------------------------------------------
// Supplied at deploy time, never committed. deploy.sh prompts for both and
// passes them with --parameters adminPassword=... dsrmPassword=...
param adminUsername = 'labadmin'
param adminPassword = readEnvironmentVariable('LAB_ADMIN_PASSWORD')
param dsrmPassword  = readEnvironmentVariable('LAB_DSRM_PASSWORD')

// --- Domain -----------------------------------------------------------------
param domainName = 'lab.local'
param domainNetbiosName = 'LAB'

// --- Machines ---------------------------------------------------------------
param serverVmSize = 'Standard_D2s_v3'
param clientVmSize = 'Standard_D2s_v3'
param clientCount = 3
param windowsServerSku = '2022-datacenter-azure-edition'
param windows11Sku = 'win11-24h2-ent'

// --- Network ----------------------------------------------------------------
param addressSpace = '10.10.0.0/16'
param labSubnetPrefix = '10.10.10.0/24'
param bastionSubnetPrefix = '10.10.250.0/26'
param dcPrivateIp = '10.10.10.4'
param enableBastion = true

// --- Monitoring -------------------------------------------------------------
param logRetentionInDays = 30
param dailyQuotaGb = 5

// --- Defender ---------------------------------------------------------------
param defenderForServersPlan = 'P2'
param enableDefenderCspm = false
param enableAncillaryDefenderPlans = false
param deployDefenderForCloudConnector = true
// Set to false if you are not Security Administrator / Global Administrator in
// the tenant - the deployment will fail on this connector otherwise.
param deployDefenderXdrConnector = true
param deployAnalyticsRules = true

// --- Cost control -----------------------------------------------------------
param enableAutoShutdown = true
param autoShutdownTime = '1900'
param autoShutdownTimeZone = 'UTC'
