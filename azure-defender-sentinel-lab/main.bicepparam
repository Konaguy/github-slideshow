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
// 4 VMs (DC01, SRV01, WIN11-01, WIN11-02) x 2 vCPU = 8 vCPU of this family.
// New subscriptions often have little quota or capacity for a given family;
// check before deploying (see NEW-ACCOUNT-SETUP.md step 2) and swap to any
// Trusted Launch 2-vCPU size that has both, e.g. D2as_v5, D2s_v5, D2as_v7.
param serverVmSize = 'Standard_D2s_v7'
param clientVmSize = 'Standard_D2s_v7'
param clientCount = 2
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
// Off by default: the Defender XDR connector is not reliably ARM-deployable
// (Sentinel rejects the connector kind). Connect it from the portal instead -
// Sentinel > Configuration > Data connectors > Microsoft Defender XDR > Connect.
param deployDefenderXdrConnector = false
param deployAnalyticsRules = true

// --- Cost control -----------------------------------------------------------
param enableAutoShutdown = true
param autoShutdownTime = '1900'
param autoShutdownTimeZone = 'UTC'
