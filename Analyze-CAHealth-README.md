# Analyze-CAHealth.ps1

Windows Server Certificate Authority health and security analysis script.
Audits your PKI infrastructure for configuration weaknesses, certificate
template misconfigurations, revocation health, and signs of compromise —
without requiring any third-party modules.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell 5.1 or later | Built into Windows Server 2016+ and Windows 10+ |
| Domain-joined machine | Required for all AD-based checks |
| AD read access | Standard domain user is sufficient for most checks |
| Network access to CA hosts | Required for Sections 6, 8, 10, and 11 |
| CA Auditor or CA Admin role | Required for Section 11 (issued cert audit) |
| RSAT AD DS tools (optional) | Improves AD query reliability on workstations |

> **Note:** The script does not need to run on the CA itself. It can run
> from any domain-joined workstation or server that can reach the CA over
> the network.

---

## Permissions Summary

| Check | Minimum Permission |
|---|---|
| AD PKI object enumeration (Sections 1–5, 7, 9) | Domain Users (AD read) |
| CA certificate and CRL health (Sections 2–4) | Domain Users |
| CA flags, audit settings, ESC6 (Section 6) | Domain Users (certutil remote read) |
| CA ACL check / ESC7 (Section 6) | Domain Users |
| CDP / AIA URL reachability (Section 8) | Network access to CRL endpoints |
| Operational checks — HSM, roles, backup (Section 10) | CA Admin or local admin on CA |
| Issued certificate audit (Section 11) | CA Auditor or CA Admin role on each CA |

---

## Execution Policy

If your execution policy blocks unsigned scripts, run one of the following
before executing:

```powershell
# Allow for the current session only (recommended)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Or unblock the downloaded file
Unblock-File .\Analyze-CAHealth.ps1
```

---

## Basic Usage

Open an elevated PowerShell prompt on a domain-joined machine and run:

```powershell
.\Analyze-CAHealth.ps1
```

The script runs all 12 sections and saves an HTML report to the current
directory named `CA_HealthReport_YYYYMMDD_HHmmss.html`.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | String | `.\CA_HealthReport_<timestamp>.html` | Full path for the HTML report |
| `-CsvPath` | String | *(none)* | Optional path to export all findings as CSV |
| `-SkipTemplateAcls` | Switch | Off | Skip the per-template ACL check (ESC4). Use in large environments to reduce runtime |
| `-AuditDays` | Integer | `90` | Number of days of certificate issuance history to examine in Section 11 |
| `-SkipIssuedCertAudit` | Switch | Off | Skip Section 11 entirely. Use if you lack CA Auditor rights or the CA database is very large |

---

## Usage Examples

**Standard run — HTML report only:**
```powershell
.\Analyze-CAHealth.ps1
```

**Save report to a specific path and export CSV for SIEM ingestion:**
```powershell
.\Analyze-CAHealth.ps1 -OutputPath C:\Reports\PKI_Health.html -CsvPath C:\Reports\PKI_Findings.csv
```

**Examine only the last 30 days of issued certificates:**
```powershell
.\Analyze-CAHealth.ps1 -AuditDays 30
```

**Large environment — skip slow ACL and issued cert checks:**
```powershell
.\Analyze-CAHealth.ps1 -SkipTemplateAcls -SkipIssuedCertAudit
```

**Run with least-privilege (AD read only — skips live CA and audit checks):**
```powershell
.\Analyze-CAHealth.ps1 -SkipIssuedCertAudit
```

---

## What the Script Checks

| Section | Description |
|---|---|
| 1 | Environment discovery — locates domain and AD PKI paths |
| 2 | Enterprise CA enumeration — certificate expiry, key size, signature algorithm |
| 3 | PKI hierarchy — verifies root CA is offline; checks chain integrity |
| 4 | CRL and OCSP health — base and delta CRL freshness and expiration |
| 5 | Certificate template security — ESC1 through ESC9 misconfigurations |
| 6 | CA-level security — ESC6 (EDITF flag), ESC7 (CA ACLs), ESC8 (HTTP enroll), audit settings |
| 7 | NTAuthCertificates — expiration and algorithm checks |
| 8 | CDP and AIA URL reachability — tests every revocation endpoint |
| 9 | Unauthorized trusted certificates — flags unrecognized certs in NTAuth and AIA store |
| 10 | Operational best practices — HSM key protection, role separation, enrollment agent restrictions, backup age |
| 11 | Issued certificate anomaly detection — privileged accounts, bulk issuance, off-hours, IP/wildcard SANs |
| 12 | Summary — console output, HTML report, optional CSV |

---

## Output

### Console
Color-coded findings print in real time as each check runs:

| Color | Severity |
|---|---|
| Red | CRITICAL |
| Dark Red | HIGH |
| Yellow | MEDIUM |
| Cyan | LOW |
| Gray | INFO |

A severity count summary is printed at the end.

### HTML Report
Saved automatically to the current directory (or `-OutputPath`). Open in
any browser. Contains:

- Severity count summary
- All findings table (severity, category, target, title, detail)
- Published certificate template details
- CDP / AIA URL reachability results
- Issued certificate anomalies
- Vulnerability reference guide (ESC1–ESC9 and additional checks)

### CSV Export (optional)
Pass `-CsvPath` to generate a CSV file alongside the HTML report. Columns:
`Severity`, `Category`, `Target`, `Title`, `Detail`, `Time`. Suitable for
import into Excel, Splunk, Sentinel, or other SIEM/SOAR platforms.

---

## Severity Levels

| Level | Meaning |
|---|---|
| CRITICAL | Actively exploitable or service-breaking; fix immediately |
| HIGH | Significant risk; remediate in the current change window |
| MEDIUM | Increases attack surface or violates best practice; schedule remediation |
| LOW | Minor hardening opportunity |
| INFO | Informational; no action required |

---

## Section 11 — Issued Certificate Audit Notes

Section 11 connects to each reachable CA's certificate database using the
`ICertView` COM interface. This requires:

1. The CA host to be reachable on the network.
2. The account running the script to hold the **CA Auditor** or **CA Admin**
   role on the target CA (configured in CA properties → Security tab).

If access is denied the section logs an INFO finding and continues. No
error is thrown — the remaining sections still complete.

**Anomalies detected:**

| Type | Threshold |
|---|---|
| Privileged account requester | Domain Admins, Enterprise Admins, Schema Admins, Administrator |
| Bulk issuance | ≥ 100 certs from the same template within a single hour |
| Off-hours issuance | 11 PM – 5 AM local time, or Saturday / Sunday |
| IP address SAN | Any cert containing `IP Address=x.x.x.x` in the SAN |
| Wildcard SAN | Any cert containing `*.` in the SAN |
| Foreign UPN SAN | UPN in SAN that does not match the AD domain |
| Excessive validity | Issued certificate validity > 3 years |

---

## Running on the CA Itself

You can run the script directly on the CA server. This is useful when:

- The CA is on a network segment that your workstation cannot reach.
- You need Section 11 and cannot grant your workstation account CA Auditor
  rights remotely.

Log on to the CA server, open an elevated PowerShell prompt, and run the
script from a local or UNC path.

> **Offline Root CA:** You cannot run the script on an offline root CA.
> The root CA's health is assessed indirectly through what it has
> published to Active Directory.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `Cannot connect to Active Directory` | Machine is not domain-joined or DNS is broken | Run from a domain-joined machine; verify `nslookup <domain>` resolves |
| CA host shows as not reachable | Firewall blocking DCOM / RPC | Open TCP 135 and dynamic RPC ports between your machine and the CA |
| Section 11 returns no certs / access denied | Insufficient CA database rights | Add the running account to the CA Auditor role in CA properties |
| `Could not read CA EditFlags` | WMI / RPC blocked or CA service stopped | Verify `CertSvc` service is running on the CA |
| Template ACL check fails (ESC4) | Insufficient rights to read security descriptors | Run as a Domain Admin or Enterprise Admin account |
| HTML report is blank or missing sections | PowerShell execution policy or `System.Web` not loaded | Run `Add-Type -AssemblyName System.Web` manually to test; ensure .NET is installed |

---

## Notes

- The script makes no changes to any AD object, certificate, or CA
  configuration. It is read-only.
- All network calls use the credentials of the account running the script
  (Windows integrated authentication).
- The issued certificate audit is capped at 5,000 rows per CA to keep
  runtime reasonable. Increase `$MAX_AUDIT_ROWS` in the constants section
  if you need deeper history.
- Findings reference the **Certified Pre-Owned** research (SpecterOps,
  2021) for ESC1–ESC9 nomenclature.
