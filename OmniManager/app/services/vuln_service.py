import json
import logging
from datetime import datetime
from app.extensions import db
from app.models.vulnerability import VulnerabilityScanResult
from app.services.winrm_service import WinRMService

logger = logging.getLogger(__name__)

_SCAN_SCRIPT = """
$vulns = @()
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$results = $searcher.Search("IsInstalled=0 and Type='Software' and BrowseOnly=0")
foreach ($update in $results.Updates) {
    if ($update.MsrcSeverity -in @('Critical','Important')) {
        foreach ($kb in $update.KBArticleIDs) {
            $vulns += [PSCustomObject]@{
                CVEId             = "KB$kb"
                Title             = $update.Title
                Severity          = if ($update.MsrcSeverity) { $update.MsrcSeverity.ToLower() } else { 'info' }
                CvssScore         = 0
                AffectedComponent = 'Windows Update'
                Remediation       = "Install KB$kb"
            }
        }
    }
}
$vulns | ConvertTo-Json -Depth 3
"""


class VulnerabilityService:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.winrm = WinRMService(endpoint)

    def scan(self, socketio=None, room=None):
        """Scan the endpoint for known vulnerabilities. Returns (results, error)."""
        logger.info("Vulnerability scan started — endpoint=%s (%s)", self.endpoint.hostname, self.endpoint.ip_address)
        out, err, code = self.winrm.run_ps(_SCAN_SCRIPT)

        if code != 0:
            logger.error("Vulnerability scan failed — endpoint=%s error=%s", self.endpoint.hostname, err)
            return [], err

        try:
            data = json.loads(out) if out.strip() else []
        except json.JSONDecodeError as e:
            logger.error("Vulnerability scan JSON parse error — endpoint=%s error=%s", self.endpoint.hostname, e)
            return [], str(e)

        if isinstance(data, dict):
            data = [data]

        VulnerabilityScanResult.query.filter_by(
            endpoint_id=self.endpoint.id, status="open"
        ).delete()

        results = []
        for item in data:
            cve_id = (item.get("CVEId") or "").strip()
            if not cve_id:
                continue

            severity = (item.get("Severity") or "info").lower()
            result = VulnerabilityScanResult(
                endpoint_id=self.endpoint.id,
                cve_id=cve_id,
                title=item.get("Title", ""),
                severity=severity,
                cvss_score=float(item.get("CvssScore") or 0),
                affected_component=item.get("AffectedComponent", ""),
                remediation=item.get("Remediation", ""),
                status="open",
            )
            db.session.add(result)
            results.append(result)

            if socketio and room:
                socketio.emit("vuln_found", {"cve_id": cve_id, "severity": severity}, to=room)

        db.session.commit()
        logger.info("Vulnerability scan complete — endpoint=%s found=%d", self.endpoint.hostname, len(results))

        critical = [r for r in results if r.severity in ("critical", "high")]
        if critical:
            try:
                from app.utils.mailer import send_vuln_alert
                send_vuln_alert(self.endpoint, critical)
            except Exception:
                logger.exception("Mailer error during vuln alert")

        return results, None

    def update_status(self, vuln_id, new_status):
        """Update the status of a vulnerability finding. Returns (success, error)."""
        vuln = db.session.get(VulnerabilityScanResult, vuln_id)
        if not vuln or vuln.endpoint_id != self.endpoint.id:
            return False, "Vulnerability not found"

        allowed = {"open", "mitigated", "accepted", "false_positive"}
        if new_status not in allowed:
            return False, f"Invalid status. Must be one of: {', '.join(allowed)}"

        logger.info("Vulnerability %s status → %s — endpoint=%s", vuln.cve_id, new_status, self.endpoint.hostname)
        vuln.status = new_status
        if new_status in ("mitigated", "accepted", "false_positive"):
            vuln.resolved_at = datetime.utcnow()
        else:
            vuln.resolved_at = None
        db.session.commit()
        return True, None
