import json
from datetime import datetime
from app.extensions import db
from app.models.patch import PatchScanResult
from app.services.winrm_service import WinRMService


_SCAN_SCRIPT = """
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$results = $searcher.Search("IsInstalled=0 and Type='Software'")
$updates = @()
foreach ($update in $results.Updates) {
    $updates += [PSCustomObject]@{
        KBId        = ($update.KBArticleIDs | Select-Object -First 1)
        Title       = $update.Title
        Severity    = $update.MsrcSeverity
    }
}
$updates | ConvertTo-Json -Depth 3
"""

_INSTALL_SCRIPT = """
param([string]$KBId)
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$results = $searcher.Search("IsInstalled=0 and KBArticleID='$KBId'")
if ($results.Updates.Count -eq 0) {
    Write-Error "Update KB$KBId not found"
    exit 1
}
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $results.Updates
$downloader.Download()
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $results.Updates
$result = $installer.Install()
exit $result.ResultCode
"""


class PatchService:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.winrm = WinRMService(endpoint)

    def scan(self, socketio=None, room=None):
        """Scan endpoint for missing patches. Returns list of PatchScanResult objects."""
        out, err, code = self.winrm.run_ps(_SCAN_SCRIPT)

        if code != 0:
            return [], err

        try:
            data = json.loads(out) if out.strip() else []
        except json.JSONDecodeError as e:
            return [], str(e)

        if isinstance(data, dict):
            data = [data]

        results = []
        for item in data:
            kb_id = str(item.get("KBId", "")).strip()
            if not kb_id:
                continue

            existing = PatchScanResult.query.filter_by(
                endpoint_id=self.endpoint.id, kb_id=kb_id
            ).first()
            if existing:
                existing.scanned_at = datetime.utcnow()
                existing.status = "missing"
                existing.title = item.get("Title", "")
                existing.severity = (item.get("Severity") or "unspecified").lower()
                results.append(existing)
            else:
                result = PatchScanResult(
                    endpoint_id=self.endpoint.id,
                    kb_id=kb_id,
                    title=item.get("Title", ""),
                    severity=(item.get("Severity") or "unspecified").lower(),
                    status="missing",
                )
                db.session.add(result)
                results.append(result)

            if socketio and room:
                socketio.emit("patch_found", {"kb_id": kb_id, "title": item.get("Title", "")}, room=room)

        db.session.commit()
        return results, None

    def install(self, kb_id, socketio=None, room=None):
        """Install a specific patch by KB ID."""
        scan_result = PatchScanResult.query.filter_by(
            endpoint_id=self.endpoint.id, kb_id=kb_id
        ).first()
        if scan_result:
            scan_result.status = "installing"
            db.session.commit()

        if socketio and room:
            socketio.emit("patch_installing", {"kb_id": kb_id}, room=room)

        out, err, code = self.winrm.run_ps(f'$KBId = "{kb_id}"\n{_INSTALL_SCRIPT}')

        if scan_result:
            if code == 0:
                scan_result.status = "installed"
                scan_result.installed_at = datetime.utcnow()
            else:
                scan_result.status = "failed"
                scan_result.error_message = err
            db.session.commit()

        if socketio and room:
            event = "patch_installed" if code == 0 else "patch_failed"
            socketio.emit(event, {"kb_id": kb_id, "error": err}, room=room)

        return code == 0, err
