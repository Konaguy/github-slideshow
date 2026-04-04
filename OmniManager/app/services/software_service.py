import json
import logging
from datetime import datetime
from app.extensions import db
from app.models.software import SoftwareScanResult
from app.services.winrm_service import WinRMService

logger = logging.getLogger(__name__)

_SCAN_SCRIPT = """
$paths = @(
    'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
    'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
    'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
$apps = @()
foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    ForEach-Object {
        $apps += [PSCustomObject]@{
            Name             = $_.DisplayName
            Publisher        = $_.Publisher
            Version          = $_.DisplayVersion
            InstallDate      = $_.InstallDate
            UninstallString  = $_.UninstallString
        }
    }
}
$apps | Sort-Object Name -Unique | ConvertTo-Json -Depth 3
"""


class SoftwareService:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.winrm = WinRMService(endpoint)

    def scan(self, socketio=None, room=None):
        """Enumerate installed software on the endpoint. Returns (results, error)."""
        logger.info("Software scan started — endpoint=%s (%s)", self.endpoint.hostname, self.endpoint.ip_address)
        out, err, code = self.winrm.run_ps(_SCAN_SCRIPT)

        if code != 0:
            logger.error("Software scan failed — endpoint=%s error=%s", self.endpoint.hostname, err)
            return [], err

        try:
            data = json.loads(out) if out.strip() else []
        except json.JSONDecodeError as e:
            logger.error("Software scan JSON parse error — endpoint=%s error=%s", self.endpoint.hostname, e)
            return [], str(e)

        if isinstance(data, dict):
            data = [data]

        SoftwareScanResult.query.filter_by(endpoint_id=self.endpoint.id).delete()

        results = []
        for item in data:
            name = (item.get("Name") or "").strip()
            if not name:
                continue
            result = SoftwareScanResult(
                endpoint_id=self.endpoint.id,
                name=name,
                publisher=item.get("Publisher", ""),
                version=item.get("Version", ""),
                install_date=item.get("InstallDate", ""),
                uninstall_string=item.get("UninstallString", ""),
                status="installed",
            )
            db.session.add(result)
            results.append(result)

            if socketio and room:
                socketio.emit("software_found", {"name": name}, to=room)

        db.session.commit()
        logger.info("Software scan complete — endpoint=%s found=%d", self.endpoint.hostname, len(results))
        return results, None

    def uninstall(self, software_id, socketio=None, room=None):
        """Uninstall software using its stored uninstall string. Returns (success, error)."""
        sw = db.session.get(SoftwareScanResult, software_id)
        if not sw or sw.endpoint_id != self.endpoint.id:
            return False, "Software record not found"

        if not sw.uninstall_string:
            return False, "No uninstall string available"

        logger.info("Uninstalling '%s' — endpoint=%s", sw.name, self.endpoint.hostname)
        sw.status = "uninstalling"
        db.session.commit()

        if socketio and room:
            socketio.emit("sw_uninstalling", {"name": sw.name}, to=room)

        script = (
            f'Start-Process -FilePath "cmd.exe" '
            f'-ArgumentList "/c {sw.uninstall_string} /S /silent /quiet" '
            f'-Wait -PassThru | Select-Object -ExpandProperty ExitCode'
        )
        out, err, code = self.winrm.run_ps(script)

        success = code == 0
        if success:
            logger.info("Uninstall succeeded — '%s' endpoint=%s", sw.name, self.endpoint.hostname)
            db.session.delete(sw)
        else:
            logger.error("Uninstall failed — '%s' endpoint=%s error=%s", sw.name, self.endpoint.hostname, err)
            sw.status = "failed"
            sw.error_message = err
        db.session.commit()

        if socketio and room:
            event = "sw_uninstalled" if success else "sw_uninstall_failed"
            socketio.emit(event, {"name": sw.name, "error": err}, to=room)

        return success, err

    def remote_install(self, install_command, name, socketio=None, room=None):
        """Run an arbitrary install command on the endpoint. Returns (success, error)."""
        logger.info("Installing '%s' — endpoint=%s", name, self.endpoint.hostname)
        if socketio and room:
            socketio.emit("sw_installing", {"name": name}, to=room)

        script = (
            f'Start-Process -FilePath "cmd.exe" '
            f'-ArgumentList "/c {install_command}" '
            f'-Wait -PassThru | Select-Object -ExpandProperty ExitCode'
        )
        out, err, code = self.winrm.run_ps(script)

        if code == 0:
            logger.info("Install succeeded — '%s' endpoint=%s", name, self.endpoint.hostname)
        else:
            logger.error("Install failed — '%s' endpoint=%s error=%s", name, self.endpoint.hostname, err)

        if socketio and room:
            event = "sw_installed" if code == 0 else "sw_install_failed"
            socketio.emit(event, {"name": name, "error": err}, to=room)

        return code == 0, err
