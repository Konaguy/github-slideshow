import winrm
from flask import current_app


class WinRMService:
    """Wraps pywinrm for remote command execution on Windows endpoints."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.session = None

    def _get_session(self):
        if self.session is None:
            self.session = winrm.Session(
                target=self.endpoint.ip_address,
                auth=(self.endpoint.winrm_username, self.endpoint.winrm_password),
                transport=self.endpoint.winrm_transport or current_app.config["WINRM_TRANSPORT"],
                server_cert_validation="ignore",
                read_timeout_sec=current_app.config["WINRM_TIMEOUT"],
                operation_timeout_sec=current_app.config["WINRM_TIMEOUT"],
            )
        return self.session

    def run_ps(self, script):
        """Run a PowerShell script and return (stdout, stderr, status_code)."""
        try:
            session = self._get_session()
            result = session.run_ps(script)
            return result.std_out.decode("utf-8", errors="replace"), result.std_err.decode("utf-8", errors="replace"), result.status_code
        except Exception as e:
            return "", str(e), -1

    def run_cmd(self, command, args=()):
        """Run a cmd.exe command and return (stdout, stderr, status_code)."""
        try:
            session = self._get_session()
            result = session.run_cmd(command, args)
            return result.std_out.decode("utf-8", errors="replace"), result.std_err.decode("utf-8", errors="replace"), result.status_code
        except Exception as e:
            return "", str(e), -1

    def ping(self):
        """Test connectivity to the endpoint. Returns True if reachable."""
        script = "Write-Output 'pong'"
        out, err, code = self.run_ps(script)
        return code == 0 and "pong" in out

    def get_system_info(self):
        """Fetch basic OS/hardware info from the endpoint."""
        script = """
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
[PSCustomObject]@{
    Hostname    = $env:COMPUTERNAME
    OSName      = $os.Caption
    OSVersion   = $os.Version
    Architecture= $os.OSArchitecture
    Domain      = $cs.Domain
    LastUser    = $cs.UserName
} | ConvertTo-Json
"""
        out, err, code = self.run_ps(script)
        if code != 0:
            return None, err
        import json
        try:
            return json.loads(out), None
        except json.JSONDecodeError as e:
            return None, str(e)
