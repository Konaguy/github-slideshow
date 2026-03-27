# OmniManager

Windows endpoint management dashboard — patch scanning, software inventory, vulnerability tracking, and one-click RDP.

## Features

| Feature | Description |
|---|---|
| **Endpoint Inventory** | Track Windows machines: hostname, IP, OS, last user, WinRM credentials |
| **Patch Scanning** | Detect missing Windows Updates via WU COM API over WinRM |
| **Patch Install** | Install individual or all missing patches remotely |
| **Software Inventory** | Enumerate installed software from the registry |
| **Remote Install/Uninstall** | Deploy or remove software silently via WinRM |
| **Vulnerability Scanning** | Surface missing critical/important patches as CVE-style findings |
| **Vulnerability Triage** | Mark findings as open, mitigated, accepted, or false positive |
| **RDP Launch** | One-click `mstsc.exe` for any endpoint |
| **Real-time updates** | SocketIO live feed during scans |
| **REST API** | `/api/v1/` endpoints for integration |

## Requirements

- Python 3.11+
- Windows endpoints with WinRM enabled (HTTP port 5985 or HTTPS 5986)
- To launch RDP: OmniManager must run on a Windows machine with `mstsc.exe`

## Quick Start

```bash
git clone <repo>
cd OmniManager

python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

pip install -r requirements.txt

copy .env.example .env        # Windows
# cp .env.example .env        # Linux/macOS
# Edit .env — change SECRET_KEY and ADMIN_PASSWORD

python run.py
```

Open `http://localhost:5000` — log in with `admin` / the password you set in `.env`.

## Enabling WinRM on Windows Endpoints

Run on each target machine (as Administrator):

```powershell
# Enable WinRM with NTLM
Enable-PSRemoting -Force
winrm quickconfig -quiet
Set-Item WSMan:\localhost\Service\Auth\Ntlm -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true  # HTTP only
netsh advfirewall firewall add rule name="WinRM HTTP" protocol=TCP dir=in localport=5985 action=allow
```

For production use HTTPS (port 5986) with a valid certificate instead of `AllowUnencrypted`.

## Project Layout

```
OmniManager/
├── run.py                  # Entry point
├── config.py               # Config classes (Dev / Prod)
├── requirements.txt
├── pyproject.toml
├── .env.example
├── OmniManager.spec        # PyInstaller build spec
└── app/
    ├── __init__.py         # App factory
    ├── extensions.py       # db, login_manager, socketio, csrf
    ├── models/
    │   ├── user.py
    │   ├── endpoint.py
    │   ├── patch.py
    │   ├── software.py
    │   └── vulnerability.py
    ├── services/
    │   ├── winrm_service.py
    │   ├── patch_service.py
    │   ├── software_service.py
    │   └── vuln_service.py
    ├── blueprints/
    │   ├── auth.py
    │   ├── dashboard.py
    │   ├── endpoints.py
    │   ├── patches.py
    │   ├── software.py
    │   ├── vulnerabilities.py
    │   ├── rdp.py
    │   └── api.py
    ├── templates/
    │   ├── base.html
    │   ├── auth/
    │   ├── dashboard/
    │   ├── endpoints/
    │   ├── patches/
    │   ├── software/
    │   ├── vulnerabilities/
    │   └── rdp/
    └── static/
        ├── css/omni.css
        └── js/omni.js
```

## REST API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/endpoints` | List all endpoints |
| GET | `/api/v1/endpoints/<id>` | Single endpoint |
| GET | `/api/v1/endpoints/<id>/patches` | Patch scan results |
| GET | `/api/v1/endpoints/<id>/software` | Software scan results |
| GET | `/api/v1/endpoints/<id>/vulnerabilities` | Vulnerability findings |
| GET | `/api/v1/stats` | Summary statistics |
| POST | `/api/v1/patches/scan` | Trigger patch scan `{"endpoint_id": 1}` |
| POST | `/api/v1/patches/install` | Install patch `{"endpoint_id":1,"kb_id":"KB1234567"}` |

All API endpoints require session authentication.

## Building a Standalone Executable

```bash
pip install pyinstaller
pyinstaller OmniManager.spec
# Output: dist/OmniManager/OmniManager.exe
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(required)* | Flask session signing key |
| `DATABASE_URL` | `sqlite:///omnimanager.db` | SQLAlchemy DB URL |
| `ADMIN_PASSWORD` | `admin` | Initial admin password |
| `WINRM_PORT` | `5985` | Default WinRM port |
| `WINRM_TRANSPORT` | `ntlm` | WinRM auth: `ntlm`, `basic`, `kerberos`, `ssl` |
| `WINRM_TIMEOUT` | `30` | WinRM operation timeout (seconds) |
| `RDP_PORT` | `3389` | Default RDP port |
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `5000` | Listen port |

## License

MIT
