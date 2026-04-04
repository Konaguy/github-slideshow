"""
Email alert helper for OmniManager.

Uses smtplib directly so it can be called from background threads without
needing a Flask-Mail app context. SMTP settings are read from the DB
(Setting model) so they can be configured via the settings UI.
"""
import logging
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


def _get_cfg() -> dict:
    try:
        from app.models.setting import Setting
        return {
            "enabled": Setting.get("ALERTS_ENABLED", "0") == "1",
            "server": Setting.get("MAIL_SERVER", ""),
            "port": int(Setting.get("MAIL_PORT", "587") or "587"),
            "use_tls": Setting.get("MAIL_USE_TLS", "1") == "1",
            "username": Setting.get("MAIL_USERNAME", ""),
            "password": Setting.get("MAIL_PASSWORD", ""),
            "from_addr": Setting.get("MAIL_FROM", ""),
            "to_addrs": [
                a.strip()
                for a in Setting.get("MAIL_TO", "").split(",")
                if a.strip()
            ],
        }
    except Exception:
        return {"enabled": False}


def send_patch_alert(endpoint, critical_patches: list) -> None:
    """Send alert email for critical/important missing patches."""
    cfg = _get_cfg()
    if not cfg.get("enabled") or not cfg.get("server") or not cfg.get("to_addrs"):
        return

    count = len(critical_patches)
    subject = f"[OmniManager] {count} critical patch(es) missing on {endpoint.hostname}"
    lines = [
        f"Critical missing patches detected on {endpoint.hostname} ({endpoint.ip_address}):",
        "",
    ]
    for p in critical_patches:
        lines.append(f"  KB{p.kb_id}  [{p.severity.upper()}]  {p.title or '(no title)'}")
    lines += ["", "Log in to OmniManager to review and remediate."]
    _send(cfg, subject, "\n".join(lines))


def send_vuln_alert(endpoint, critical_vulns: list) -> None:
    """Send alert email for critical/high open vulnerabilities."""
    cfg = _get_cfg()
    if not cfg.get("enabled") or not cfg.get("server") or not cfg.get("to_addrs"):
        return

    count = len(critical_vulns)
    subject = f"[OmniManager] {count} critical vulnerability(s) on {endpoint.hostname}"
    lines = [
        f"Critical/high vulnerabilities detected on {endpoint.hostname} ({endpoint.ip_address}):",
        "",
    ]
    for v in critical_vulns:
        score = f"CVSS {v.cvss_score:.1f}" if v.cvss_score else "CVSS N/A"
        lines.append(
            f"  {v.cve_id}  [{v.severity.upper()}]  {score}  {v.title or '(no title)'}"
        )
    lines += ["", "Log in to OmniManager to review and remediate."]
    _send(cfg, subject, "\n".join(lines))


def _send(cfg: dict, subject: str, body: str) -> None:
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = cfg["from_addr"]
        msg["To"] = ", ".join(cfg["to_addrs"])

        with smtplib.SMTP(cfg["server"], cfg["port"], timeout=15) as smtp:
            if cfg["use_tls"]:
                smtp.starttls()
            if cfg["username"] and cfg["password"]:
                smtp.login(cfg["username"], cfg["password"])
            smtp.sendmail(cfg["from_addr"], cfg["to_addrs"], msg.as_string())

        logger.info("Alert email sent: %s", subject)
    except Exception:
        logger.exception("Failed to send alert email: %s", subject)
