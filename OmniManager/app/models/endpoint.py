from datetime import datetime
from app.extensions import db


class Endpoint(db.Model):
    __tablename__ = "endpoints"

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    domain = db.Column(db.String(255))
    os_name = db.Column(db.String(255))
    os_version = db.Column(db.String(100))
    architecture = db.Column(db.String(20))
    last_user = db.Column(db.String(255))

    # WinRM credentials (stored encrypted in production)
    winrm_username = db.Column(db.String(255))
    winrm_password = db.Column(db.String(255))
    winrm_port = db.Column(db.Integer, default=5985)
    winrm_transport = db.Column(db.String(20), default="ntlm")

    # Status
    status = db.Column(
        db.Enum("online", "offline", "unknown", name="endpoint_status"),
        default="unknown",
    )
    last_seen = db.Column(db.DateTime)
    last_ping = db.Column(db.DateTime)

    # Tags / notes
    tags = db.Column(db.String(500))
    notes = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    patch_scans = db.relationship("PatchScanResult", backref="endpoint", lazy="dynamic", cascade="all, delete-orphan")
    software_scans = db.relationship("SoftwareScanResult", backref="endpoint", lazy="dynamic", cascade="all, delete-orphan")
    vuln_scans = db.relationship("VulnerabilityScanResult", backref="endpoint", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def tag_list(self):
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    @property
    def status_badge(self):
        badges = {"online": "success", "offline": "danger", "unknown": "secondary"}
        return badges.get(self.status, "secondary")

    def __repr__(self):
        return f"<Endpoint {self.hostname} ({self.ip_address})>"
