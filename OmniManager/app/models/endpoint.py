from datetime import datetime
from sqlalchemy import select, func
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

    # WinRM credentials — password stored encrypted via crypto.py
    winrm_username = db.Column(db.String(255))
    _winrm_password = db.Column("winrm_password", db.String(500))
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

    # Relationships (lazy="select" — SQLAlchemy 2.x compatible)
    patch_scans = db.relationship(
        "PatchScanResult", backref="endpoint", lazy="select", cascade="all, delete-orphan"
    )
    software_scans = db.relationship(
        "SoftwareScanResult", backref="endpoint", lazy="select", cascade="all, delete-orphan"
    )
    vuln_scans = db.relationship(
        "VulnerabilityScanResult", backref="endpoint", lazy="select", cascade="all, delete-orphan"
    )

    # ── Encrypted password property ───────────────────────────────────────────

    @property
    def winrm_password(self) -> str:
        from app.utils.crypto import decrypt
        return decrypt(self._winrm_password) if self._winrm_password else ""

    @winrm_password.setter
    def winrm_password(self, value: str):
        from app.utils.crypto import encrypt
        self._winrm_password = encrypt(value) if value else ""

    # ── Aggregate helpers (SQLAlchemy 2.x select() style) ─────────────────────

    @property
    def missing_patch_count(self) -> int:
        from app.models.patch import PatchScanResult
        return db.session.scalar(
            select(func.count(PatchScanResult.id)).where(
                PatchScanResult.endpoint_id == self.id,
                PatchScanResult.status == "missing",
            )
        ) or 0

    @property
    def software_count(self) -> int:
        from app.models.software import SoftwareScanResult
        return db.session.scalar(
            select(func.count(SoftwareScanResult.id)).where(
                SoftwareScanResult.endpoint_id == self.id,
            )
        ) or 0

    @property
    def open_vuln_count(self) -> int:
        from app.models.vulnerability import VulnerabilityScanResult
        return db.session.scalar(
            select(func.count(VulnerabilityScanResult.id)).where(
                VulnerabilityScanResult.endpoint_id == self.id,
                VulnerabilityScanResult.status == "open",
            )
        ) or 0

    # ── Utilities ─────────────────────────────────────────────────────────────

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
