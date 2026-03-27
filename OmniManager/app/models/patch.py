from datetime import datetime
from app.extensions import db


class Patch(db.Model):
    __tablename__ = "patches"

    id = db.Column(db.Integer, primary_key=True)
    kb_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    title = db.Column(db.String(500))
    description = db.Column(db.Text)
    severity = db.Column(
        db.Enum("critical", "important", "moderate", "low", "unspecified", name="patch_severity"),
        default="unspecified",
    )
    category = db.Column(db.String(100))
    release_date = db.Column(db.DateTime)
    size_mb = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def severity_badge(self):
        badges = {
            "critical": "danger",
            "important": "warning",
            "moderate": "info",
            "low": "secondary",
            "unspecified": "light",
        }
        return badges.get(self.severity, "secondary")

    def __repr__(self):
        return f"<Patch {self.kb_id}>"


class PatchScanResult(db.Model):
    __tablename__ = "patch_scan_results"

    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoints.id"), nullable=False, index=True)
    kb_id = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(500))
    severity = db.Column(db.String(50), default="unspecified")
    status = db.Column(
        db.Enum("missing", "installed", "installing", "failed", name="patch_result_status"),
        default="missing",
    )
    installed_at = db.Column(db.DateTime)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)
    error_message = db.Column(db.Text)

    @property
    def severity_badge(self):
        badges = {
            "critical": "danger",
            "important": "warning",
            "moderate": "info",
            "low": "secondary",
            "unspecified": "light",
        }
        return badges.get(self.severity, "secondary")

    @property
    def status_badge(self):
        badges = {
            "missing": "warning",
            "installed": "success",
            "installing": "info",
            "failed": "danger",
        }
        return badges.get(self.status, "secondary")

    def __repr__(self):
        return f"<PatchScanResult {self.kb_id} on endpoint {self.endpoint_id}>"
