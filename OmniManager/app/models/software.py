from datetime import datetime
from app.extensions import db


class Software(db.Model):
    __tablename__ = "software_catalog"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    publisher = db.Column(db.String(255))
    version = db.Column(db.String(100))
    install_command = db.Column(db.Text)
    uninstall_command = db.Column(db.Text)
    silent_args = db.Column(db.String(255))
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Software {self.name} {self.version}>"


class SoftwareScanResult(db.Model):
    __tablename__ = "software_scan_results"

    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoints.id"), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    publisher = db.Column(db.String(255))
    version = db.Column(db.String(100))
    install_date = db.Column(db.String(50))
    uninstall_string = db.Column(db.Text)
    status = db.Column(
        db.Enum("installed", "installing", "uninstalling", "failed", name="sw_result_status"),
        default="installed",
    )
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)
    error_message = db.Column(db.Text)

    @property
    def status_badge(self):
        badges = {
            "installed": "success",
            "installing": "info",
            "uninstalling": "warning",
            "failed": "danger",
        }
        return badges.get(self.status, "secondary")

    def __repr__(self):
        return f"<SoftwareScanResult {self.name} on endpoint {self.endpoint_id}>"
