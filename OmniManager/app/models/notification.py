from datetime import datetime
from app.extensions import db


class Notification(db.Model):
    """System-wide in-app notifications shown in the topbar bell."""
    __tablename__ = "notifications"

    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(120), nullable=False)
    message    = db.Column(db.String(500))
    type       = db.Column(db.String(20), default="info")   # info|success|warning|danger
    link       = db.Column(db.String(255))                  # optional click-through URL
    read       = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    @property
    def type_icon(self):
        return {
            "success": "bi-check-circle-fill text-success",
            "warning": "bi-exclamation-triangle-fill text-warning",
            "danger":  "bi-x-circle-fill text-danger",
            "info":    "bi-info-circle-fill text-info",
        }.get(self.type, "bi-bell-fill text-secondary")

    def __repr__(self):
        return f"<Notification {self.title!r} read={self.read}>"
