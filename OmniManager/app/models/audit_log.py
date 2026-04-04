from datetime import datetime
from app.extensions import db


class AuditLog(db.Model):
    """Immutable record of user actions for compliance and troubleshooting."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    # Denormalize username so the entry survives user deletion
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = db.Column(db.String(80), nullable=False, default="system")
    action = db.Column(db.String(100), nullable=False, index=True)
    object_type = db.Column(db.String(50))   # endpoint | patch | software | vulnerability | user
    object_id = db.Column(db.String(100))
    detail = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<AuditLog {self.action} by {self.username}>"
