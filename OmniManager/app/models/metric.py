from datetime import datetime
from app.extensions import db


class EndpointMetric(db.Model):
    """Point-in-time CPU / RAM / disk snapshot collected via WinRM."""
    __tablename__ = "endpoint_metrics"

    id          = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoints.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    cpu_percent  = db.Column(db.Float)
    ram_percent  = db.Column(db.Float)
    ram_free_gb  = db.Column(db.Float)
    disk_percent = db.Column(db.Float)
    disk_free_gb = db.Column(db.Float)
    disk_total_gb = db.Column(db.Float)
    recorded_at  = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<EndpointMetric ep={self.endpoint_id} cpu={self.cpu_percent}%>"
