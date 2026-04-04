from datetime import datetime
from app.extensions import db


class ScheduledJob(db.Model):
    """Persisted configuration for APScheduler cron jobs."""
    __tablename__ = "scheduled_jobs"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(50), unique=True, nullable=False)
    label = db.Column(db.String(100))
    job_type = db.Column(db.String(50))   # patch_scan | software_scan | vuln_scan
    cron_hour = db.Column(db.String(10), default="2")
    cron_minute = db.Column(db.String(10), default="0")
    cron_day_of_week = db.Column(db.String(20), default="*")
    include_unknown = db.Column(db.Boolean, default=False)
    enabled = db.Column(db.Boolean, default=False)
    last_run_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ScheduledJob {self.job_id} enabled={self.enabled}>"
