"""
APScheduler integration for OmniManager.

Jobs are stored in the DB (ScheduledJob model) and reloaded on startup.
Call reschedule_job() from the settings UI whenever a job is toggled/edited.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None

_DEFAULT_JOBS = [
    {
        "job_id": "patch_scan_all",
        "label": "Patch Scan — All Endpoints",
        "job_type": "patch_scan",
        "cron_hour": "2",
        "cron_minute": "0",
    },
    {
        "job_id": "software_scan_all",
        "label": "Software Scan — All Endpoints",
        "job_type": "software_scan",
        "cron_hour": "3",
        "cron_minute": "0",
    },
    {
        "job_id": "vuln_scan_all",
        "label": "Vulnerability Scan — All Endpoints",
        "job_type": "vuln_scan",
        "cron_hour": "4",
        "cron_minute": "0",
    },
]


def get_scheduler() -> BackgroundScheduler | None:
    return _scheduler


def init_scheduler(app) -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    _scheduler = BackgroundScheduler(daemon=True)

    with app.app_context():
        _seed_defaults()
        _load_enabled_jobs(app)

    _scheduler.start()
    logger.info("APScheduler started — %d job(s) active", len(_scheduler.get_jobs()))
    return _scheduler


def reschedule_job(app, job) -> None:
    """Called from settings UI after a ScheduledJob is saved."""
    global _scheduler
    if _scheduler is None:
        return

    if not job.enabled:
        try:
            _scheduler.remove_job(job.job_id)
            logger.info("Removed scheduled job %s", job.job_id)
        except Exception:
            pass  # job may not have been registered
    else:
        _register_job(app, job)


# ── internal helpers ──────────────────────────────────────────────────────────

def _seed_defaults() -> None:
    from app.models.scheduled_job import ScheduledJob
    from app.extensions import db

    for d in _DEFAULT_JOBS:
        if not ScheduledJob.query.filter_by(job_id=d["job_id"]).first():
            db.session.add(ScheduledJob(**d))
    db.session.commit()


def _load_enabled_jobs(app) -> None:
    from app.models.scheduled_job import ScheduledJob

    for job in ScheduledJob.query.filter_by(enabled=True).all():
        _register_job(app, job)


def _register_job(app, job) -> None:
    job_id = job.job_id
    job_type = job.job_type
    include_unknown = job.include_unknown

    trigger = CronTrigger(
        hour=job.cron_hour,
        minute=job.cron_minute,
        day_of_week=job.cron_day_of_week,
    )

    def _run():
        with app.app_context():
            from datetime import datetime
            from app.extensions import db
            from app.models.endpoint import Endpoint
            from app.models.scheduled_job import ScheduledJob as SJ
            from app.utils.bulk_scan import run_bulk_scan

            statuses = ["online", "unknown"] if include_unknown else ["online"]
            endpoint_ids = [
                ep.id for ep in Endpoint.query.filter(Endpoint.status.in_(statuses)).all()
            ]

            if not endpoint_ids:
                logger.info("Scheduled %s: no endpoints to scan", job_type)
                return

            logger.info("Scheduled %s triggered — %d endpoint(s)", job_type, len(endpoint_ids))

            if job_type == "patch_scan":
                from app.services.patch_service import PatchService
                def _scan(ep_id):
                    ep = db.session.get(Endpoint, ep_id)
                    if ep:
                        PatchService(ep).scan()
            elif job_type == "software_scan":
                from app.services.software_service import SoftwareService
                def _scan(ep_id):
                    ep = db.session.get(Endpoint, ep_id)
                    if ep:
                        SoftwareService(ep).scan()
            elif job_type == "vuln_scan":
                from app.services.vuln_service import VulnerabilityService
                def _scan(ep_id):
                    ep = db.session.get(Endpoint, ep_id)
                    if ep:
                        VulnerabilityService(ep).scan()
            else:
                logger.warning("Unknown job_type: %s", job_type)
                return

            run_bulk_scan(app, endpoint_ids, _scan, label=f"scheduled {job_type}")

            sj = SJ.query.filter_by(job_id=job_id).first()
            if sj:
                sj.last_run_at = datetime.utcnow()
                db.session.commit()

    _scheduler.add_job(_run, trigger=trigger, id=job_id, replace_existing=True)
    logger.debug(
        "Registered scheduled job %s (hour=%s min=%s dow=%s)",
        job_id, job.cron_hour, job.cron_minute, job.cron_day_of_week,
    )
