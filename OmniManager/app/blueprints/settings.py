from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required
from app.extensions import db
from app.models.scheduled_job import ScheduledJob
from app.models.setting import Setting

settings_bp = Blueprint("settings", __name__)

_MAIL_KEYS = [
    "ALERTS_ENABLED",
    "MAIL_SERVER",
    "MAIL_PORT",
    "MAIL_USE_TLS",
    "MAIL_USERNAME",
    "MAIL_PASSWORD",
    "MAIL_FROM",
    "MAIL_TO",
]


@settings_bp.route("/")
@login_required
def index():
    jobs = ScheduledJob.query.order_by(ScheduledJob.id).all()
    mail_cfg = {k: Setting.get(k) for k in _MAIL_KEYS}
    return render_template("settings/index.html", jobs=jobs, mail_cfg=mail_cfg)


@settings_bp.route("/schedules/<job_id>", methods=["POST"])
@login_required
def update_schedule(job_id):
    job = ScheduledJob.query.filter_by(job_id=job_id).first_or_404()

    job.enabled = request.form.get("enabled") == "1"
    job.cron_hour = (request.form.get("cron_hour") or "2").strip()
    job.cron_minute = (request.form.get("cron_minute") or "0").strip()
    job.cron_day_of_week = (request.form.get("cron_day_of_week") or "*").strip()
    job.include_unknown = request.form.get("include_unknown") == "1"
    db.session.commit()

    try:
        from app.utils.scheduler import reschedule_job
        reschedule_job(current_app._get_current_object(), job)
    except Exception:
        pass  # scheduler may not be running (CLI / test)

    status = "enabled" if job.enabled else "disabled"
    flash(f"'{job.label}' {status} and saved.", "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/mail", methods=["POST"])
@login_required
def update_mail():
    for key in _MAIL_KEYS:
        Setting.set(key, request.form.get(key, "").strip())
    flash("Email alert settings saved.", "success")
    return redirect(url_for("settings.index"))
