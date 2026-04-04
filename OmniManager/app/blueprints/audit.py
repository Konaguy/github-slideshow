from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.extensions import db
from app.models.audit_log import AuditLog
from app.models.user import User

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/")
@login_required
def index():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard.index"))

    page = request.args.get("page", 1, type=int)
    q_user = request.args.get("user", "").strip()
    q_action = request.args.get("action", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    query = AuditLog.query

    if q_user:
        query = query.filter(AuditLog.username.ilike(f"%{q_user}%"))
    if q_action:
        query = query.filter(AuditLog.action.ilike(f"%{q_action}%"))
    if date_from:
        try:
            from datetime import datetime
            query = query.filter(AuditLog.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
        except ValueError:
            pass
    if date_to:
        try:
            from datetime import datetime, timedelta
            query = query.filter(AuditLog.created_at < datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1))
        except ValueError:
            pass

    logs = query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=50, error_out=False)

    # Distinct action names for dropdown
    action_types = [
        r[0] for r in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    ]

    return render_template(
        "audit/index.html",
        logs=logs,
        action_types=action_types,
        q_user=q_user,
        q_action=q_action,
        date_from=date_from,
        date_to=date_to,
    )
