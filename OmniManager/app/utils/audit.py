"""
Audit logging helper for OmniManager.

Call log_action() from any route after the primary DB commit to record what
happened. Safe to call outside a request context (e.g. from scheduled jobs)
— request/user fields will fall back to sensible defaults.
"""
import logging
from app.extensions import db
from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def log_action(
    action: str,
    object_type: str | None = None,
    object_id: str | None = None,
    detail: str | None = None,
    actor_id: int | None = None,
    actor_name: str | None = None,
) -> None:
    """
    Record a single audit entry.

    When called from a Flask route, current_user and request are resolved
    automatically. Pass actor_id/actor_name explicitly for background threads.
    """
    ip = None
    user_id = actor_id
    username = actor_name or "system"

    try:
        from flask import has_request_context, request
        from flask_login import current_user

        if has_request_context():
            ip = request.remote_addr
            if actor_id is None and current_user.is_authenticated:
                user_id = current_user.id
                username = current_user.username
    except Exception:
        pass

    try:
        entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            object_type=object_type,
            object_id=str(object_id) if object_id is not None else None,
            detail=detail,
            ip_address=ip,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        logger.exception("Failed to write audit log entry: action=%s", action)
