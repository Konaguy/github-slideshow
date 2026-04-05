"""
Notification helper — safe to call from routes and background threads.
"""
import logging
from app.extensions import db
from app.models.notification import Notification

logger = logging.getLogger(__name__)


def notify(title: str, message: str = "", ntype: str = "info", link: str | None = None) -> None:
    """Create a system notification. Call from within an app context."""
    try:
        n = Notification(title=title, message=message, type=ntype, link=link)
        db.session.add(n)
        db.session.commit()
    except Exception:
        logger.exception("Failed to create notification: %s", title)
