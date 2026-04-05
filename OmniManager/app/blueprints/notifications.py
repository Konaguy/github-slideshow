from flask import Blueprint, render_template, redirect, url_for, jsonify
from flask_login import login_required
from app.extensions import db
from app.models.notification import Notification

notifications_bp = Blueprint("notifications", __name__)


@notifications_bp.route("/")
@login_required
def index():
    notes = Notification.query.order_by(Notification.created_at.desc()).limit(100).all()
    # Mark all as read
    Notification.query.filter_by(read=False).update({"read": True})
    db.session.commit()
    return render_template("notifications/index.html", notifications=notes)


@notifications_bp.route("/unread-count")
@login_required
def unread_count():
    count = Notification.query.filter_by(read=False).count()
    recent = Notification.query.order_by(Notification.created_at.desc()).limit(5).all()
    return jsonify({
        "count": count,
        "recent": [
            {
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "type": n.type,
                "link": n.link,
                "read": n.read,
                "created_at": n.created_at.strftime("%Y-%m-%d %H:%M"),
            }
            for n in recent
        ],
    })


@notifications_bp.route("/mark-read", methods=["POST"])
@login_required
def mark_all_read():
    Notification.query.filter_by(read=False).update({"read": True})
    db.session.commit()
    return jsonify({"ok": True})
