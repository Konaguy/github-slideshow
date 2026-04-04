import os
import sys
from flask import Flask
from config import config
from app.extensions import db, login_manager, socketio, csrf, migrate, limiter


def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config[config_name])

    # Logging (before everything else so startup messages are captured)
    from app.utils.logging import setup_logging
    setup_logging(app)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    socketio.init_app(app, async_mode=app.config["SOCKETIO_ASYNC_MODE"], cors_allowed_origins="*")

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return db.session.get(User, int(user_id))

    # Register blueprints
    from app.blueprints.auth import auth_bp
    from app.blueprints.dashboard import dashboard_bp
    from app.blueprints.endpoints import endpoints_bp
    from app.blueprints.patches import patches_bp
    from app.blueprints.software import software_bp
    from app.blueprints.vulnerabilities import vulnerabilities_bp
    from app.blueprints.rdp import rdp_bp
    from app.blueprints.api import api_bp
    from app.blueprints.settings import settings_bp
    from app.blueprints.audit import audit_bp
    from app.blueprints.search import search_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(endpoints_bp, url_prefix="/endpoints")
    app.register_blueprint(patches_bp, url_prefix="/patches")
    app.register_blueprint(software_bp, url_prefix="/software")
    app.register_blueprint(vulnerabilities_bp, url_prefix="/vulnerabilities")
    app.register_blueprint(rdp_bp, url_prefix="/rdp")
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(audit_bp, url_prefix="/audit")
    app.register_blueprint(search_bp, url_prefix="/search")

    # SocketIO room management
    @socketio.on("join")
    def on_join(data):
        from flask_socketio import join_room
        room = data.get("room")
        if room:
            join_room(room)

    # Create tables (Flask-Migrate handles future schema changes)
    with app.app_context():
        db.create_all()
        _seed_admin_user()

    # Start APScheduler — skip in reloader parent process and Flask CLI sub-commands
    _is_cli_cmd = any(arg in sys.argv for arg in ("db", "shell", "routes", "test"))
    _is_reloader_parent = app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true"
    if not _is_cli_cmd and not _is_reloader_parent:
        try:
            from app.utils.scheduler import init_scheduler
            init_scheduler(app)
        except Exception:
            app.logger.exception("Scheduler failed to start — scheduled scans disabled")

    return app


def _seed_admin_user():
    from app.models.user import User
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email="admin@omnimanager.local",
            is_admin=True,
        )
        admin.set_password(os.environ.get("ADMIN_PASSWORD", "admin"))
        db.session.add(admin)
        db.session.commit()
