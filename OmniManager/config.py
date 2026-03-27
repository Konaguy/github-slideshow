import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///omnimanager.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True

    # Flask-Login
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # SocketIO
    SOCKETIO_ASYNC_MODE = os.environ.get("SOCKETIO_ASYNC_MODE", "threading")

    # WinRM defaults
    WINRM_PORT = int(os.environ.get("WINRM_PORT", 5985))
    WINRM_TRANSPORT = os.environ.get("WINRM_TRANSPORT", "ntlm")
    WINRM_TIMEOUT = int(os.environ.get("WINRM_TIMEOUT", 30))

    # Pagination
    ENDPOINTS_PER_PAGE = 25

    # RDP
    RDP_PORT = int(os.environ.get("RDP_PORT", 3389))


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = False


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_ECHO = False


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
