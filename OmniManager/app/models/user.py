from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    totp_secret = db.Column(db.String(256))
    totp_enabled = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_secret(self):
        if not self.totp_secret:
            return None
        from app.utils.crypto import decrypt
        return decrypt(self.totp_secret)

    def set_totp_secret(self, raw_secret: str) -> None:
        from app.utils.crypto import encrypt
        self.totp_secret = encrypt(raw_secret)

    def verify_totp(self, token: str) -> bool:
        import pyotp
        secret = self.get_totp_secret()
        if not secret:
            return False
        return pyotp.TOTP(secret).verify(token, valid_window=1)

    def __repr__(self):
        return f"<User {self.username}>"
