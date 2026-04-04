import secrets
from datetime import datetime, timedelta
from app.extensions import db

EXPIRY_HOURS = 1


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @classmethod
    def create_for(cls, user):
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=EXPIRY_HOURS)
        obj = cls(token=token, user_id=user.id, expires_at=expires_at)
        db.session.add(obj)
        db.session.commit()
        return obj

    @classmethod
    def find_valid(cls, token_str):
        obj = cls.query.filter_by(token=token_str, used=False).first()
        if obj and obj.expires_at > datetime.utcnow():
            return obj
        return None

    def consume(self):
        self.used = True
        db.session.commit()

    def __repr__(self):
        return f"<PasswordResetToken user_id={self.user_id} used={self.used}>"
