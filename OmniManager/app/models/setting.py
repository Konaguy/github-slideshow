from app.extensions import db


class Setting(db.Model):
    """Key-value store for runtime configuration (email, etc.)."""
    __tablename__ = "settings"

    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")

    @classmethod
    def get(cls, key, default=""):
        obj = db.session.get(cls, key)
        return obj.value if obj else default

    @classmethod
    def set(cls, key, value):
        obj = db.session.get(cls, key)
        if obj:
            obj.value = str(value)
        else:
            db.session.add(cls(key=key, value=str(value)))
        db.session.commit()

    def __repr__(self):
        return f"<Setting {self.key}>"
