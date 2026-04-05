from datetime import datetime
from app.extensions import db

# Association table — many-to-many Endpoint ↔ EndpointGroup
endpoint_group_members = db.Table(
    "endpoint_group_members",
    db.Column("endpoint_id", db.Integer, db.ForeignKey("endpoints.id", ondelete="CASCADE"), primary_key=True),
    db.Column("group_id",    db.Integer, db.ForeignKey("endpoint_groups.id", ondelete="CASCADE"), primary_key=True),
)


class EndpointGroup(db.Model):
    __tablename__ = "endpoint_groups"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))
    color       = db.Column(db.String(7), default="#6366f1")  # hex colour for UI badge
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship(
        "Endpoint",
        secondary=endpoint_group_members,
        backref=db.backref("groups", lazy="select"),
        lazy="select",
    )

    @property
    def member_count(self):
        return len(self.members)

    def __repr__(self):
        return f"<EndpointGroup {self.name}>"
