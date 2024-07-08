from app import db
import uuid


user_org = db.Table('user_org',
                    db.Column('user_id', db.String, db.ForeignKey('user.id')),
                    db.Column('org_id', db.String, db.ForeignKey('organisation.id')))

class User(db.Model):
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4())))
    firstName = db.Column(db.String, nullable=False)
    lastName = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    phone = db.Column(db.String)
    organisation = db.relationship('Organisation', secondary=user_org, backref='users')


    def __repr__(self):
        return f"User('{self.firstName}', '{self.lastName}', '{self.email}')"


class Organisation(db.Model):
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4())))
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, default="")

    def __repr__(self):
        return f"User('{self.name}')"
    
