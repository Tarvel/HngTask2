from app import db


user_org = db.Table('user_org',
                    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                    db.Column('org_id', db.Integer, db.ForeignKey('organisation.id')))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String, nullable=False)
    lastName = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    phone = db.Column(db.String)
    organisation = db.relationship('Organisation', secondary=user_org, backref='users')


    def __repr__(self):
        return f"User('{self.firstName}', '{self.lastName}', '{self.email}')"


class Organisation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, default="")

    def __repr__(self):
        return f"User('{self.name}')"
    