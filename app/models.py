from app import db, login, app
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from hashlib import md5
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class User(UserMixin, db.Model):
    __table__ = db.Table('users', db.metadata,
                        db.Column('id', db.Integer, primary_key=True),
                        db.Column('username', db.String(64), index=True, unique=True),
                        db.Column('email', db.String(120), index=True, unique=True),
                        db.Column('password_hash', db.String(128)),

                        db.Column('join_timestamp', db.DateTime, default=datetime.utcnow()),
                        db.Column('about_me', db.String(140)),
                        db.Column('followers', db.Integer, db.ForeignKey('users.id')),
                        db.Column('following', db.Integer, db.ForeignKey('users.id')))


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user

    def __repr__(self):
        return '<User {}>'.format(self.username)


class Post(db.Model):
    __table__ = db.Table('posts', db.metadata,
                         db.Column('id', db.Integer, primary_key=True),
                         db.Column('content', db.String(140)),
                         db.Column('timestamp', db.DateTime, index=True, default=datetime.utcnow),
                         db.Column('user', db.Integer, db.ForeignKey('users.id'))
                         )

    def __repr__(self):
        return '<Post {}>'.format(self.content)

    def to_dict(self):
        res = {}
        for field in self.__table__.columns.keys():
            if hasattr(self, field):
                res[field] = getattr(self, field)
        return res

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    img = db.Column(db.Text, unique=True, nullable=False, default="<no image>")
    name = db.Column(db.Text, nullable=False, default="image")
    mimetype = db.Column(db.Text, nullable=False, default=".png")