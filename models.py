from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    nickname = db.Column(db.String(100), unique=True)  # 新增昵称字段
    register_time = db.Column(db.DateTime, default=db.func.now())
    timezone = db.Column(db.String(50), default="UTC")
    avatar = db.Column(db.String(200), default="avatar.jpg")
    links = db.relationship('Link', backref='user', lazy=True)
    is_superuser = db.Column(db.Boolean, default=False)  # 新增超级用户标识

class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500))
    short_code = db.Column(db.String(100), unique=True)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    clicks_at = db.Column(db.DateTime, nullable=True)