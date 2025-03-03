from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import pytz

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    nickname = db.Column(db.String(100), unique=True)  # 新增昵称字段
    register_time = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Shanghai')))
    timezone = db.Column(db.String(50), default="Asia/Shanghai")
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

# models.py
class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Shanghai')))
    ip_address = db.Column(db.String(100))
    device_info = db.Column(db.String(100))
    login_status = db.Column(db.String(50))
    login_location = db.Column(db.String(100))  # 添加地理位置字段
    user = db.relationship('User', backref=db.backref('login_logs', lazy=True))

class ClickLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('link.id'), nullable=False)
    click_time = db.Column(db.DateTime, default=db.func.now())
    link = db.relationship('Link', backref=db.backref('click_logs', lazy=True))

