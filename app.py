import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user, LoginManager
from models import db, User, Link
from auth import login_manager
from datetime import datetime, timedelta
from sqlalchemy import func
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化组件
db.init_app(app)
login_manager.init_app(app)

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user, remember=True)  # 使用 remember=True 保持登录状态
            session.permanent = True  # 设置 session 为持久化
            app.permanent_session_lifetime = timedelta(hours=24)  # 设置 session 有效期为 24 小时
            return jsonify({"redirect": url_for('index')})
        return jsonify({"error": "用户名密码错误"})
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "用户名已存在"})
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"redirect": url_for('login')})
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/index')
@login_required
def index():
    total_links = Link.query.filter_by(user_id=current_user.id).count()
    current_month = datetime.now().strftime('%Y-%m')
    monthly_links = Link.query.filter(
        Link.user_id == current_user.id,
        func.strftime('%Y-%m', Link.created_at) == current_month
    ).count()

    yesterday = datetime.now() - timedelta(days=1)
    yesterday_date = yesterday.date()
    yesterday_links = Link.query.filter(
        Link.user_id == current_user.id,
        func.date(Link.created_at) == yesterday_date
    ).count()

    today_date = datetime.now().date()
    today_links = Link.query.filter(
        Link.user_id == current_user.id,
        func.date(Link.created_at) == today_date
    ).count()

    update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    links = Link.query.filter_by(user_id=current_user.id).order_by(Link.created_at.desc()).limit(5).all()
    return render_template('index.html',
                           total_links=total_links,
                           monthly_links=monthly_links,
                           yesterday_links=yesterday_links,
                           today_links=today_links,
                           update_time=update_time,
                           link_count=len(links),
                           recent_links=links)


@app.route('/links', methods=['GET', 'POST'])
@login_required
def links():
    if request.method == 'POST':
        original_url = request.form['original_url']
        custom_suffix = request.form.get('custom_suffix')

        if custom_suffix:
            if Link.query.filter_by(short_code=custom_suffix).first():
                return 'Custom suffix exists'
            short_code = custom_suffix
        else:
            short_code = secrets.token_urlsafe(4)

        new_link = Link(
            original_url=original_url,
            short_code=short_code,
            user_id=current_user.id
        )
        db.session.add(new_link)
        db.session.commit()

    links = Link.query.filter_by(user_id=current_user.id).all()
    base_url = request.host_url
    return render_template('links.html', links=links, base_url=base_url)


@app.route('/<short_code>')
def redirect_short_url(short_code):
    link = Link.query.filter_by(short_code=short_code).first()
    if link:
        link.clicks += 1
        db.session.commit()
        return redirect(link.original_url)
    return 'Link not found', 404


@app.route('/stats/<short_code>')
@login_required
def link_stats(short_code):
    link = Link.query.filter_by(short_code=short_code).first()
    return render_template('stats.html', link=link)


@app.route('/profile')
@login_required
def profile():
    total_links = Link.query.filter_by(user_id=current_user.id).count()
    total_clicks = Link.query.filter_by(user_id=current_user.id).with_entities(func.sum(Link.clicks)).scalar() or 0
    return render_template('profile.html',
                           total_links=total_links,
                           total_clicks=total_clicks,
                           user=current_user)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8462)