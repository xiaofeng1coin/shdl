import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user, LoginManager
from models import db, User, Link
from auth import login_manager
from datetime import datetime, timedelta
from sqlalchemy import func
import secrets
import pytz  # 引入 pytz 库以支持完整的时区名称

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # 添加头像上传目录
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # 允许的文件扩展名

# 初始化组件
db.init_app(app)
login_manager.init_app(app)

with app.app_context():
    db.create_all()

# 检查文件扩展名是否允许
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        account_name = request.form['account_name']  # 修改为 account_name
        password = request.form['password']
        user = User.query.filter_by(account_name=account_name).first()  # 修改为 account_name
        if user and user.password == password:
            login_user(user, remember=True)  # 使用 remember=True 保持登录状态
            session.permanent = True  # 设置 session 为持久化
            app.permanent_session_lifetime = timedelta(hours=24)  # 设置 session 有效期为 24 小时
            return jsonify({"redirect": url_for('index')})
        return jsonify({"error": "账户名或密码错误"})
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        account_name = request.form['account_name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']  # 新增密码确认
        nickname = request.form['nickname']  # 新增昵称

        # 校验密码和确认密码是否一致
        if password != confirm_password:
            return jsonify({"error": "两次输入的密码不一致"})

        # 校验账户名是否已存在
        if User.query.filter_by(account_name=account_name).first():
            return jsonify({"error": "账户名已存在"})

        # 校验昵称是否已存在
        if User.query.filter_by(nickname=nickname).first():
            return jsonify({"error": "昵称已被使用"})

        # 创建新用户
        new_user = User(account_name=account_name, password=password, nickname=nickname)
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

@app.route('/update_timezone', methods=['POST'])
@login_required
def update_timezone():
    data = request.json
    new_timezone = data.get('timezone')
    if new_timezone in pytz.all_timezones:  # 检查时区是否有效
        current_user.timezone = new_timezone
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False})

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({"error": "未上传文件"}), 400
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({"error": "未选择文件"}), 400
    if file and allowed_file(file.filename):
        # 使用正斜杠（/）确保路径正确
        filename = f"user_{current_user.id}_avatar.{file.filename.rsplit('.', 1)[1].lower()}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # 保存相对路径到数据库，确保路径使用正斜杠
        relative_path = os.path.join('uploads', filename).replace("\\", "/")  # 替换反斜杠为正斜杠
        current_user.avatar = relative_path
        db.session.commit()

        return jsonify({"avatar_url": url_for('static', filename=relative_path)})
    return jsonify({"error": "文件格式不支持"}), 400

@app.route('/account_security')
@login_required
def account_security():
    return render_template('account_security.html', user=current_user)



@app.route('/update_nickname', methods=['POST'])
@login_required
def update_nickname():
    new_nickname = request.form.get('new_nickname')
    if not new_nickname:
        return jsonify({"success": False, "message": "昵称不能为空"})
    if User.query.filter_by(nickname=new_nickname).first():
        return jsonify({"success": False, "message": "昵称已被使用"})
    current_user.nickname = new_nickname
    db.session.commit()
    return jsonify({"success": True, "message": "昵称更新成功"})

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    if not new_password or not confirm_password:
        return jsonify({"success": False, "message": "密码不能为空"})
    if new_password != confirm_password:
        return jsonify({"success": False, "message": "两次输入的密码不一致"})

    # 更新密码
    current_user.password = new_password
    db.session.commit()

    # 自动登出用户
    logout_user()

    return jsonify({"success": True, "message": "密码更新成功，请重新登录"})

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        # 删除当前用户
        db.session.delete(current_user)
        db.session.commit()
        logout_user()  # 注销登录
        return jsonify({"success": True, "message": "账户已注销，您将被重定向到登录页面"})
    except Exception as e:
        return jsonify({"success": False, "message": "注销失败，请稍后再试"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8462)