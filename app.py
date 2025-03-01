# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user, LoginManager
from models import db, User, Link, LoginLog  # 确保导入 LoginLog
from auth import login_manager
from datetime import datetime, timedelta
from sqlalchemy import func, desc
import secrets
import pytz
from user_agents import parse  # 导入 user_agents 库
import requests  # 导入 requests 库
from sqlalchemy.orm import joinedload
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

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


# IPinfo API 配置
IPINFO_API_KEY = "281293911c5b75"  # 替换为你的 IPinfo API 密钥
IPINFO_URL = "https://ipinfo.io/{ip}/json?token={token}"


def get_real_ip():
    """获取真实的客户端 IP 地址"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr


def get_login_location(ip):
    """根据 IP 地址获取登录地址"""
    if ip.startswith("127.0.0.1") or ip.startswith("192.168"):
        return "本地"

    try:
        response = requests.get(IPINFO_URL.format(ip=ip, token=IPINFO_API_KEY))
        response.raise_for_status()
        location_data = response.json()
        return f"{location_data.get('region', '未知')} {location_data.get('city', '未知')}"
    except requests.RequestException as e:
        print(f"Error fetching location data: {e}")
        return "未知"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        account_name = request.form['account_name']
        password = request.form['password']

        # 查询用户是否存在
        user = User.query.filter_by(account_name=account_name).first()
        if not user:
            return jsonify({"error": "账户不存在"})

        # 检查密码是否正确
        if user.password != password:
            # 记录登录失败的日志
            user_ip = get_real_ip()
            login_location = get_login_location(user_ip)
            login_log = LoginLog(
                user_id=user.id,
                login_time=datetime.now(),
                ip_address=user_ip,
                device_info="未知",  # 可以选择不解析 User-Agent 或设置为默认值
                login_status="失败",
                login_location=login_location
            )
            db.session.add(login_log)
            db.session.commit()
            print(f"Login failed for user {user.account_name} from IP {user_ip}")  # 调试信息
            return jsonify({"error": "密码错误"})

        # 登录成功
        login_user(user, remember=True)
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=24)

        # 获取用户的 IP 地址和登录地址
        user_ip = get_real_ip()
        login_location = get_login_location(user_ip)

        # 获取 User-Agent 信息
        user_agent = request.headers.get('User-Agent')
        parsed_agent = parse(user_agent)
        device_type = parsed_agent.os.family

        # 记录登录成功的日志
        login_log = LoginLog(
            user_id=user.id,
            login_time=datetime.now(),
            ip_address=user_ip,
            device_info=device_type,
            login_status="成功",
            login_location=login_location
        )
        db.session.add(login_log)
        db.session.commit()
        print(f"Login successful for user {user.account_name} from IP {user_ip}")  # 调试信息

        # 重定向
        if user.is_superuser:
            return jsonify({"redirect": url_for('user_management')})
        else:
            return jsonify({"redirect": url_for('index')})
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
def redirect_to_original(short_code):
    link = Link.query.filter_by(short_code=short_code).first()
    if link:
        # 更新点击量
        link.clicks += 1
        link.clicks_at = datetime.now()
        db.session.commit()
        return redirect(link.original_url)
    else:
        return "Short link not found", 404

@app.route('/stats/<short_code>')
@login_required
def link_stats(short_code):
    link = Link.query.filter_by(short_code=short_code).first()
    if not link:
        return "Link not found", 404

    # 获取当前日期
    today = datetime.now().date()
    # 生成日期范围（从今日开始，往前推8天）
    date_range = [(today - timedelta(days=i)) for i in range(8, -1, -1)]
    date_range_str = [date.strftime('%Y-%m-%d') for date in date_range]

    # 查询每个日期的点击量
    clicks_by_day = db.session.query(
        func.date(Link.clicks_at).label('day'),
        func.sum(Link.clicks).label('click_count')  # 统计每天的点击量
    ).filter(
        Link.short_code == short_code,
        Link.clicks_at >= date_range[-1]  # 只查询最近9天的数据
    ).group_by('day').order_by('day').all()

    # 将查询结果转换为字典
    clicks_dict = {day: count for day, count in clicks_by_day}

    # 生成完整的日期和点击量数据
    days = []
    clicks = []
    for date in date_range_str:
        days.append(date)
        clicks.append(clicks_dict.get(date, 0))  # 如果某天没有数据，则点击量为0

    # 获取总点击量
    total_clicks = link.clicks  # 使用Link模型中的clicks字段

    return render_template('stats.html',
                           link=link,
                           days=days,
                           clicks=clicks,
                           total_clicks=total_clicks)  # 将总点击量传递到前端
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
        # 获取当前用户
        user = current_user

        # 删除与该用户关联的所有登录日志
        LoginLog.query.filter_by(user_id=user.id).delete()

        # 删除当前用户
        db.session.delete(user)
        db.session.commit()

        # 注销登录
        logout_user()
        return jsonify({"success": True, "message": "账户已注销，您将被重定向到登录页面"})
    except Exception as e:
        print(f"Error deleting account: {e}")  # 打印错误信息
        return jsonify({"success": False, "message": "注销失败，请稍后再试"})

@app.route('/delete_link', methods=['POST'])
@login_required
def delete_link():
    data = request.json
    short_code = data.get('short_code')
    if not short_code:
        return jsonify({"success": False, "message": "无效的短链接代码"})

    link = Link.query.filter_by(short_code=short_code, user_id=current_user.id).first()
    if link:
        db.session.delete(link)
        db.session.commit()  # 确保提交事务
        return jsonify({"success": True, "message": "短链接已删除"})
    else:
        return jsonify({"success": False, "message": "短链接不存在或您无权删除"})

@app.route('/update_link', methods=['POST'])
@login_required
def update_link():
    data = request.json
    short_code = data.get('short_code')
    new_original_url = data.get('original_url')
    new_custom_suffix = data.get('custom_suffix')

    link = Link.query.filter_by(short_code=short_code, user_id=current_user.id).first()
    if not link:
        return jsonify({"success": False, "message": "链接不存在或您无权修改"})

    # 检查自定义后缀是否冲突
    if new_custom_suffix != link.short_code and Link.query.filter_by(short_code=new_custom_suffix).first():
        return jsonify({"success": False, "message": "自定义后缀已存在"})

    # 更新链接信息
    link.original_url = new_original_url
    link.short_code = new_custom_suffix
    db.session.commit()

    return jsonify({"success": True, "message": "链接已更新"})

@app.route('/create_link', methods=['POST'])
@login_required
def create_link():
    data = request.json
    original_url = data.get('original_url')
    custom_suffix = data.get('custom_suffix')

    if not original_url:
        return jsonify({"success": False, "message": "长链接不能为空"})

    # 检查自定义后缀是否冲突
    if custom_suffix and Link.query.filter_by(short_code=custom_suffix).first():
        return jsonify({"success": False, "message": "自定义后缀已存在"})

    # 生成短链接
    short_code = custom_suffix or secrets.token_urlsafe(4)

    # 创建新的短链接
    new_link = Link(
        original_url=original_url,
        short_code=short_code,
        user_id=current_user.id
    )
    db.session.add(new_link)
    db.session.commit()

    # 返回新创建的短链数据
    return jsonify({
        "success": True,
        "message": "短链接已创建",
        "link": {
            "short_code": new_link.short_code,
            "original_url": new_link.original_url,
            "clicks": new_link.clicks,
            "created_at": new_link.created_at.strftime('%Y-%m-%d')
        }
    })

@app.route('/user_management')
@login_required
def user_management():
    if not current_user.is_superuser:
        return "您没有权限访问此页面", 403

    # 查询所有普通用户及其短链数量，排除超级用户
    users = User.query.outerjoin(Link).group_by(User.id).with_entities(
        User.id,
        User.account_name,
        User.nickname,
        User.register_time,
        func.count(Link.id).label('link_count')
    ).filter(User.is_superuser == False).all()

    # 重新编号用户 ID（从 1 开始）
    user_list = []
    for index, user in enumerate(users, start=1):
        user_list.append({
            "display_id": index,  # 重新编号的用户 ID
            "id": user.id,  # 数据库中的用户 ID
            "account_name": user.account_name,
            "nickname": user.nickname,
            "register_time": user.register_time,
            "link_count": user.link_count
        })

    return render_template('user_management.html', users=user_list)

@app.route('/update_user_password', methods=['POST'])
@login_required
def update_user_password():
    if not current_user.is_superuser:
        return jsonify({"success": False, "message": "您没有权限执行此操作"}), 403
    data = request.json
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    if not user_id or not new_password:
        return jsonify({"success": False, "message": "参数错误"})
    user = User.query.get(user_id)
    if user and not user.is_superuser:  # 确保不会修改超级用户的密码
        user.password = new_password
        db.session.commit()
        return jsonify({"success": True, "message": "密码修改成功"})
    return jsonify({"success": False, "message": "用户不存在或无法修改"})

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_superuser:
        return jsonify({"success": False, "message": "您没有权限执行此操作"}), 403

    user = User.query.get(user_id)
    if user:
        try:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"success": True, "message": "用户删除成功"})
        except Exception as e:
            return jsonify({"success": False, "message": "删除失败，请稍后再试"})
    else:
        return jsonify({"success": False, "message": "用户不存在"})

@app.route('/login_log')
@login_required
def login_log():
    # 查询当前用户的登录日志
    login_logs = LoginLog.query.filter_by(user_id=current_user.id).order_by(desc(LoginLog.login_time)).all()
    return render_template('login_log.html', login_logs=login_logs)

# app.py
@app.route('/superuser_login_log')
@login_required
def superuser_login_log():
    if not current_user.is_superuser:
        return "您没有权限访问此页面", 403

    # 查询所有用户的登录日志，并预加载关联的用户信息
    login_logs = db.session.query(LoginLog).options(joinedload(LoginLog.user)).order_by(desc(LoginLog.login_time)).all()
    return render_template('superuser_login_log.html', login_logs=login_logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8462)