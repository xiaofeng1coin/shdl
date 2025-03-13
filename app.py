# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user, LoginManager
from models import db, User, Link, LoginLog, ClickLog  # 确保导入 LoginLog
from auth import login_manager
from datetime import datetime, timedelta, time
from sqlalchemy import func, desc
import secrets
import pytz
from user_agents import parse  # 导入 user_agents 库
import requests  # 导入 requests 库
from sqlalchemy.orm import joinedload
import logging
from apscheduler.schedulers.background import BackgroundScheduler  # 导入 APScheduler
from pytz import timezone
from models import db, User, Link, LoginLog, ClickLog, Domain  # 确保导入 Domain


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# 获取项目根目录的绝对路径
basedir = os.path.abspath(os.path.dirname(__file__))

# 使用绝对路径指定数据库文件
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
# 设置默认时区为北京时间
app.config['TIMEZONE'] = pytz.timezone('Asia/Shanghai')
# 从环境变量中读取安全入口路径，不允许设置默认值
app.config['SECURE_ENTRY_PATH'] = os.getenv('SECURE_ENTRY_PATH')
if not app.config['SECURE_ENTRY_PATH']:
    raise ValueError("SECURE_ENTRY_PATH environment variable is not set. Please set it before running the application.")

# 初始化组件
db.init_app(app)
login_manager.init_app(app)

with app.app_context():
    db.create_all()

# 配置日志
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# 检查文件扩展名是否允许
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    return "访问被拒绝，请通过安全入口访问", 403

@app.route(app.config['SECURE_ENTRY_PATH'])
def secure_entry():
    # 设置一个标志，表示用户已经通过安全入口访问
    session['secure_entry'] = True
    return redirect(url_for('login'))


# 替换为 Vore API 的配置
VORE_API_URL = "https://api.vore.top/api/IPdata?ip={ip}"


def get_real_ip():
    """获取真实的客户端 IP 地址"""
    if request.headers.getlist("X-Forwarded-For"):
        # 获取 X-Forwarded-For 中的第一个 IP 地址（客户端的真实 IP）
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        # 如果没有 X-Forwarded-For，直接使用远程地址
        return request.remote_addr


def get_login_location(ip):
    """根据 IP 地址获取登录地址"""
    if ip.startswith("127.0.0.1") or ip.startswith("192.168"):
        return "本地"

    try:
        response = requests.get(VORE_API_URL.format(ip=ip))
        response.raise_for_status()
        location_data = response.json()

        if location_data.get("code") == 200:
            # 从返回的 JSON 数据中提取地理位置信息
            ipdata = location_data.get("ipdata", {})
            region = ipdata.get("info1", "")  # 省份
            city = ipdata.get("info2", "")   # 城市
            district = ipdata.get("info3", "")  # 区/县

            # 组合地理位置信息
            if district:
                location = f"{region} {city} {district}"
            elif city:
                location = f"{region} {city}"
            else:
                location = region or "未知"
            return location
        else:
            print(f"API Error: {location_data.get('msg', 'Unknown error')}")
            return "未知"
    except requests.RequestException as e:
        print(f"Error fetching location data: {e}")
        return "未知"

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 检查是否通过安全入口访问
    if not session.get('secure_entry'):
        return "访问被拒绝，请通过安全入口访问", 403

    if request.method == 'GET':
        session['can_register'] = True
        return render_template('login.html')
    if request.method == 'POST':
        account_name = request.form['account_name']
        password = request.form['password']
        user = User.query.filter_by(account_name=account_name).first()
        if not user:
            return jsonify({"error": "账户不存在"})
        if user.password != password:
            login_location = get_login_location(get_real_ip())
            login_log = LoginLog(
                user_id=user.id,
                login_time=datetime.now(pytz.timezone('Asia/Shanghai')),
                ip_address=get_real_ip(),
                device_info="未知",
                login_status="失败",
                login_location=login_location
            )
            db.session.add(login_log)
            db.session.commit()
            print(f"Login failed for user {user.account_name} from IP {get_real_ip()}")
            return jsonify({"error": "密码错误"})
        login_user(user, remember=True)
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=24)
        user_ip = get_real_ip()
        login_location = get_login_location(user_ip)
        user_agent = request.headers.get('User-Agent')
        parsed_agent = parse(user_agent)
        device_type = parsed_agent.os.family
        login_log = LoginLog(
            user_id=user.id,
            login_time=datetime.now(pytz.timezone('Asia/Shanghai')),
            ip_address=user_ip,
            device_info=device_type,
            login_status="成功",
            login_location=login_location
        )
        db.session.add(login_log)
        db.session.commit()
        print(f"Login successful for user {user.account_name} from IP {user_ip}")
        if user.is_superuser:
            return jsonify({"redirect": url_for('user_management')})
        else:
            return jsonify({"redirect": url_for('index')})
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not session.get('can_register'):
        return "您没有权限访问此页面", 403
    if request.method == 'POST':
        account_name = request.form['account_name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        nickname = request.form['nickname']
        if password != confirm_password:
            return jsonify({"error": "两次输入的密码不一致"})
        if User.query.filter_by(account_name=account_name).first():
            return jsonify({"error": "账户名已存在"})
        if User.query.filter_by(nickname=nickname).first():
            return jsonify({"error": "昵称已被使用"})
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
    current_month = datetime.now(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m')
    monthly_links = Link.query.filter(
        Link.user_id == current_user.id,
        func.strftime('%Y-%m', Link.created_at) == current_month
    ).count()

    yesterday = datetime.now(pytz.timezone('Asia/Shanghai')) - timedelta(days=1)
    yesterday_date = yesterday.date()
    yesterday_links = Link.query.filter(
        Link.user_id == current_user.id,
        func.date(Link.created_at) == yesterday_date
    ).count()

    today_date = datetime.now(pytz.timezone('Asia/Shanghai')).date()
    today_links = Link.query.filter(
        Link.user_id == current_user.id,
        func.date(Link.created_at) == today_date
    ).count()

    update_time = datetime.now(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')

    # 查询最近的短链接，并包含 selected_domain 字段
    recent_links = Link.query.filter_by(user_id=current_user.id).order_by(Link.created_at.desc()).limit(20).all()

    return render_template('index.html',
                           total_links=total_links,
                           monthly_links=monthly_links,
                           yesterday_links=yesterday_links,
                           today_links=today_links,
                           update_time=update_time,
                           recent_links=recent_links)

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
        app.logger.debug(f"Short code: {short_code}, Link found: {link}")
        try:
            # 更新点击量
            link.clicks += 1
            db.session.commit()
            app.logger.debug(f"Updating clicks for link ID {link.id} from {link.clicks - 1} to {link.clicks}")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating click count: {e}")
            return f"Error updating click count: {e}", 500

        try:
            # 记录点击日志到 ClickLog 表
            current_time = datetime.now(app.config['TIMEZONE'])  # 使用配置的时区
            new_click_log = ClickLog(
                link_id=link.id,
                click_time=datetime.now(pytz.timezone('Asia/Shanghai'))
            )
            db.session.add(new_click_log)
            db.session.commit()
            app.logger.debug(f"Creating click log for link ID {link.id} at {current_time}")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating click log: {e}")
            return f"Error creating click log: {e}", 500

        # 重定向到原始链接
        return redirect(link.original_url)
    else:
        app.logger.warning(f"Short link not found: {short_code}")
        return "Short link not found", 404


@app.route('/stats/<short_code>')
@login_required
def link_stats(short_code):
    #app.logger.debug(f"Fetching link with short_code: {short_code}")
    link = Link.query.filter_by(short_code=short_code).first()
    if not link:
        #app.logger.debug("Link not found")
        return "Link not found", 404

    #app.logger.debug("Link found")
    now = datetime.now(app.config['TIMEZONE'])
    today = now.date()

    # 获取最近9天的日期范围（从今天开始往前推8天）
    date_range = [(today - timedelta(days=i)) for i in range(0, 9)]
    date_range_str = [date.strftime('%Y-%m-%d') for date in date_range]
    #app.logger.debug(f"Date range: {date_range_str}")

    # 计算最近9天的起始日期（最早日期）
    query_start = date_range[-1].strftime('%Y-%m-%d')
    #app.logger.debug(f"Query start date: {query_start}")

    # 使用原生SQL查询每个日期的点击量
    query = f"""
    SELECT strftime('%Y-%m-%d', click_time) AS day, COUNT(*) AS click_count 
    FROM click_log 
    WHERE link_id = {link.id} AND click_time >= '{query_start} 00:00:00' 
    GROUP BY day 
    ORDER BY day;
    """
    app.logger.debug(f"Executing raw SQL query: {query}")
    result = db.session.execute(query)
    clicks_by_day = result.fetchall()
    #app.logger.debug(f"Clicks by day query result: {clicks_by_day}")

    # 将查询结果转换为字典
    clicks_dict = {row[0]: row[1] for row in clicks_by_day}
    #app.logger.debug(f"Clicks dictionary: {clicks_dict}")

    # 生成完整的日期和点击量数据
    days = []
    clicks = []
    for date in date_range_str:
        days.append(date)
        clicks.append(clicks_dict.get(date, 0))  # 如果某天没有数据，则点击量为0
        #app.logger.debug(f"Date: {date}, Clicks: {clicks_dict.get(date, 0)}")

    #app.logger.debug(f"Days: {days}, Clicks: {clicks}")

    # 在渲染模板时反转日期和点击量列表
    days.reverse()
    clicks.reverse()

    # 查询昨日和今日的点击量
    yesterday = today - timedelta(days=1)
    yesterday_start = datetime.combine(yesterday, time.min).astimezone(app.config['TIMEZONE'])
    yesterday_end = datetime.combine(yesterday, time.max).astimezone(app.config['TIMEZONE'])
    yesterday_clicks = ClickLog.query.filter(
        ClickLog.link_id == link.id,
        ClickLog.click_time >= yesterday_start,
        ClickLog.click_time <= yesterday_end
    ).count()
    #app.logger.debug(f"Yesterday clicks: {yesterday_clicks}")

    today_start = datetime.combine(today, time.min).astimezone(app.config['TIMEZONE'])
    today_end = datetime.combine(today, time.max).astimezone(app.config['TIMEZONE'])
    today_clicks = ClickLog.query.filter(
        ClickLog.link_id == link.id,
        ClickLog.click_time >= today_start,
        ClickLog.click_time <= today_end
    ).count()
    #app.logger.debug(f"Today clicks: {today_clicks}")

    # 确保返回一个有效的响应
    return render_template('stats.html',
                           link=link,
                           yesterday_clicks=yesterday_clicks,
                           today_clicks=today_clicks,
                           days=days,
                           clicks=clicks)
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

    # 调试信息：打印接收到的密码
    app.logger.debug(f"Received new_password: {new_password}")
    app.logger.debug(f"Received confirm_password: {confirm_password}")

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
        print(f"Deleting user: {user.id} ({user.account_name})")

        # 删除与该用户关联的所有点击日志
        click_logs = ClickLog.query.filter(ClickLog.link_id.in_([link.id for link in user.links])).all()
        print(f"Deleting {len(click_logs)} click logs")
        ClickLog.query.filter(ClickLog.link_id.in_([link.id for link in user.links])).delete(synchronize_session=False)

        # 删除与该用户关联的所有短链接
        links = Link.query.filter_by(user_id=user.id).all()
        print(f"Deleting {len(links)} links")
        Link.query.filter_by(user_id=user.id).delete(synchronize_session=False)

        # 删除与该用户关联的所有登录日志
        login_logs = LoginLog.query.filter_by(user_id=user.id).all()
        print(f"Deleting {len(login_logs)} login logs")
        LoginLog.query.filter_by(user_id=user.id).delete(synchronize_session=False)

        # 提交删除操作，确保数据一致性
        db.session.commit()

        # 删除当前用户
        db.session.delete(user)
        db.session.commit()

        # 注销登录
        logout_user()
        return jsonify({"success": True, "message": "账户已注销，您将被重定向到登录页面"})
    except Exception as e:
        print(f"Error deleting account: {e}")  # 打印错误信息
        db.session.rollback()  # 回滚事务，防止部分删除
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
        try:
            # 删除相关的 ClickLog 记录
            ClickLog.query.filter_by(link_id=link.id).delete()
            db.session.delete(link)
            db.session.commit()
            return jsonify({"success": True, "message": "短链接已删除"})
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Failed to delete link: {e}")
            return jsonify({"success": False, "message": "删除失败，请稍后再试"}), 500
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

    if custom_suffix and Link.query.filter_by(short_code=custom_suffix).first():
        return jsonify({"success": False, "message": "自定义后缀已存在"})

    # 生成短链接
    short_code = custom_suffix or secrets.token_urlsafe(4)

    # 创建新的短链接，显式设置时间
    created_at = datetime.now(app.config['TIMEZONE']).replace(second=0, microsecond=0)  # 去掉秒和微秒
    new_link = Link(
        original_url=original_url,
        short_code=short_code,
        user_id=current_user.id,
        created_at=created_at
    )
    db.session.add(new_link)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "短链接已创建",
        "link": {
            "short_code": new_link.short_code,
            "original_url": new_link.original_url,
            "clicks": new_link.clicks,
            "created_at": created_at.strftime('%Y-%m-%d %H:%M')  # 返回格式化的时间
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
    # 查询当前用户的登录日志（只保留最近半个月的数据）
    half_month_ago = datetime.now(pytz.timezone('Asia/Shanghai')) - timedelta(days=15)
    login_logs = LoginLog.query.filter_by(user_id=current_user.id).filter(LoginLog.login_time >= half_month_ago).order_by(desc(LoginLog.login_time)).all()
    return render_template('login_log.html', login_logs=login_logs)

# app.py
@app.route('/superuser_login_log')
@login_required
def superuser_login_log():
    if not current_user.is_superuser:
        return "您没有权限访问此页面", 403

    # 查询所有用户的登录日志（只保留最近半个月的数据）
    half_month_ago = datetime.now(pytz.timezone('Asia/Shanghai')) - timedelta(days=15)
    login_logs = db.session.query(LoginLog).options(joinedload(LoginLog.user)).filter(LoginLog.login_time >= half_month_ago).order_by(desc(LoginLog.login_time)).all()
    return render_template('superuser_login_log.html', login_logs=login_logs)

def cleanup_login_logs():
    """清理超过半个月的登录日志"""
    half_month_ago = datetime.now(pytz.timezone('Asia/Shanghai')) - timedelta(days=15)
    LoginLog.query.filter(LoginLog.login_time < half_month_ago).delete()
    db.session.commit()
    print("Cleaned up old login logs")

# 设置定时任务，每天凌晨清理日志
scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_login_logs, trigger='cron', hour=0, minute=0, timezone=timezone('Asia/Shanghai'))
scheduler.start()

def cleanup_clicks_at():
    # 计算10天前的时间
    ten_days_ago = datetime.now(pytz.timezone('Asia/Shanghai')) - timedelta(days=10)
    # 删除超过10天的点击记录
    Link.query.filter(Link.clicks_at < ten_days_ago).update({"clicks_at": None})
    db.session.commit()
    print("Cleaned up old clicks_at records")

# 添加定时任务，每天凌晨清理
scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_clicks_at, trigger='cron', hour=0, minute=0, timezone=timezone('Asia/Shanghai'))
scheduler.start()

@app.before_request
def check_secure_entry():
    request_path = request.path

    # 获取所有短链后缀，并统一处理为带斜杠的形式
    allowed_short_codes = [f"/{link.short_code.strip('/')}" for link in Link.query.with_entities(Link.short_code).all()]

    # 允许的路径列表
    allowed_paths = [
        app.config['SECURE_ENTRY_PATH'],
        '/static/',
        '/favicon.ico',
        *allowed_short_codes
    ]

    # 检查请求路径是否在允许的路径列表中
    if request_path not in allowed_paths and not request_path.startswith('/static/'):
        if not session.get('secure_entry'):
            return "访问被拒绝，请通过安全入口访问", 403


# 域名管理页面
@app.route('/domain_management')
@login_required
def domain_management():
    # 获取用户的所有自定义域名
    domains = Domain.query.filter_by(user_id=current_user.id).all()
    return render_template('domain_management.html', domains=domains)

# 添加自定义域名
@app.route('/add_domain', methods=['POST'])
@login_required
def add_domain():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({"success": False, "message": "域名不能为空"})
    if Domain.query.filter_by(domain=domain, user_id=current_user.id).first():
        return jsonify({"success": False, "message": "该域名已存在"})
    new_domain = Domain(domain=domain, user_id=current_user.id)
    db.session.add(new_domain)
    db.session.commit()
    return jsonify({"success": True, "message": "域名添加成功"})

# 更新自定义域名
@app.route('/update_domain', methods=['POST'])
@login_required
def update_domain():
    domain_id = request.form.get('domain_id')
    new_domain = request.form.get('new_domain')
    if not domain_id or not new_domain:
        return jsonify({"success": False, "message": "参数错误"})
    domain = Domain.query.filter_by(id=domain_id, user_id=current_user.id).first()
    if not domain:
        return jsonify({"success": False, "message": "域名不存在"})
    domain.domain = new_domain
    db.session.commit()
    return jsonify({"success": True, "message": "域名更新成功"})

# 删除自定义域名
@app.route('/delete_domain', methods=['POST'])
@login_required
def delete_domain():
    domain_id = request.form.get('domain_id')
    if not domain_id:
        return jsonify({"success": False, "message": "参数错误"})
    domain = Domain.query.filter_by(id=domain_id, user_id=current_user.id).first()
    if not domain:
        return jsonify({"success": False, "message": "域名不存在"})
    db.session.delete(domain)
    db.session.commit()
    return jsonify({"success": True, "message": "域名删除成功"})

@app.route('/save_domain_choice', methods=['POST'])
@login_required
def save_domain_choice():
    data = request.json
    short_code = data.get('short_code')
    selected_domain = data.get('selected_domain')

    link = Link.query.filter_by(short_code=short_code, user_id=current_user.id).first()
    if link:
        link.selected_domain = selected_domain  # 假设 Link 模型中有一个字段 selected_domain
        db.session.commit()
        return jsonify({"success": True, "message": "域名选择已保存"})
    else:
        return jsonify({"success": False, "message": "短链接不存在或您无权修改"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8462, debug=False)