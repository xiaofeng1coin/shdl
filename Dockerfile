# 基于 Python 3.9 镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 设置 PATH 环境变量（假设 gunicorn 在虚拟环境中）
ENV PATH="/path/to/your/virtualenv/bin:${PATH}"

# 复制项目文件和安装依赖
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# 启动命令
CMD ["gunicorn", "-b", "0.0.0.0:8462", "app:app"]