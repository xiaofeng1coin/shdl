# 基于Python官方镜像构建
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 将项目中的 requirements.txt 文件复制到容器的工作目录
COPY shdl/requirements.txt .

# 安装项目所需的依赖包
RUN pip install --no-cache-dir -r requirements.txt

# 将整个项目复制到容器的工作目录
COPY shdl/ .

# 设置环境变量
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8462

# 暴露端口
EXPOSE 8462

# 定义容器启动时执行的命令
CMD ["flask", "run"]