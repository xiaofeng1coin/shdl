FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# 添加调试信息，查看 pip install 的输出
RUN pip install --no-cache-dir -r requirements.txt || (echo "pip install failed" && exit 1)

EXPOSE 8462
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]  # 修改启动命令