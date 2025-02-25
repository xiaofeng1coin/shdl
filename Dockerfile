FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8462
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]  # 修改启动命令