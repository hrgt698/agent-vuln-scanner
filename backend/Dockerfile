# Agent Vulnerability Assessment Platform - Backend image
FROM python:3.10-slim

# 设置工作目录
WORKDIR /app

# 创建非 root 用户（安全最佳实践）
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# 安装系统依赖（用于漏洞靶机模拟）
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt ./requirements.txt

# 安装 Python 依赖（包含 JWT 支持）
RUN pip install --no-cache-dir -r requirements.txt

# 复制所有源代码
COPY . /app/

# 创建数据目录
RUN mkdir -p /app/data /app/data/vector_db

# 设置目录权限（为非 root 用户）
RUN chown -R appuser:appgroup /app

# 切换为非 root 用户
USER appuser

# 健康检查（使用 Python 而非 curl，确保非 root 环境可用）
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/status')" || exit 1

# 默认启动 FastAPI 后端
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
