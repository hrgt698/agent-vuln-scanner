# 使用轻量级的 Python 3.10 环境
FROM python:3.10-slim

# 设置容器内的工作目录
WORKDIR /app

# 创建非 root 用户（安全最佳实践）
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# 【关键修复】：slim 镜像默认没有 ping 命令，必须手动安装以支撑 CWE-78 靶标
# 安装完毕后清理 apt 缓存，保持镜像极简
RUN apt-get update && \
    apt-get install -y iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# 使用清华源加速安装 FastAPI 和 Uvicorn
RUN pip install fastapi uvicorn -i https://pypi.tuna.tsinghua.edu.cn/simple

# 把刚刚写好的 target_api.py 复制到容器里，并重命名为 main.py
COPY target_api.py /app/main.py

# 设置目录权限
RUN chown -R appuser:appgroup /app

# 切换为非 root 用户
USER appuser

# 暴露 18789 端口
EXPOSE 18789

# 启动靶机服务（绑定 127.0.0.1 仅监听本地）
CMD ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "18789"]