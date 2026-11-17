"""
漏洞靶机应用
包含 4 类故意保留的教学漏洞（CS0048/CWE-89/CWE-78/AML.T0051）
此文件用于构建 Dockerfile.target，生产环境请勿部署。

【警告】此文件包含故意设计的漏洞，仅供教学和授权的安全测试使用。

v3.0 变更：
- 所有敏感信息默认值改为 "__REQUIRED__" 占位符，避免意外暴露
- 启动时自动检测占位符是否未被替换，并打印明确的安全警告
- 敏感信息必须通过 docker run -e 或 docker-compose.yml 显式注入

v3.1 变更（教学模式漏洞生命周期管理）：
- 新增 --expire-seconds / TARGET_EXPIRE_SECONDS 教学会话自动过期
- 新增 /api/v1/health/status 状态端点
- 新增独立安全日志 target_security.log
- 新增 /api/v1/admin/terminate-session 管理员终止端点
"""

import os
import sys
import json
import time
import threading
import warnings
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone, timedelta

# ============================================================
# 【重要】教学靶机敏感信息配置
# v3.0：未配置时使用 __REQUIRED__ 占位符（避免意外暴露教学凭证）
# 生产部署时通过 docker run -e 或 docker-compose.yml 注入真实值
# ============================================================
_Target_MODE = os.environ.get("TARGET_MODE", "teaching").lower()

# v3.1：教学会话自动过期时间（秒），默认 1800 = 30 分钟
_TARGET_EXPIRE_SECONDS = int(os.environ.get("TARGET_EXPIRE_SECONDS", "1800"))

# v3.2：教学靶机单会话最大请求数（避免滥用），默认 500
_TARGET_MAX_REQUESTS = int(os.environ.get("TARGET_MAX_REQUESTS", "500"))

# v3.1：教学管理员 Token（用于 terminate-session 等管理接口）
_TEACHING_ADMIN_TOKEN = os.environ.get(
    "TEACHING_ADMIN_TOKEN",
    "assessment-teaching-admin-token-demo-only",
)

# ============================================================
# v3.2 新增：安全日志轮转处理器（单文件 10MB，保留 5 份备份）
# 避免长期运行导致磁盘膨胀
# ============================================================
_security_logger = logging.getLogger("assessment.target_security")
_security_logger.setLevel(logging.INFO)
_security_logger.propagate = False  # 避免被父 logger 重复输出
try:
    _log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(_log_dir, exist_ok=True)
    _log_handler = RotatingFileHandler(
        os.path.join(_log_dir, "target_security.log"),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8",
    )
    _log_handler.setFormatter(logging.Formatter("%(message)s"))  # JSON 行纯文本
    _security_logger.addHandler(_log_handler)
except Exception:
    # 日志初始化失败不影响主业务，回退到无操作
    _log_handler = None

# Flag 值（通过环境变量注入）
FLAG_CONFIG = {
    "CS0048": os.environ.get("FLAG_CS0048", "__REQUIRED__"),
    "CWE-78": os.environ.get("FLAG_CWE78", "__REQUIRED__"),
    "CWE-89": os.environ.get("FLAG_CWE89", "__REQUIRED__"),
    "AML.T0051": os.environ.get("FLAG_AML", "__REQUIRED__"),
}

# API 配置泄露内容（通过环境变量注入）
CONFIG_SECRETS = {
    "db_password": os.environ.get("TARGET_DB_PASSWORD", "__REQUIRED__"),
    "api_key": os.environ.get("TARGET_API_KEY", "__REQUIRED__"),
    "jwt_secret": os.environ.get("TARGET_JWT_SECRET", "__REQUIRED__"),
    "aws_access_key": os.environ.get("TARGET_AWS_ACCESS_KEY", "__REQUIRED__"),
    "aws_secret_key": os.environ.get("TARGET_AWS_SECRET_KEY", "__REQUIRED__"),
}

# SQL 注入泄漏数据（通过环境变量注入）
SQL_LEAK_DATA = {
    "admin_email": os.environ.get("TARGET_ADMIN_EMAIL", "__REQUIRED__"),
    "admin_secret": os.environ.get("TARGET_ADMIN_SECRET", "__REQUIRED__"),
}

# Prompt 注入泄漏数据（通过环境变量注入）
PROMPT_LEAK_DATA = {
    "jwt_secret": os.environ.get("TARGET_JWT_SECRET_LEAK", "__REQUIRED__"),
    "internal_token": os.environ.get("TARGET_INTERNAL_TOKEN", "__REQUIRED__"),
}

# 合法管理员账户（通过环境变量注入）
LEGIT_ADMIN = {
    "username": os.environ.get("TARGET_ADMIN_USER", "__REQUIRED__"),
    "password": os.environ.get("TARGET_ADMIN_PASS", "__REQUIRED__"),
    "token": os.environ.get("TARGET_ADMIN_TOKEN", "__REQUIRED__"),
}


# ============================================================
# v3.1 新增：教学模式会话生命周期全局状态
# ============================================================
_teaching_session_expired = False
_session_started_at = None
_session_expires_at = None
_expiry_lock = threading.Lock()

# v3.2：教学靶机请求计数器 + 速率限制
_total_requests = 0
_request_counter_lock = threading.Lock()


# ============================================================
# v3.2 改进：安全日志（RotatingFileHandler，10MB x 5份备份）
# 写入 ./data/target_security.log，格式为 JSON 行
# ============================================================
def _log_security_event(event_type, details=None):
    """将安全事件写入带轮转的 target_security.log 文件

    参数:
        event_type: 事件类型（如 startup / vuln_access / expired /
                    terminate / rate_limit_hit 等）
        details:    附加细节 dict（可含 vuln_type / client_ip / endpoint 等）
    """
    try:
        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "event": event_type,
        }
        if details:
            entry.update(details)
        _security_logger.info(json.dumps(entry, ensure_ascii=False))
    except Exception:
        # 日志写入失败不影响主业务
        pass


def _hit_request_limit() -> bool:
    """v3.2：请求计数器 — 达到 TARGET_MAX_REQUESTS 时返回 True 并置会话过期

    返回:
        bool: 若本次调用触发了请求数限制（刚达到上限），返回 True；否则 False
    """
    global _total_requests, _teaching_session_expired
    with _request_counter_lock:
        _total_requests += 1
        if _total_requests >= _TARGET_MAX_REQUESTS and not _teaching_session_expired:
            _teaching_session_expired = True
            _log_security_event(
                "rate_limit_hit",
                {"reason": "max_requests_reached", "limit": _TARGET_MAX_REQUESTS},
            )
            print(
                "\n" + "=" * 70 + "\n"
                f"⚠️  [Rate Limit] 已达到教学靶机最大请求数 {_TARGET_MAX_REQUESTS}，"
                f"漏洞端点将被关闭\n" + "=" * 70 + "\n"
            )
            return True
        return False


def _get_client_ip(request):
    """从请求中提取客户端 IP（辅助函数）"""
    try:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"


# ============================================================
# v3.0 新增：启动安全校验
# 检测是否仍使用 __REQUIRED__ 占位符，是则打印安全警告
# ============================================================
def _validate_secrets_on_startup():
    """启动时安全校验：检测 __REQUIRED__ 占位符"""
    has_placeholder = False
    placeholder_items = []

    all_configs = {
        "FLAG_CONFIG": FLAG_CONFIG,
        "CONFIG_SECRETS": CONFIG_SECRETS,
        "SQL_LEAK_DATA": SQL_LEAK_DATA,
        "PROMPT_LEAK_DATA": PROMPT_LEAK_DATA,
        "LEGIT_ADMIN": LEGIT_ADMIN,
    }

    for section, data in all_configs.items():
        for key, value in data.items():
            if value == "__REQUIRED__":
                has_placeholder = True
                placeholder_items.append(f"{section}.{key}")

    if has_placeholder:
        # 教学模式：打印警告但继续运行（用于演示）
        if _Target_MODE == "production":
            # 真实生产环境：禁止启动
            print("\n" + "=" * 70)
            print("❌ 错误：TARGET_MODE=production 但存在 __REQUIRED__ 占位符")
            print("未配置的敏感项:")
            for item in placeholder_items:
                print(f"   - {item}")
            print("=" * 70 + "\n")
            sys.exit(1)
        else:
            # 教学模式：警告 + 替换为教学用占位符值
            print("\n" + "=" * 70)
            print("⚠️  警告：检测到 __REQUIRED__ 占位符，当前为教学模式")
            print("以下敏感项未配置，将使用教学演示值（仅用于漏洞验证）：")
            for item in placeholder_items[:10]:
                print(f"   - {item}")
            if len(placeholder_items) > 10:
                print(f"   ... 以及其他 {len(placeholder_items) - 10} 项")
            print("如需自定义，请通过 docker run -e KEY=value 显式配置")
            print("=" * 70 + "\n")
            # 替换为安全的教学演示值（不模仿真实密钥格式）
            _apply_demo_placeholders()


def _apply_demo_placeholders():
    """将 __REQUIRED__ 替换为安全的教学演示值"""
    for data in [FLAG_CONFIG, CONFIG_SECRETS, SQL_LEAK_DATA, PROMPT_LEAK_DATA, LEGIT_ADMIN]:
        for key, value in list(data.items()):
            if value == "__REQUIRED__":
                data[key] = f"DEMO_{key}_VALUE_FOR_TEACHING_ONLY"


# ============================================================
# v3.1 新增：教学模式会话过期计时器
# 在 _validate_secrets_on_startup() 成功后以守护线程启动
# ============================================================
def _start_expiry_timer():
    """启动教学模式会话倒计时，到期后设置全局过期标志

    - 仅在 teaching 模式下生效；production 模式不启用
    - 倒计时结束后打印警告日志，设置 _teaching_session_expired = True
    """
    global _session_started_at, _session_expires_at

    # 记录启动时间（UTC）
    now = datetime.now(timezone.utc)
    _session_started_at = now
    _session_expires_at = now + timedelta(seconds=_TARGET_EXPIRE_SECONDS)

    if _Target_MODE != "teaching":
        # 生产模式不启用自动过期
        _log_security_event(
            "startup",
            {
                "mode": _Target_MODE,
                "expire_seconds": 0,
                "started_at": _session_started_at.strftime("%Y-%m-%dT%H:%M:%S"),
            },
        )
        return

    _log_security_event(
        "startup",
        {
            "mode": _Target_MODE,
            "expire_seconds": _TARGET_EXPIRE_SECONDS,
            "started_at": _session_started_at.strftime("%Y-%m-%dT%H:%M:%S"),
            "expires_at": _session_expires_at.strftime("%Y-%m-%dT%H:%M:%S"),
        },
    )

    print(
        f"[TEACHING MODE] 教学演练会话将在 {_TARGET_EXPIRE_SECONDS} 秒后自动关闭 "
        f"（到期时间: {_session_expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}）"
    )

    def _timer_loop():
        """后台线程：倒计时到期后设置过期标志"""
        global _teaching_session_expired
        # 以 1 秒粒度循环，支持管理员提前终止
        for _ in range(_TARGET_EXPIRE_SECONDS):
            with _expiry_lock:
                if _teaching_session_expired:
                    return
            time.sleep(1)

        with _expiry_lock:
            if _teaching_session_expired:
                return
            _teaching_session_expired = True

        msg = "⚠️ [TEACHING MODE] 教学演练会话已过期，自动关闭漏洞端口..."
        print("\n" + "=" * 70)
        print(msg)
        print("=" * 70 + "\n")
        _log_security_event(
            "expired",
            {
                "mode": _Target_MODE,
                "expires_at": _session_expires_at.strftime("%Y-%m-%dT%H:%M:%S")
                if _session_expires_at
                else None,
                "reason": "timeout",
            },
        )

    t = threading.Thread(target=_timer_loop, daemon=True)
    t.start()


# 应用启动校验
_validate_secrets_on_startup()

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import subprocess

app = FastAPI(title="[教学靶机] 漏洞演示平台")


# ============================================================
# v3.1 新增：教学会话过期中间件（v3.2 新增请求数限制）
# 若 _teaching_session_expired 为 True，则拦截所有请求返回 410 Gone
# 若请求数达到 TARGET_MAX_REQUESTS，则置会话过期并返回 429
# ============================================================
@app.middleware("http")
async def _teaching_session_expiry_middleware(request: Request, call_next):
    """教学会话过期 + 请求数限制中间件"""
    if _teaching_session_expired:
        # 允许 /api/v1/health/status 和 /health 继续查询状态（便于监控）
        path = request.url.path
        allow_paths = ("/health", "/api/v1/health/status", "/")
        if path in allow_paths:
            return await call_next(request)
        return JSONResponse(
            status_code=410,
            content={
                "error": "teaching_session_expired",
                "message": "[TEACHING MODE] 教学演练会话已过期，漏洞端口已关闭。"
                           "请重启靶机以开始新的演练。",
            },
        )

    # v3.2：请求计数器 — 命中上限时返回 429 Too Many Requests
    if _hit_request_limit():
        return JSONResponse(
            status_code=429,
            content={
                "error": "too_many_requests",
                "message": f"[TEACHING MODE] 已达到最大请求数限制 ({_TARGET_MAX_REQUESTS})，"
                           f"漏洞端点已禁用。",
                "limit": _TARGET_MAX_REQUESTS,
            },
        )
    return await call_next(request)


# ============================================================
# v3.3 重构：漏洞模块已从 target_app.py 剥离到 vuln/ 目录
# - vuln/cs0048.py  (API 未授权访问配置泄露)
# - vuln/cwe78.py   (操作系统命令注入)
# - vuln/cwe89.py   (SQL 注入)
# - vuln/amlt0051.py(LLM 提示词注入)
# 通过 register_vuln_routes 统一注册
# ============================================================

# 统一漏洞配置对象（传递给各子模块）
_vuln_config = {
    "FLAG_CONFIG": FLAG_CONFIG,
    "CONFIG_SECRETS": CONFIG_SECRETS,
    "SQL_LEAK_DATA": SQL_LEAK_DATA,
    "LEGIT_ADMIN": LEGIT_ADMIN,
    "PROMPT_LEAK_DATA": PROMPT_LEAK_DATA,
    "_log_security_event": _log_security_event,
    "_get_client_ip": _get_client_ip,
    "_teaching_session_expired": lambda: _teaching_session_expired,
}

try:
    from vuln import register_vuln_routes
    register_vuln_routes(app, _vuln_config)
except ImportError as e:
    print(f"[WARN] 漏洞模块导入失败（{e}），跳过漏洞路由注册")
    print("[WARN] 请确认 backend/vuln/ 目录存在")


# ============================================================
# 健康检查接口
# ============================================================
@app.get("/health")
async def health(request: Request):
    _log_security_event(
        "system_health_check",
        {
            "path": "/health",
            "client_ip": _get_client_ip(request),
        },
    )
    return {"status": "healthy", "service": "assessment-target"}


# ============================================================
# v3.1 新增：教学模式状态查询端点
# 返回运行模式、启动时间、到期时间、剩余秒数、漏洞列表
# ============================================================
@app.get("/api/v1/health/status")
async def health_status(request: Request):
    _log_security_event(
        "status_query",
        {
            "path": "/api/v1/health/status",
            "client_ip": _get_client_ip(request),
        },
    )
    """
    查询当前教学靶机的运行状态

    返回字段：
      - mode:                  "teaching" 或 "production"
      - started_at:            ISO 时间戳（UTC）
      - expires_at:            ISO 时间戳（仅 teaching 模式）
      - seconds_remaining:     剩余秒数（到期后为 0）
      - session_expired:       bool，会话是否已过期
      - vulnerabilities_enabled: 启用的漏洞列表
    """
    now = datetime.now(timezone.utc)
    if _session_started_at is None:
        started_at_iso = now.strftime("%Y-%m-%dT%H:%M:%S")
    else:
        started_at_iso = _session_started_at.strftime("%Y-%m-%dT%H:%M:%S")

    response = {
        "mode": _Target_MODE,
        "started_at": started_at_iso,
        "seconds_remaining": 0,
        "session_expired": bool(_teaching_session_expired),
        "vulnerabilities_enabled": list(FLAG_CONFIG.keys()),
        "total_requests": _total_requests,
        "max_requests": _TARGET_MAX_REQUESTS,
        "requests_remaining": max(0, _TARGET_MAX_REQUESTS - _total_requests),
    }

    if _Target_MODE == "teaching" and _session_expires_at is not None:
        response["expires_at"] = _session_expires_at.strftime("%Y-%m-%dT%H:%M:%S")
        remaining = int((_session_expires_at - now).total_seconds())
        response["seconds_remaining"] = max(0, remaining)

    return response


# ============================================================
# v3.1 新增：管理员提前终止教学会话
# 需要 Authorization: Bearer TEACHING_ADMIN_TOKEN
# ============================================================
@app.post("/api/v1/admin/terminate-session")
async def terminate_session(request: Request):
    """
    提前终止教学演练会话，立即关闭所有漏洞端口

    认证方式：Authorization: Bearer <TEACHING_ADMIN_TOKEN>
    """
    # 简单 Bearer token 校验
    auth_header = request.headers.get("authorization", "")
    expected = f"Bearer {_TEACHING_ADMIN_TOKEN}"
    if auth_header != expected:
        _log_security_event(
            "admin_unauthorized",
            {
                "endpoint": "/api/v1/admin/terminate-session",
                "client_ip": _get_client_ip(request),
                "reason": "invalid_token",
            },
        )
        raise HTTPException(status_code=401, detail="Invalid or missing admin token")

    global _teaching_session_expired
    with _expiry_lock:
        _teaching_session_expired = True

    msg = "⚠️ [TEACHING MODE] 教学演练会话已被管理员提前终止，漏洞端口已关闭..."
    print("\n" + "=" * 70)
    print(msg)
    print("=" * 70 + "\n")

    _log_security_event(
        "terminated",
        {
            "endpoint": "/api/v1/admin/terminate-session",
            "client_ip": _get_client_ip(request),
            "reason": "admin_terminate",
            "terminated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        },
    )

    return {
        "status": "ok",
        "message": "Teaching session terminated. All vulnerability endpoints are now closed.",
        "session_expired": True,
    }


@app.get("/")
async def root(request: Request):
    _log_security_event(
        "root_access",
        {
            "path": "/",
            "client_ip": _get_client_ip(request),
        },
    )
    return {
        "service": "漏洞靶机",
        "version": "1.0.0",
        "warning": "【警告】此服务包含故意漏洞，仅供教学演示",
        "endpoints": [
            "/api/v1/config (CS0048 - 未授权访问)",
            "/api/v1/ping (CWE-78 - 命令注入)",
            "/api/v1/login (CWE-89 - SQL注入)",
            "/api/v1/agent (AML.T0051 - 提示词注入)",
        ],
        "admin_endpoints": [
            "/api/v1/health/status (GET - 状态查询)",
            "/api/v1/admin/terminate-session (POST - 提前终止会话)",
        ],
    }


if __name__ == "__main__":
    # v3.1：在启动 uvicorn 之前启动过期计时器
    _start_expiry_timer()

    print("=" * 60)
    print("【警告】漏洞靶机正在启动")
    print("【警告】此服务包含故意漏洞，禁止在生产环境暴露")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=18789, log_level="warning")
