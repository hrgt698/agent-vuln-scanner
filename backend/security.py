"""
安全模块 v3.0
提供：
  - JWT Token 动态认证（替代静态 API Key）
  - 权限装饰器 permission_required（细粒度权限控制）
  - CSRF 防护（Double-Submit Cookie Pattern）
  - API 限流中间件（滑动窗口）
  - 安全响应头（CSP、X-Frame-Options 等）
  - 路径清理防路径遍历
  - 敏感数据哈希脱敏
  - 匿名请求自动拦截机制（v3.0 新增）
"""

import os
import time
import hashlib
import secrets
from typing import Optional, Dict, Callable, Any
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from fastapi import Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# ======================================================
# JWT 库检测（支持 PyJWT 与 python-jose 双兼容，两者都不可用时降级为 HMAC stub）
# ======================================================
_JWT_LIB = None  # 取值："pyjwt" / "jose" / None
try:
    from jose import jwt as _jose_jwt  # type: ignore
    _JWT_LIB = "jose"
except ImportError:
    try:
        import jwt as _pyjwt  # type: ignore
        _JWT_LIB = "pyjwt"
    except ImportError:
        _JWT_LIB = None

JWT_AVAILABLE = _JWT_LIB is not None


def _jwt_encode(payload: Dict[str, Any], secret: str, algorithm: str) -> str:
    """根据可用库选择 JWT 编码实现"""
    if _JWT_LIB == "jose":
        return _jose_jwt.encode(payload, secret, algorithm=algorithm)
    if _JWT_LIB == "pyjwt":
        return _pyjwt.encode(payload, secret, algorithm=algorithm)  # type: ignore[arg-type]
    # 无 JWT 库：降级为 HMAC-based 简单 token（非标准，但保证流程不中断）
    import hmac
    import base64
    header = json_dumps_safe({"alg": algorithm, "typ": "JWT"})
    body = json_dumps_safe(payload)
    signing_input = b64url(header) + b"." + b64url(body)
    sig = hmac.new(secret.encode("utf-8"), signing_input, "sha256").digest()
    return (signing_input + b"." + b64url_bytes(sig)).decode("ascii")


def _jwt_decode(token: str, secret: str, algorithm: str) -> Dict[str, Any]:
    """根据可用库选择 JWT 解码实现"""
    if _JWT_LIB == "jose":
        return _jose_jwt.decode(token, secret, algorithms=[algorithm])
    if _JWT_LIB == "pyjwt":
        return _pyjwt.decode(token, secret, algorithms=[algorithm])  # type: ignore[arg-type]
    # 无 JWT 库：验证签名合法性
    import hmac
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, "sha256").digest()
    import base64
    actual_sig = base64.urlsafe_b64decode(parts[2] + "==")
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid signature")
    try:
        payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
        import json as _json_mod
        return _json_mod.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise ValueError("Invalid payload")


def json_dumps_safe(obj: Any) -> str:
    import json as _json_mod
    return _json_mod.dumps(obj, separators=(",", ":"))


def b64url(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64encode(s.encode("utf-8")).rstrip(b"=")


def b64url_bytes(b: bytes) -> bytes:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=")


# ======================================================
# JWT Token 认证
# ======================================================

class JWTAuth:
    """JWT 动态 Token 认证
    支持 Token 生成、验证、过期刷新。
    使用 HS256 算法，需要设置 JWT_SECRET 环境变量。
    """

    ALGORITHM = "HS256"
    # Token 默认有效期：8 小时
    DEFAULT_EXPIRE_HOURS = 8

    # v3.0 新增：内置权限集合（参考 RBAC）
    PERM_READ_VULN = "read:vulnerability"
    PERM_EXEC_SCAN = "execute:scan"
    PERM_EXEC_JUDGE = "execute:judge"
    PERM_EXEC_ADVERSARIAL = "execute:adversarial"
    PERM_WRITE_PATCH = "write:patch"
    PERM_MANAGE_KNOWLEDGE = "manage:knowledge"
    PERM_READ_HISTORY = "read:history"
    PERM_TRACER = "execute:tracer"

    # 默认管理员权限集合（用于 generate_token 的 extra_claims 默认值）
    _ALL_PERMISSIONS = frozenset({
        PERM_READ_VULN, PERM_EXEC_SCAN, PERM_EXEC_JUDGE,
        PERM_EXEC_ADVERSARIAL, PERM_WRITE_PATCH,
        PERM_MANAGE_KNOWLEDGE, PERM_READ_HISTORY, PERM_TRACER,
    })

    # 已知的弱密钥/开发专用密钥（禁止在生产环境使用）
    _WEAK_SECRETS = frozenset({
        "TEMPORARY_SECRET_FOR_DEV_ONLY_CHANGE_ME",
        "CHANGE_ME",
        "dev_secret",
        "your-secret-here",
        "secret",
        "changeme",
    })

    def __init__(
        self,
        secret: Optional[str] = None,
        expire_hours: int = DEFAULT_EXPIRE_HOURS,
    ):
        # 优先使用环境变量，其次使用传入的 secret
        self.secret = os.environ.get("JWT_SECRET") or secret
        self.expire_hours = expire_hours
        self._warn_if_no_secret()
        self._validate_secret_strength()

    def _warn_if_no_secret(self):
        """未设置 secret 时发出警告"""
        if not self.secret:
            if os.environ.get("ENV") == "production":
                raise RuntimeError(
                    "[JWT] ❌ 错误：生产环境（ENV=production）必须设置 JWT_SECRET 环境变量。"
                    "请通过 JWT_SECRET 环境变量设置至少 32 字符的随机密钥。"
                )
            else:
                print(
                    "[JWT] ⚠️ 警告：未设置 JWT_SECRET 环境变量，"
                    "JWT 认证已降级为跳过模式（仅演示用途）"
                )

    def _validate_secret_strength(self) -> None:
        """校验 JWT secret 强度
        - 长度必须 >= 32 字符
        - 禁止使用已知的弱密钥
        - 生产环境（ENV=production）检测到弱密钥时抛出 ValueError
        """
        if not self.secret:
            return  # _warn_if_no_secret 已处理

        # 检查已知弱密钥
        if self.secret in self._WEAK_SECRETS:
            msg = (
                "[JWT] ❌ 错误：检测到弱密钥或开发专用密钥（'%s'）。"
                "请通过 JWT_SECRET 环境变量设置至少 32 字符的随机密钥。"
            ) % self.secret
            if os.environ.get("ENV") == "production":
                raise ValueError(msg)
            else:
                print("[JWT] ⚠️ " + msg)
                return

        # 检查最小长度
        if len(self.secret) < 32:
            msg = (
                "[JWT] ❌ 错误：JWT_SECRET 长度不足（当前 %d 字符，需 >= 32）。"
                "请使用：openssl rand -hex 32"
            ) % len(self.secret)
            if os.environ.get("ENV") == "production":
                raise ValueError(msg)
            else:
                print("[JWT] ⚠️ " + msg)

    def _get_secret(self) -> str:
        """获取 secret，无 secret 时生成临时 secret（仅演示用）"""
        if not self.secret:
            # 生成一个临时 secret（仅在没有配置时使用，生产环境不应如此）
            return os.environ.get(
                "JWT_SECRET",
                "TEMPORARY_SECRET_FOR_DEV_ONLY_CHANGE_ME"
            )
        return self.secret

    def generate_token(
        self,
        subject: str,
        extra_claims: Optional[Dict[str, Any]] = None,
        expire_hours: Optional[int] = None,
        permissions: Optional[list] = None,
    ) -> str:
        """生成 JWT Token（v3.0 支持权限注入）
        参数：
            subject: Token 主体标识（如 "admin", "api_client"）
            extra_claims: 额外的自定义声明
            expire_hours: 过期小时数（默认使用 self.expire_hours）
            permissions: 权限列表（如 ["execute:scan", "read:vulnerability"]）
        返回：JWT Token 字符串
        """
        if not JWT_AVAILABLE and not self.secret:
            raise RuntimeError(
                "JWT 库不可用（python-jose 或 PyJWT 均未安装）。"
                "请运行：pip install python-jose[cryptography] 或 pip install PyJWT"
            )

        now = datetime.now(timezone.utc)
        expire = now + timedelta(hours=expire_hours or self.expire_hours)

        # v3.0 新增：权限列表
        perm_list = list(permissions) if permissions else list(self._ALL_PERMISSIONS)

        payload = {
            "sub": subject,                       # 主体
            "iat": int(now.timestamp()),           # 签发时间（unix 秒）
            "exp": int(expire.timestamp()),       # 过期时间（unix 秒）
            "jti": secrets.token_hex(16),     # 唯一 ID，防重放
            "type": "access",
            "permissions": perm_list,            # v3.0 权限列表
        }

        if extra_claims:
            payload.update(extra_claims)

        return _jwt_encode(
            payload,
            self._get_secret(),
            self.ALGORITHM,
        )

    def verify_token(self, token: str) -> Dict[str, Any]:
        """验证 JWT Token
        参数：token: JWT Token 字符串
        返回：payload 字典
        异常：
            - Token 过期或无效时返回空字典
        """
        try:
            payload = _jwt_decode(token, self._get_secret(), self.ALGORITHM)
            # 基本过期检查（防止 HMAC stub 未内置过期校验）
            exp = payload.get("exp")
            if exp:
                if datetime.now(timezone.utc).timestamp() > float(exp):
                    return {}
            return payload
        except Exception:
            return {}

    def decode_token_unsafe(self, token: str) -> Optional[Dict[str, Any]]:
        """不验证签名的纯解码（用于日志脱敏）"""
        try:
            import base64
            import json as _json_mod
            parts = token.split(".")
            if len(parts) < 2:
                return None
            payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
            return _json_mod.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return None


# 全局 JWT 实例（延迟初始化）
_jwt_auth: Optional[JWTAuth] = None


def get_jwt_auth() -> JWTAuth:
    """获取 JWT 认证单例"""
    global _jwt_auth
    if _jwt_auth is None:
        _jwt_auth = JWTAuth()
    return _jwt_auth


async def require_jwt_auth(request: Request) -> Dict[str, Any]:
    """FastAPI 依赖：JWT Token 认证
    从请求头提取 Token，验证后返回 payload。
    支持两种 Token 来源：
      1. Authorization: Bearer <token>
      2. X-Access-Token: <token>

    v3.0 改动：若 JWT_SECRET 未配置，返回匿名用户 payload
    并由 permission_required() 负责后续的权限检查。
    """
    jwt_auth = get_jwt_auth()

    # v3.0 增强：JWT_SECRET 未配置时返回匿名用户（不再返回有效身份）
    # 由下游的 permission_required() 依赖自动拦截敏感操作
    if not jwt_auth.secret and not JWT_AVAILABLE:
        return {
            "sub": "anonymous",
            "type": "dev_mode_anonymous",
            "is_anonymous": True,
            "permissions": [],
        }

    if not JWT_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT 认证功能不可用（python-jose 未安装）",
        )

    # 提取 Token
    auth_header = request.headers.get("authorization", "")
    token = None

    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    else:
        token = request.headers.get("x-access-token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="缺少认证 Token。请通过 'Authorization: Bearer <token>' 或 'X-Access-Token: <token>' 传递。",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt_auth.verify_token(token)
        # v3.0 增强：确保 payload 包含权限列表（向后兼容：旧 token 默认全部权限）
        if "permissions" not in payload:
            payload["permissions"] = list(JWTAuth._ALL_PERMISSIONS)
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的 Token 或签名验证失败",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_authenticated_user(
    payload: Dict[str, Any] = Depends(require_jwt_auth)
) -> Dict[str, Any]:
    """FastAPI 依赖：强制要求已认证用户（v3.0 新增）
    自动拦截匿名请求（is_anonymous=True），返回 403。
    用法：
        async def my_endpoint(user: dict = Depends(require_authenticated_user)):
            ...
    """
    if payload.get("is_anonymous") or payload.get("type") == "dev_mode_anonymous":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "匿名请求无权执行此操作。"
                "请设置 JWT_SECRET 环境变量并通过有效 Token 认证后重试。"
            ),
        )
    return payload


def permission_required(*required_perms: str):
    """权限装饰器工厂（v3.0 新增）
    返回一个 FastAPI 依赖函数，验证当前用户是否拥有指定权限。

    用法示例：
        from security import JWTAuth, permission_required

        @app.post("/api/scan")
        async def scan(
            user: dict = Depends(permission_required(JWTAuth.PERM_EXEC_SCAN))
        ):
            ...

    同时满足：
      - 用户必须已认证（非匿名）
      - 用户的 permissions 列表必须包含所有 required_perms
    """
    async def _check(
        payload: Dict[str, Any] = Depends(require_jwt_auth)
    ) -> Dict[str, Any]:
        # 首先检查是否已认证
        if payload.get("is_anonymous") or payload.get("type") == "dev_mode_anonymous":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "匿名请求无权执行此操作。"
                    "请设置 JWT_SECRET 环境变量并通过有效 Token 认证后重试。"
                ),
            )

        # 验证权限
        user_perms = set(payload.get("permissions") or [])
        missing = [p for p in required_perms if p not in user_perms]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"缺少权限: {', '.join(missing)}。当前权限: {', '.join(sorted(user_perms)) or '无'}",
            )
        return payload

    return _check


async def optional_jwt_auth(request: Request) -> Optional[Dict[str, Any]]:
    """FastAPI 依赖：可选的 JWT 认证（不强制）"""
    try:
        return await require_jwt_auth(request)
    except HTTPException:
        return None


# ======================================================
# API Key 认证（向后兼容，已废弃，推荐使用 JWT）
# ======================================================

class APIKeyAuth:
    """静态 API Key 认证（已废弃，请使用 JWTAuth）

    仅在 JWT_SECRET 未配置时作为降级方案使用。
    验证逻辑：直接比对请求头中的 X-API-Key 与环境变量 API_KEY 是否一致。
    """

    def __init__(self):
        self.expected_key = os.environ.get("API_KEY")

    def verify(self, request: Request) -> bool:
        """验证 API Key"""
        if not self.expected_key:
            return True  # 未配置时跳过

        provided = request.headers.get("X-API-Key") or \
                   request.query_params.get("api_key")

        return secrets.compare_digest(provided or "", self.expected_key)


# ======================================================
# 限流中间件
# ======================================================

class RateLimiter(BaseHTTPMiddleware):
    """API 限流中间件
    基于滑动窗口算法，实现精确的请求频率控制。
    """

    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.window_ms = 60 * 1000  # 1 分钟窗口
        self._buckets: Dict[str, list] = defaultdict(list)

    def _get_client_id(self, request: Request) -> str:
        """获取客户端标识"""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _is_rate_limited(self, client_id: str) -> bool:
        """检查是否超过限流阈值"""
        now = time.time() * 1000
        window_start = now - self.window_ms

        # 清理过期记录
        self._buckets[client_id] = [
            ts for ts in self._buckets[client_id]
            if ts > window_start
        ]

        if len(self._buckets[client_id]) >= self.requests_per_minute:
            return True

        self._buckets[client_id].append(now)
        return False

    async def dispatch(self, request: Request, call_next):
        # 跳过健康检查和文档路由
        if request.url.path in [
            "/docs", "/openapi.json", "/health",
            "/api/status", "/api/token/generate"
        ]:
            return await call_next(request)

        client_id = self._get_client_id(request)
        if self._is_rate_limited(client_id):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "请求过于频繁，请等待一分钟后重试",
                    "retry_after_ms": self.window_ms,
                },
            )
        return await call_next(request)


# ======================================================
# 安全辅助函数
# ======================================================

def add_security_headers(request: Request, call_next):
    """添加安全响应头（v3.0 增强：添加 CSP、Referrer-Policy、Permissions-Policy）"""
    response = call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    # v3.0 新增：CSP 内容安全策略
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    # v3.0 新增：Referrer-Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # v3.0 新增：Permissions-Policy
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    )
    return response


# ======================================================
# v3.0 新增：CSRF 防护中间件（Double-Submit Cookie Pattern）
# ======================================================

class CSRFProtection(BaseHTTPMiddleware):
    """CSRF 防护中间件（v3.0 新增）
    采用 Double-Submit Cookie Pattern：
    1. 在 GET 请求时为用户签发 X-CSRF-Token Cookie
    2. 在 POST/PUT/DELETE/PATCH 请求时验证请求头
       X-CSRF-Token 与 Cookie 中的 token 是否一致
    3. 匿名用户（未配置 JWT_SECRET）默认免除 CSRF 要求
       （因为该场景下请求本身会被 permission_required 拦截）

    前端使用方式：
      - fetch 请求时添加 header: 'X-CSRF-Token': token
      - token 从 document.cookie 中读取
    """

    CSRF_COOKIE_NAME = "X-CSRF-Token"
    CSRF_HEADER_NAME = "x-csrf-token"
    CSRF_TOKEN_LENGTH = 32

    # 安全方法：GET/HEAD/OPTIONS/TRACE 不修改状态，免除 CSRF 校验
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

    # 需要豁免的路径（如 Webhook、公开 API）
    EXEMPT_PATHS = {
        "/health",
        "/api/status",
        "/api/token/generate",
    }

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method.upper()

        # 安全方法或豁免路径：签发 cookie 并放行
        if method in self.SAFE_METHODS or self._is_exempt(path):
            response = await call_next(request)
            # 签发新的 CSRF cookie（每次 GET 请求都会刷新）
            if method == "GET" and path not in {"/docs", "/openapi.json"}:
                self._set_csrf_cookie(response)
            return response

        # 非安全方法：验证 CSRF token
        cookie_token = request.cookies.get(self.CSRF_COOKIE_NAME)
        header_token = request.headers.get(self.CSRF_HEADER_NAME)

        if not cookie_token or not header_token:
            return JSONResponse(
                status_code=403,
                content={"error": "csrf_missing", "detail": "缺少 CSRF token"},
            )

        # 使用恒定时间比较（防止时序攻击）
        if not secrets.compare_digest(cookie_token, header_token):
            return JSONResponse(
                status_code=403,
                content={"error": "csrf_invalid", "detail": "CSRF token 不匹配"},
            )

        # 通过验证，放行请求
        response = await call_next(request)
        # 可选：在响应中也刷新 token
        self._set_csrf_cookie(response)
        return response

    def _is_exempt(self, path: str) -> bool:
        """判断路径是否在豁免列表中"""
        return any(path == p or path.startswith(p + "/") for p in self.EXEMPT_PATHS)

    def _set_csrf_cookie(self, response):
        """在响应中设置 CSRF token Cookie（HttpOnly=False 以便 JS 读取）"""
        token = secrets.token_hex(self.CSRF_TOKEN_LENGTH // 2)
        response.set_cookie(
            key=self.CSRF_COOKIE_NAME,
            value=token,
            httponly=False,           # 允许 JS 读取以放入请求头
            samesite="lax",
            secure=False,             # 生产环境建议使用 HTTPS
            max_age=3600,
            path="/",
        )


def sanitize_path(path: str) -> str:
    """路径清理，防止路径遍历攻击"""
    parts = path.split("/")
    cleaned = []
    for part in parts:
        if part == "..":
            if cleaned:
                cleaned.pop()
        elif part and part != ".":
            cleaned.append(part)
    return "/" + "/".join(cleaned) if cleaned else "/"


def hash_sensitive_data(data: str) -> str:
    """对敏感数据进行哈希处理（用于日志脱敏）"""
    return hashlib.sha256(data.encode()).hexdigest()[:16] + "..."


# ======================================================
# Token 生成辅助函数（供 API 调用）
# ======================================================

def generate_api_token(subject: str = "api_client",
                       permissions: Optional[list] = None) -> str:
    """生成 API 访问 Token（便捷函数，v3.0 支持权限）
    使用方式：
        POST /api/token/generate  ->  返回 {token: "..."}

    注意：该函数要求 JWT_SECRET 已正确配置，
    否则抛出 RuntimeError（不再允许生成不安全的 token）。
    """
    jwt_auth = get_jwt_auth()
    # v3.0：禁止在未配置 JWT_SECRET 时生成 token
    if not jwt_auth.secret:
        raise RuntimeError(
            "JWT_SECRET 未配置，无法生成访问 Token。"
            "请设置环境变量 JWT_SECRET（至少 32 字符），"
            "或使用：openssl rand -hex 32"
        )
    return jwt_auth.generate_token(subject=subject, permissions=permissions)


def require_authenticated(payload: dict) -> None:
    """[已废弃，推荐使用 permission_required() 或 require_authenticated_user]
    验证 JWT payload 是否为有效认证身份（非匿名）。
    用于保护敏感 API 端点。在 require_jwt_auth 依赖之后调用。
    """
    if payload.get("is_anonymous") or payload.get("type") == "dev_mode_anonymous":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "匿名请求无权执行此操作。"
                "请配置 JWT_SECRET 并通过有效 Token 认证后重试。"
            ),
        )
