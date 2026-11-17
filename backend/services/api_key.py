"""
services.api_key — API Key 健康检查 + 动态轮换
支持：多 Key 轮询、健康状态监控、运行时热替换
"""

import os
import time
import json
import threading
from typing import Optional, List, Dict, Any


_api_key_pool: List[str] = []
_current_key_index: int = 0
_last_health_check: float = 0.0
_health_cache: Dict[str, Any] = {}

# 后台健康检查线程相关全局变量
_health_thread: Optional[threading.Thread] = None
_health_thread_running: bool = False
_health_thread_lock = threading.Lock()
_health_check_interval: int = 300
_per_key_health_cache: Dict[str, Dict[str, Any]] = {}


def _start_health_check_thread() -> None:
    """启动 API Key 健康检查后台线程（带锁，防止重复启动）"""
    global _health_thread, _health_thread_running
    with _health_thread_lock:
        if _health_thread is not None and _health_thread.is_alive():
            print("[Services] API Key 健康检查后台线程已在运行")
            return
        _health_thread_running = True
        _health_thread = threading.Thread(
            target=_health_check_worker,
            name="APIKeyHealthChecker",
            daemon=True,
        )
        _health_thread.start()
        print(f"[Services] 启动 API Key 健康检查后台线程，每 {_health_check_interval} 秒检查一次")


def _stop_health_check_thread() -> None:
    """停止 API Key 健康检查后台线程"""
    global _health_thread_running
    _health_thread_running = False
    print("[Services] 正在停止 API Key 健康检查后台线程")


def _health_check_worker() -> None:
    """健康检查后台线程主循环：逐 Key 检查并缓存结果"""
    global _last_health_check
    while _health_thread_running:
        try:
            for key in _api_key_pool:
                if not _health_thread_running:
                    break
                result = check_api_key_health(key, timeout=5)
                _per_key_health_cache[key] = {
                    **result,
                    "checked_at": time.time(),
                }
                time.sleep(1)
            _last_health_check = time.time()
        except Exception as e:
            print(f"[WARN] 健康检查线程发生异常：{e}")
        # 分小段 sleep，便于及时响应停止信号
        total_sleep = _health_check_interval
        slept = 0
        while slept < total_sleep and _health_thread_running:
            time.sleep(1)
            slept += 1


def init_api_key_pool() -> List[str]:
    """初始化 API Key 池（从环境变量解析，支持逗号分隔多个 Key）"""
    global _api_key_pool
    raw_keys = os.getenv("DASHSCOPE_API_KEY_POOL", os.getenv("DASHSCOPE_API_KEY", ""))
    _api_key_pool = [
        k.strip() for k in raw_keys.split(",")
        if k.strip() and k.strip() != "__REQUIRED__"
    ]
    if not _api_key_pool:
        single_key = os.getenv("DASHSCOPE_API_KEY", "")
        if single_key and single_key != "__REQUIRED__":
            _api_key_pool = [single_key]
    print(f"[Services] API Key 池初始化：共 {len(_api_key_pool)} 个 Key")
    if _api_key_pool:
        _start_health_check_thread()
    return _api_key_pool


def get_next_api_key() -> Optional[str]:
    """轮询获取下一个可用的 API Key（健康检查优先）"""
    global _current_key_index
    if not _api_key_pool:
        return os.getenv("DASHSCOPE_API_KEY") or None
    key = _api_key_pool[_current_key_index % len(_api_key_pool)]
    _current_key_index = (_current_key_index + 1) % len(_api_key_pool)
    return key


def check_api_key_health(key: Optional[str] = None, timeout: int = 10) -> dict:
    """检查单个 API Key 的健康状态（通过 DashScope 简单请求）"""
    import urllib.request
    import urllib.error
    target_key = key or get_next_api_key()
    if not target_key:
        return {
            "status": "error",
            "reason": "no_api_key_configured",
            "latency_ms": 0,
        }
    try:
        start_time = time.time()
        req = urllib.request.Request(
            "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
            data=json.dumps({
                "model": "qwen-turbo",
                "input": {"messages": [{"role": "user", "content": "ping"}]},
                "parameters": {"max_tokens": 5},
            }).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {target_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        response = urllib.request.urlopen(req, timeout=timeout)
        latency_ms = int((time.time() - start_time) * 1000)
        result = {
            "status": "ok",
            "http_code": response.getcode(),
            "latency_ms": latency_ms,
            "key_masked": f"{target_key[:8]}...{target_key[-4:]}" if len(target_key) > 12 else "***",
        }
        response.close()
        _per_key_health_cache[target_key] = {**result, "checked_at": time.time()}
        return result
    except urllib.error.HTTPError as e:
        result = {
            "status": "unauthorized" if e.code in (401, 403) else "error",
            "http_code": e.code,
            "reason": str(e.reason),
            "latency_ms": int((time.time() - _last_health_check) * 1000) if _last_health_check else 0,
            "key_masked": f"{target_key[:8]}...{target_key[-4:]}" if len(target_key) > 12 else "***",
        }
        _per_key_health_cache[target_key] = {**result, "checked_at": time.time()}
        return result
    except Exception as e:
        result = {
            "status": "timeout",
            "reason": str(e),
            "latency_ms": 0,
            "key_masked": f"{target_key[:8]}...{target_key[-4:]}" if len(target_key) > 12 else "***",
        }
        _per_key_health_cache[target_key] = {**result, "checked_at": time.time()}
        return result


def health_check_all_keys() -> dict:
    """检查所有 API Key 的健康状态"""
    cache_ttl = 60
    now = time.time()
    from_cache = True
    results = []

    effective_keys: List[str] = list(_api_key_pool)
    if not effective_keys:
        single_key = os.getenv("DASHSCOPE_API_KEY", "")
        if single_key and single_key != "__REQUIRED__":
            effective_keys = [single_key]

    for key in effective_keys:
        cached = _per_key_health_cache.get(key)
        if cached and (now - cached.get("checked_at", 0)) <= cache_ttl:
            results.append({
                "status": cached.get("status", "unknown"),
                "http_code": cached.get("http_code"),
                "latency_ms": cached.get("latency_ms", 0),
                "key_masked": cached.get("key_masked", f"{key[:8]}...{key[-4:]}" if len(key) > 12 else "***"),
                "checked_at": cached.get("checked_at", 0),
                "from_cache": True,
            })
        else:
            from_cache = False
            result = check_api_key_health(key)
            results.append({**result, "from_cache": False})

    healthy = sum(1 for r in results if r.get("status") == "ok")
    recommended_next = next((r for r in results if r.get("status") == "ok"), results[0] if results else None)
    return {
        "total": len(results),
        "healthy": healthy,
        "unhealthy": len(results) - healthy,
        "keys": results,
        "recommended_next": recommended_next,
        "from_cache": from_cache,
        "last_check_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(_last_health_check)) if _last_health_check > 0 else "never",
    }


def rotate_api_key(new_key: str) -> dict:
    """运行时动态替换主 API Key（不重启服务）"""
    if not new_key or new_key.strip() == "__REQUIRED__":
        return {"status": "error", "reason": "invalid_key"}
    health = check_api_key_health(new_key.strip())
    if health["status"] != "ok":
        return {
            "status": "rejected",
            "reason": "new_key_health_check_failed",
            "detail": health,
        }
    os.environ["DASHSCOPE_API_KEY"] = new_key.strip()
    if new_key.strip() not in _api_key_pool:
        _api_key_pool.append(new_key.strip())
    print(f"[Services] API Key 已动态轮换")
    return {
        "status": "ok",
        "latency_ms": health.get("latency_ms", 0),
        "key_masked": health.get("key_masked", "***"),
    }


def get_api_key_pool_status() -> dict:
    """获取当前 Key 池的状态摘要"""
    now = time.time()
    healthy_count = 0
    unhealthy_count = 0
    for key in _api_key_pool:
        cached = _per_key_health_cache.get(key)
        if cached and cached.get("status") == "ok":
            healthy_count += 1
        elif cached:
            unhealthy_count += 1
    return {
        "pool_size": len(_api_key_pool),
        "current_index": _current_key_index,
        "keys_masked": [f"{k[:8]}...{k[-4:]}" if len(k) > 12 else "***" for k in _api_key_pool],
        "last_check_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(_last_health_check)) if _last_health_check > 0 else "never",
        "last_check_seconds_ago": int(now - _last_health_check) if _last_health_check > 0 else -1,
        "thread_running": _health_thread is not None and _health_thread.is_alive(),
        "healthy_key_count": healthy_count,
        "unhealthy_key_count": unhealthy_count,
    }


def get_health_cache_summary() -> dict:
    """返回 per-key 健康缓存摘要"""
    summary = {}
    for key, cached in _per_key_health_cache.items():
        masked = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else "***"
        summary[masked] = {
            "status": cached.get("status", "unknown"),
            "latency_ms": cached.get("latency_ms", 0),
            "http_code": cached.get("http_code"),
            "checked_at": cached.get("checked_at", 0),
            "checked_at_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cached.get("checked_at", 0))) if cached.get("checked_at", 0) > 0 else "never",
        }
    return summary