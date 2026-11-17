"""
安全中间件 & 配置文件加载测试
测试 RateLimiter、路径清理、敏感数据哈希、Config 加载等功能。
"""

import os
import sys
import time
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from security import RateLimiter, sanitize_path, hash_sensitive_data
from config_loader import Config


# ======================================================
# RateLimiter 测试
# ======================================================
class MockRequest:
    def __init__(self, client_ip="127.0.0.1", path="/api/scan"):
        self.client = MagicMock()
        self.client.host = client_ip
        self.url = MagicMock()
        self.url.path = path
        self.headers = {}


@pytest.fixture
def limiter():
    return RateLimiter(MagicMock(), requests_per_minute=5)


def test_rate_limit_not_exceeded(limiter):
    """测试未超过限流阈值时正常放行"""
    # 手动模拟
    client_id = "127.0.0.1"
    for _ in range(3):
        assert not limiter._is_rate_limited(client_id)


def test_rate_limit_exceeded(limiter):
    """测试超过限流阈值被拒绝"""
    client_id = "127.0.0.1"
    # 消耗 5 次
    for _ in range(5):
        limiter._is_rate_limited(client_id)
    # 第 6 次应该触发限流
    assert limiter._is_rate_limited(client_id) is True


def test_rate_limit_isolated_by_ip(limiter):
    """测试不同 IP 的限流是独立的"""
    client_a = "10.0.0.1"
    client_b = "10.0.0.2"

    for _ in range(5):
        limiter._is_rate_limited(client_a)

    # A 被限流
    assert limiter._is_rate_limited(client_a) is True
    # B 不受影响
    assert limiter._is_rate_limited(client_b) is False


def test_client_id_from_header(limiter):
    """测试从 X-Forwarded-For 获取客户端 ID"""
    request = MockRequest()
    request.headers["x-forwarded-for"] = "203.0.113.45, 198.51.100.2"
    assert limiter._get_client_id(request) == "203.0.113.45"


def test_client_id_fallback_to_host(limiter):
    """测试没有 X-Forwarded-For 时回退到 client.host"""
    request = MockRequest(client_ip="192.168.1.100")
    assert limiter._get_client_id(request) == "192.168.1.100"


# ======================================================
# sanitize_path 测试
# ======================================================
def test_sanitize_path_normal():
    """测试正常路径不被改变"""
    assert sanitize_path("/api/config") == "/api/config"
    assert sanitize_path("/health") == "/health"


def test_sanitize_path_traversal():
    """测试路径遍历攻击被清理"""
    result = sanitize_path("/etc/../../../passwd")
    assert ".." not in result
    assert result.startswith("/")


def test_sanitize_path_complex():
    """测试复杂路径遍历组合"""
    result = sanitize_path("/api/../admin/./config")
    assert ".." not in result


# ======================================================
# hash_sensitive_data 测试
# ======================================================
def test_hash_sensitive_data_consistent():
    """测试相同输入产生相同输出"""
    assert hash_sensitive_data("secret") == hash_sensitive_data("secret")


def test_hash_sensitive_data_different():
    """测试不同输入产生不同输出"""
    assert hash_sensitive_data("password1") != hash_sensitive_data("password2")


def test_hash_sensitive_data_truncated():
    """测试输出长度合理（不泄露原始信息）"""
    result = hash_sensitive_data("very_long_secret_string")
    assert len(result) < 50


# ======================================================
# Config 测试
# ======================================================
@pytest.fixture
def sample_config(tmp_path):
    """创建一个临时配置文件"""
    yaml_content = """
app:
  name: "测试平台"
  version: "1.0.0"
  host: "127.0.0.1"
  port: 9000
  debug: true

target:
  url: "http://example.com"
  container_name: "test-container"
  timeout: 30

security:
  cors_origins:
    - "http://localhost:3000"
  rate_limit:
    enabled: true
    requests_per_minute: 30
  api_key_required: false

rag:
  provider: "faiss"
  embedding_model: "text-embedding-v3"
  embedding_dim: 1024
  top_k: 5
  persist_dir: "./data/test_vector_db"

database:
  path: "./data/test.db"
  echo: false
"""
    cfg_file = tmp_path / "test_config.yaml"
    cfg_file.write_text(yaml_content, encoding="utf-8")

    # 替换默认路径
    with patch.object(Config, "_load_config"):
        cfg = Config.__new__(Config)
        import yaml as _yaml
        cfg._config = _yaml.safe_load(yaml_content)
        return cfg


def test_config_get_nested(sample_config):
    """测试读取嵌套配置项"""
    assert sample_config.get("app.name") == "测试平台"
    assert sample_config.get("app.port") == 9000
    assert sample_config.get("target.url") == "http://example.com"
    assert sample_config.get("rag.top_k") == 5


def test_config_get_default(sample_config):
    """测试默认值回退"""
    assert sample_config.get("nonexistent.key", "fallback") == "fallback"
    assert sample_config.get("app.missing") is None


def test_config_get_boolean(sample_config):
    """测试布尔配置读取"""
    assert sample_config.get("security.api_key_required") is False
    assert sample_config.get("security.rate_limit.enabled") is True


def test_config_property_access(sample_config):
    """测试属性访问方式"""
    app_cfg = sample_config.app
    assert app_cfg["name"] == "测试平台"

    rag_cfg = sample_config.rag
    assert rag_cfg["provider"] == "faiss"
    assert rag_cfg["embedding_dim"] == 1024


def test_config_singleton():
    """测试 Config.get_instance() 的单例特性"""
    cfg1 = get_config()
    cfg2 = get_config()
    # 同进程内返回同一实例
    assert cfg1 is cfg2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
