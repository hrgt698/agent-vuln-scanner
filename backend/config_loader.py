"""
配置加载模块 v2.2
统一管理所有配置项，支持 YAML 文件 + 环境变量覆盖。
若 PyYAML 未安装，自动降级为默认配置字典。
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
from functools import lru_cache

# 尝试导入 yaml（可选依赖，若未安装则使用默认配置）
try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False
    yaml = None


# ======================================================
# 默认配置（当 config.yaml 不可读取时使用的安全回退）
# ======================================================
_DEFAULT_CONFIG: Dict[str, Any] = {
    "app": {
        "name": "Agent Vulnerability Assessment Platform",
        "version": "2.2.0",
        "host": "127.0.0.1",
        "port": 8000,
        "debug": False,
    },
    "target": {
        "url": "http://127.0.0.1:18789",
        "container_name": "assessment-target",
        "timeout": 60,
    },
    "dashscope": {
        "api_key": "${DASHSCOPE_API_KEY}",
        "base_url": "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
    },
    "models": {
        "default": "qwen-turbo",
        "available": [
            {"id": "qwen-turbo", "name": "通义千问-Turbo"},
            {"id": "qwen-plus", "name": "通义千问-Plus"},
            {"id": "qwen-max", "name": "通义千问-Max"},
        ],
    },
    "rag": {
        "provider": "faiss",
        "embedding_model": "text-embedding-v3",
        "embedding_dim": 1024,
        "top_k": 3,
        "persist_dir": "./data/vector_db",
    },
    "database": {"path": "./data/assessment.db", "echo": False},
    "security": {
        "cors_origins": ["http://localhost:5173", "http://127.0.0.1:5173"],
        "rate_limit": {"enabled": True, "requests_per_minute": 60},
        "api_key_required": False,
        "waf_threshold_initial": 0.4,
        "waf_threshold_min": 0.1,
        "waf_threshold_decay": 0.05,
    },
    "exploits": {
        "allowed_scripts": [
            "exp_cs0048.py",
            "exp_cwe78.py",
            "exp_sql_injection.py",
            "exp_prompt_injection.py",
        ]
    },
    "adversarial": {
        "max_rounds": 5,
        "attempts_per_round": 5,
        "use_real_waf": True,
    },
}


class Config:
    """配置管理类（v2.2：支持 YAML + 环境变量 + 默认配置三级回退）"""

    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        """从 YAML 文件加载配置，自动降级为默认值"""
        config_path = Path(__file__).parent / "config.yaml"
        source = "default"

        if _YAML_AVAILABLE and config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    self._config = yaml.safe_load(f) or {}
                source = "config.yaml"
            except Exception as e:
                print(f"[Config] 读取 config.yaml 失败（{e}），使用默认配置")
                self._config = dict(_DEFAULT_CONFIG)
        elif not _YAML_AVAILABLE:
            print("[Config] PyYAML 未安装（pip install pyyaml），使用默认配置")
            self._config = dict(_DEFAULT_CONFIG)
        else:
            print(f"[Config] 未找到 config.yaml（期望路径: {config_path}），使用默认配置")
            self._config = dict(_DEFAULT_CONFIG)

        if self._config:
            print(f"[Config] 配置已加载（来源: {source}）")

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项，支持点号分隔的路径（如 'app.host'）"""
        keys = key.split(".")
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        # 环境变量覆盖：检查 ${VAR_NAME} 格式
        if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            env_var = value[2:-1]
            return os.getenv(env_var, default)
        return value

    def reload(self):
        """重新加载配置"""
        self._load_config()

    @property
    def app(self) -> Dict[str, Any]:
        return self._config.get("app", {})

    @property
    def target(self) -> Dict[str, Any]:
        return self._config.get("target", {})

    @property
    def dashscope(self) -> Dict[str, Any]:
        return self._config.get("dashscope", {})

    @property
    def models(self) -> Dict[str, Any]:
        return self._config.get("models", {})

    @property
    def rag(self) -> Dict[str, Any]:
        return self._config.get("rag", {})

    @property
    def database(self) -> Dict[str, Any]:
        return self._config.get("database", {})

    @property
    def security(self) -> Dict[str, Any]:
        return self._config.get("security", {})

    @property
    def exploits(self) -> Dict[str, Any]:
        return self._config.get("exploits", {})

    @property
    def adversarial(self) -> Dict[str, Any]:
        return self._config.get("adversarial", {})


@lru_cache()
def get_config() -> Config:
    """获取配置单例"""
    return Config()
