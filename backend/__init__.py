"""
Agent Vulnerability Assessment Platform — 后端包初始化
"""

__version__ = "2.4.0"
__author__ = "hrgt698"
__description__ = "基于 AgentBench + OpenClaw 的 AI Agent 高危漏洞自动化评估平台"

# 延迟导入，确保依赖在 pip install 后可用
from . import config_loader
from . import database
from . import security

__all__ = ["__version__", "__author__", "__description__"]
