"""
路由包
所有 API 路由按功能域拆分到此目录，由 main.py 统一注册。
"""

from . import scan
from . import judge
from . import knowledge
from . import adversarial
from . import tracer
from . import history

__all__ = ["scan", "judge", "knowledge", "adversarial", "tracer", "history"]
