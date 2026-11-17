"""
services.globals — 全局实例管理与初始化
"""

from __future__ import annotations

import os
from typing import Optional, Any

# =====================================================
# 内部模块（无循环导入风险）
# =====================================================
from config_loader import get_config as _get_config_from_loader
from scheduler import DAGScheduler, VulnTask, AdaptiveScheduler
from attack_graph import AttackGraphAnalyzer
from ensemble_judge import EnsembleJudger
from agent_tracer import DecisionTreeTracer
from auto_patcher import AutoPatcher
from adversarial_mode import AdversarialEvaluator
from database import Database, ScanRecord


# =====================================================
# 全局实例（延迟初始化）
# =====================================================
_config = None
_db: Optional[Database] = None
_attack_graph: Optional[AttackGraphAnalyzer] = None
_rag_engine: Optional[Any] = None
_ensemble_judger: Optional[EnsembleJudger] = None
_adaptive_scheduler: Optional[AdaptiveScheduler] = None
_decision_tracer: Optional[DecisionTreeTracer] = None
_auto_patcher: Optional[AutoPatcher] = None
_adversarial_evaluator: Optional[AdversarialEvaluator] = None
_current_model: str = "qwen-turbo"

# v3.0 高级算法模块全局实例
_cross_validator: Optional[Any] = None
_rl_agent: Optional[Any] = None
_autonomous_prober: Optional[Any] = None
_patch_generator: Optional[Any] = None

# RAG 可用性标记
_RAG_AVAILABLE: bool = False


# =====================================================
# 初始化（由 main.py 调用）
# =====================================================
def init_services():
    """初始化所有共享服务实例（应在 FastAPI app 创建前调用）"""
    global _config, _db, _attack_graph, _rag_engine
    global _ensemble_judger, _adaptive_scheduler
    global _decision_tracer, _auto_patcher
    global _RAG_AVAILABLE

    _config = _get_config_from_loader()

    # 数据库
    _db = Database.get_instance(db_path=_config.get("database.path", "./data/assessment.db"))

    # 攻击图
    _attack_graph = AttackGraphAnalyzer()

    # RAG 引擎
    _RAG_AVAILABLE = False
    try:
        from rag_engine import RAGEngine
        rag_config = _config.get("rag", {}) if hasattr(_config, "get") else {}
        _rag_engine = RAGEngine(
            api_key=os.getenv("DASHSCOPE_API_KEY"),
            embedding_model=_config.get("rag.embedding_model", "text-embedding-v3"),
            embedding_dim=int(_config.get("rag.embedding_dim", "1024")) or 1024,
            top_k=int(_config.get("rag.top_k", "3")) or 3,
            persist_dir=_config.get("rag.persist_dir", "./data/vector_db"),
        )
        _RAG_AVAILABLE = True
    except ImportError:
        try:
            from rag_advice import RAGAdviceEngine
            _rag_engine = RAGAdviceEngine()
            _RAG_AVAILABLE = True
        except ImportError:
            _rag_engine = None
    except Exception as e:
        print(f"[WARN] RAGEngine 初始化失败：{e}，将降级为无 RAG 模式")

    # 其他服务
    _ensemble_judger = EnsembleJudger()
    _adaptive_scheduler = AdaptiveScheduler()
    _decision_tracer = DecisionTreeTracer("assessment-agent")
    _auto_patcher = AutoPatcher(
        container_name=_config.get("target.container_name", "assessment-target")
    )

    # v3.0 高级算法模块初始化
    from cross_validator import CrossValidator
    from rl_agent import RLAttackAgent, RLConfig
    from autonomous_prober import AutonomousProber, ProbeConfig
    from auto_patch_generator import AutoPatchGenerator, PatchConfig

    _cross_validator = CrossValidator()
    _rl_agent = RLAttackAgent(RLConfig(epsilon=0.3))
    _autonomous_prober = AutonomousProber(ProbeConfig())
    _autonomous_prober.build_default()
    _patch_generator = AutoPatchGenerator(PatchConfig())


# =====================================================
# Getter（供各路由模块使用）
# =====================================================
def get_config() -> Any:
    return _config

def get_db() -> Database:
    assert _db is not None, "数据库未初始化，请先调用 init_services()"
    return _db

def get_attack_graph() -> AttackGraphAnalyzer:
    assert _attack_graph is not None, "AttackGraph 未初始化"
    return _attack_graph

def get_rag_engine() -> Optional[Any]:
    return _rag_engine

def is_rag_available() -> bool:
    return _RAG_AVAILABLE

def get_ensemble_judger() -> EnsembleJudger:
    assert _ensemble_judger is not None
    return _ensemble_judger

def get_adaptive_scheduler() -> AdaptiveScheduler:
    assert _adaptive_scheduler is not None
    return _adaptive_scheduler

def get_decision_tracer() -> DecisionTreeTracer:
    return _decision_tracer

def set_decision_tracer(tracer: DecisionTreeTracer) -> None:
    global _decision_tracer
    _decision_tracer = tracer

def get_auto_patcher() -> AutoPatcher:
    assert _auto_patcher is not None
    return _auto_patcher

def get_adversarial_evaluator() -> Optional[AdversarialEvaluator]:
    return _adversarial_evaluator

def set_adversarial_evaluator(evaluator: AdversarialEvaluator) -> None:
    global _adversarial_evaluator
    _adversarial_evaluator = evaluator

def get_current_model() -> str:
    return _current_model

def set_current_model(model: str) -> None:
    global _current_model
    _current_model = model

# =====================================================
# v3.0 高级算法模块 Getter
# =====================================================
def get_cross_validator() -> Any:
    assert _cross_validator is not None, "CrossValidator 未初始化"
    return _cross_validator

def get_rl_agent() -> Any:
    assert _rl_agent is not None, "RLAgent 未初始化"
    return _rl_agent

def get_autonomous_prober() -> Any:
    assert _autonomous_prober is not None, "AutonomousProber 未初始化"
    return _autonomous_prober

def get_patch_generator() -> Any:
    assert _patch_generator is not None, "PatchGenerator 未初始化"
    return _patch_generator