"""
services 包 — 向后兼容层
将全局实例、常量、工具函数重新导出，保持与旧 services.py 完全兼容。
"""

# =====================================================
# 全局实例 + 初始化 + Getter
# =====================================================
from services.globals import (
    init_services,
    get_config,
    get_db,
    get_attack_graph,
    get_rag_engine,
    is_rag_available,
    get_ensemble_judger,
    get_adaptive_scheduler,
    get_decision_tracer,
    set_decision_tracer,
    get_auto_patcher,
    get_adversarial_evaluator,
    set_adversarial_evaluator,
    get_current_model,
    set_current_model,
    get_cross_validator,
    get_rl_agent,
    get_autonomous_prober,
    get_patch_generator,
)

# =====================================================
# 常量 + Prompt 模板 + DAG 配置
# =====================================================
from services.constants import (
    ALLOWED_SCRIPTS,
    AVAILABLE_MODELS,
    COT_SYSTEM_PROMPT,
    FEW_SHOT_EXAMPLES,
    SCRIPTS_INFO,
    build_default_scheduler,
)

# =====================================================
# 漏洞执行 + 报告生成
# =====================================================
from services.exploit_runner import (
    generate_report,
    run_exploit,
    try_fuzz_payload,
    sse_data,
)

# =====================================================
# API Key 健康检查 + 动态轮换
# =====================================================
from services.api_key import (
    init_api_key_pool,
    get_next_api_key,
    check_api_key_health,
    health_check_all_keys,
    rotate_api_key,
    get_api_key_pool_status,
    get_health_cache_summary,
)

# =====================================================
# ReAct Agent 集成
# =====================================================
from services.react_service import (
    get_react_agent,
    run_react_query,
)

# =====================================================
# 多模型对比 + 加权投票
# =====================================================
from services.multimodel import (
    COMPARE_MODEL_LIST,
    MODEL_RELIABILITY_WEIGHTS,
    _call_single_model,
    judge_multimodel_compare,
    sse_stream_multimodel,
    judge_weighted_ensemble_compare,
)

# =====================================================
# Demo 模式
# =====================================================
from services.demo import (
    is_demo_mode,
    generate_demo_report,
)