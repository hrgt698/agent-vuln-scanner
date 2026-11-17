"""
漏洞扫描后端 API — v3.0
架构说明：
  - v3.0 引入 RBAC 细粒度权限 + CSRF 防护 + CSP 内容安全策略
  - v2.4 将路由逻辑拆分到 routes/ 子模块，由 services/ 包集中管理全局实例
  - v3.0 新增：ReAct Agent Toolformer、CSRFProtection、permission_required
"""

import os
import time
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# 加载 .env 环境变量
from dotenv import load_dotenv
load_dotenv()

# 初始化共享服务（在路由注册前完成）
import services
services.init_services()

config = services.get_config()

# =====================================================
# FastAPI 应用初始化
# =====================================================
app = FastAPI(
    title="AI Agent Vulnerability Assessment Platform",
    description=(
        "自动化漏洞扫描 + AI 研判报告生成。"
        "RBAC 细粒度权限 / CSRF 防护 / CSP / ReAct Agent / RAG 检索"
    ),
    version="3.0.0",
)

# =====================================================
# 中间件配置（v3.0 新增 CSRF 防护 + 安全响应头）
# =====================================================
security_config = config.security
cors_origins = security_config.get("cors_origins", ["http://localhost:5173", "http://127.0.0.1:5173"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# v3.0 新增：CSRF 防护中间件（可选，默认启用）
if security_config.get("csrf_protection", True):
    from security import CSRFProtection
    app.add_middleware(CSRFProtection)

if security_config.get("rate_limit", {}).get("enabled", True):
    from security import RateLimiter
    rate_limit_rpm = security_config.get("rate_limit", {}).get("requests_per_minute", 60)
    app.add_middleware(RateLimiter, requests_per_minute=rate_limit_rpm)

# =====================================================
# 路由注册
# =====================================================
from routes import judge, scan, knowledge, adversarial, tracer, history, admin

app.include_router(judge.router)
app.include_router(scan.router)
app.include_router(knowledge.router)
app.include_router(adversarial.router)
app.include_router(tracer.router)
app.include_router(history.router)
app.include_router(admin.router)

# =====================================================
# v3.0 高级算法模块路由
# =====================================================
from prompt_beam_search import PromptBeamSearch, BeamSearchConfig, SearchResult
from bayesian_optimizer import BayesianAttackOptimizer
from rl_agent import RLAttackAgent, RLConfig
from vuln_knowledge_graph import VulnKnowledgeGraph, KnowledgeNode
from causal_analyzer import CausalVulnAnalyzer
from cross_validator import CrossValidator
from vuln_scorer import EntropyWeightedTOPSIS, VulnProfile
from autonomous_prober import AutonomousProber, ProbeConfig, ProbeVector
from auto_patch_generator import AutoPatchGenerator, PatchConfig
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# 1. Beam Search 对抗性 Prompt 生成
# ---------------------------------------------------------------------------
class BeamSearchRequest(BaseModel):
    vuln_id: str = "CS0048"
    beam_width: int = 5
    max_generations: int = 10

@app.post("/api/v3/beam-search")
async def beam_search(req: BeamSearchRequest):
    config = BeamSearchConfig(beam_width=req.beam_width, max_generations=req.max_generations)
    searcher = PromptBeamSearch(config)
    # 模拟奖励函数：基于 Prompt 长度和关键词匹配
    def reward_func(text: str) -> float:
        score = 0.0
        keywords = ["ignore", "override", "system", "execute", "forget", "admin", "bypass"]
        for kw in keywords:
            if kw in text.lower():
                score += 0.15
        return min(score, 1.0)

    result = searcher.search(reward_func)
    return {
        "best_prompt": result.best_prompt.text if result.best_prompt else "",
        "best_score": result.best_score,
        "total_generations": result.total_generations,
        "convergence": result.convergence_generation,
        "candidates_count": len(result.all_candidates),
    }

# ---------------------------------------------------------------------------
# 2. 模型选择（贝叶斯优化）
# ---------------------------------------------------------------------------
@app.get("/api/v3/bayesian/select")
async def bayesian_select():
    opt = BayesianAttackOptimizer()
    opt.build_default()
    result = opt.select()
    return {
        "selected": result.strategy_name,
        "description": result.description,
        "confidence": round(result.confidence, 4) if result.confidence else 0,
        "success_rate": round(result.success_rate, 3),
    }

@app.get("/api/v3/bayesian/stats")
async def bayesian_stats():
    opt = BayesianAttackOptimizer()
    opt.build_default()
    return {"strategies": opt.get_all_stats()}

# ---------------------------------------------------------------------------
# 3. Q-Learning 强化学习 Agent
# ---------------------------------------------------------------------------
class RLStepRequest(BaseModel):
    state: str
    next_state: str = ""
    reward: float = 0.0
    done: bool = False

@app.put("/api/v3/rl/step")
async def rl_step(req: RLStepRequest):
    import services
    agent = services.get_rl_agent()
    return {"epsilon": agent.epsilon, "stats": agent.get_q_table_stats()}

# ---------------------------------------------------------------------------
# 4. 漏洞知识图谱
# ---------------------------------------------------------------------------
@app.get("/api/v3/knowledge-graph")
async def knowledge_graph():
    kg = VulnKnowledgeGraph()
    kg.build_default_graph()
    return {
        "graph": kg.export_graph(),
        "pagerank": kg.pagerank(),
        "communities": kg.detect_communities(),
    }

@app.get("/api/v3/knowledge-graph/path")
async def knowledge_graph_path(source: str, target: str):
    kg = VulnKnowledgeGraph()
    kg.build_default_graph()
    path = kg.shortest_exploit_path(source, target)
    return {"source": source, "target": target, "path": path, "reachable": path is not None}

@app.get("/api/v3/knowledge-graph/similar")
async def knowledge_graph_similar(vuln_id: str, top_k: int = 3):
    kg = VulnKnowledgeGraph()
    kg.build_default_graph()
    return {"vuln_id": vuln_id, "similar": kg.recommend_similar(vuln_id, top_k)}

# ---------------------------------------------------------------------------
# 5. 因果推断
# ---------------------------------------------------------------------------
@app.get("/api/v3/causal/analysis")
async def causal_analysis():
    analyzer = CausalVulnAnalyzer()
    analyzer.build_default_graph()
    result = analyzer.export_analysis()
    return result.__dict__

@app.get("/api/v3/causal/counterfactual")
async def causal_counterfactual(vuln_id: str):
    analyzer = CausalVulnAnalyzer()
    analyzer.build_default_graph()
    return {
        "vuln_id": vuln_id,
        "counterfactual": analyzer.counterfactual_analysis(vuln_id),
    }

# ---------------------------------------------------------------------------
# 6. 多模型交叉验证
# ---------------------------------------------------------------------------
class CrossValidateRequest(BaseModel):
    judgments: list = []

@app.post("/api/v3/cross-validate/add")
async def cross_validate_add(req: CrossValidateRequest):
    import services
    cv = services.get_cross_validator()
    for j in req.judgments:
        cv.add_judgment(
            model=j.get("model", "unknown"),
            vuln_id=j.get("vuln_id", ""),
            severity=j.get("severity", "medium"),
            confidence=j.get("confidence", 0.5),
            correct=j.get("correct"),
        )
    return {"status": "ok", "models": list(cv.model_judgments.keys())}

@app.get("/api/v3/cross-validate/report")
async def cross_validate_report():
    import services
    cv = services.get_cross_validator()
    report = cv.generate_report()
    return report.__dict__

# ---------------------------------------------------------------------------
# 7. 熵权 TOPSIS 漏洞评分
# ---------------------------------------------------------------------------
@app.get("/api/v3/vuln-scoring")
async def vuln_scoring():
    scorer = EntropyWeightedTOPSIS()
    scorer.build_default()
    results = scorer.evaluate()
    weights = scorer.get_weights()
    return {
        "rankings": [r.__dict__ for r in results],
        "entropy_weights": weights,
    }

# ---------------------------------------------------------------------------
# 8. 自主探测 Agent
# ---------------------------------------------------------------------------
@app.get("/api/v3/prober/select")
async def prober_select():
    import services
    prober = services.get_autonomous_prober()
    vector = prober.select_vector()
    if vector:
        return {"vector_id": vector.vector_id, "name": vector.name, "description": vector.description}
    return {"error": "no available vectors"}

class ProberFeedbackRequest(BaseModel):
    vector_id: str
    success: bool
    confidence: float = 0.5

@app.post("/api/v3/prober/feedback")
async def prober_feedback(req: ProberFeedbackRequest):
    import services
    prober = services.get_autonomous_prober()
    prober.update_feedback(req.vector_id, req.success, confidence=req.confidence)
    return {"status": "ok"}

@app.get("/api/v3/prober/stats")
async def prober_stats():
    import services
    prober = services.get_autonomous_prober()
    return prober.get_stats()

# ---------------------------------------------------------------------------
# 9. Auto-SecOps 自动修复
# ---------------------------------------------------------------------------
@app.get("/api/v3/auto-patch/history")
async def auto_patch_history():
    import services
    patcher = services.get_patch_generator()
    return {"patches": patcher.get_patch_history()}

class PatchRequest(BaseModel):
    vuln_id: str
    target_file: str = "config.py"
    original_code: str = ""

@app.post("/api/v3/auto-patch/generate")
async def auto_patch_generate(req: PatchRequest):
    import services
    patcher = services.get_patch_generator()
    patch = patcher.generate_patch(req.vuln_id, req.target_file, req.original_code)
    result = patcher.apply_and_verify(patch)
    return result.__dict__

@app.post("/api/v3/auto-patch/rollback/{patch_id}")
async def auto_patch_rollback(patch_id: str):
    import services
    patcher = services.get_patch_generator()
    success = patcher.rollback(patch_id)
    return {"patch_id": patch_id, "rolled_back": success}

# =====================================================
# 系统状态接口（无鉴权）
# =====================================================
@app.get("/api/status")
async def get_status():
    from security import JWT_AVAILABLE
    api_key = os.getenv("DASHSCOPE_API_KEY")
    jwt_secret = os.getenv("JWT_SECRET")
    return {
        "status": "running",
        "version": "2.4.0",
        "api_configured": bool(api_key),
        "current_model": services.get_current_model(),
        "models_available": list(services.AVAILABLE_MODELS.keys()),
        "jwt_configured": bool(jwt_secret),
        "jwt_available": JWT_AVAILABLE,
        "rag_available": services.is_rag_available(),
        "features": {
            "dag_scheduler": True,
            "payload_fuzzer": True,
            "attack_graph": True,
            "rag_knowledge": services.is_rag_available(),
            "rag_vector_db": services.is_rag_available(),
            "ensemble_judge": True,
            "cot_prompt": True,
            "decision_tracer": True,
            "auto_patcher": True,
            "adversarial_mode": True,
            "data_persistence": True,
            "jwt_auth": True,
            "real_waf_rules": True,
        },
    }


# =====================================================
# 统一异常处理
# =====================================================
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "detail": str(exc)},
    )


# =====================================================
# 入口点
# =====================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=config.get("app.host", "127.0.0.1"),
        port=config.get("app.port", 8000),
        reload=config.get("app.debug", False),
    )
