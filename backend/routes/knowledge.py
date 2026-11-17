"""
知识库 + 攻击图路由
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from security import require_jwt_auth

router = APIRouter(prefix="/api", tags=["知识库与攻击图"])


@router.get("/kb/{cve_id}")
async def get_knowledge(cve_id: str):
    """查询指定 CVE 的知识库信息"""
    from services import get_rag_engine
    engine = get_rag_engine()
    if engine:
        kb_entry = engine.get_kb_entry(cve_id.upper())
        if kb_entry:
            return {"found": True, "knowledge": kb_entry}
    return {"found": False, "message": f"未找到 {cve_id} 的知识库条目"}


@router.get("/kb/summary/{cve_id}")
async def get_knowledge_summary(cve_id: str):
    """获取知识库摘要"""
    from services import get_rag_engine
    engine = get_rag_engine()
    if engine:
        return engine.get_kb_summary(cve_id.upper())
    return {"message": "RAG 引擎未初始化"}


class AttackGraphRequest(BaseModel):
    target_url: str = "http://127.0.0.1:18789"


@router.post("/attack-graph/analyze")
async def analyze_attack_graph(req: AttackGraphRequest, _: dict = Depends(require_jwt_auth)):
    """对已保存的扫描结果执行攻击图分析"""
    from services import SCRIPTS_INFO, run_exploit, get_attack_graph

    results = []
    for info in SCRIPTS_INFO:
        result = run_exploit(info[0], req.target_url)
        results.append(result)

    graph = get_attack_graph().analyze(results)
    return {
        "scan_results": results,
        "attack_graph": graph,
        "chain_description": get_attack_graph().get_attack_chain_description(
            [r.get("cve_id", "") for r in results if r.get("status") == "success"]
        ),
    }


# =====================================================
# DAG 调度信息
# =====================================================
@router.get("/scheduler/order")
async def get_scheduler_order():
    """返回 DAG 调度器的拓扑排序结果"""
    from services import build_default_scheduler
    scheduler = build_default_scheduler()
    order = scheduler.get_execution_order()
    tasks_info = {}
    for cve, task in scheduler.tasks.items():
        tasks_info[cve] = {
            "name": task.name,
            "script": task.script,
            "priority": task.priority,
            "dependencies": task.dependencies,
            "max_retries": task.max_retries,
        }
    return {"execution_order": order, "tasks": tasks_info}


@router.get("/scheduler/stats")
async def get_scheduler_stats():
    """返回自适应调度器的历史统计数据"""
    from services import SCRIPTS_INFO, get_adaptive_scheduler
    return {info[2]: get_adaptive_scheduler().get_stats(info[2]) for info in SCRIPTS_INFO}
