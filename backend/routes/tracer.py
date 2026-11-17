"""
Agent 决策追踪路由
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional, List, Any

from security import require_jwt_auth

router = APIRouter(prefix="/api", tags=["Agent 决策追踪"])


class TracerStartRequest(BaseModel):
    agent_id: str = "assessment-agent"


class TracerRecordRequest(BaseModel):
    observation: str = ""
    action: str = ""
    reward: float = 0.0
    thought: str = ""
    tools: List[str] = []
    confidence: float = 0.0
    error: str = ""


@router.post("/tracer/start")
async def tracer_start(req: TracerStartRequest, _: dict = Depends(require_jwt_auth)):
    """开始一个 Agent 评估回合的决策追踪"""
    from agent_tracer import DecisionTreeTracer
    from services import set_decision_tracer

    tracer = DecisionTreeTracer(req.agent_id)
    set_decision_tracer(tracer)
    node_id = tracer.start_episode(
        "初始化靶机连接，准备扫描",
        f"Agent [{req.agent_id}] 启动漏洞评估"
    )
    return {"episode_id": tracer.episode_id, "root_node_id": node_id, "agent_id": req.agent_id}


@router.post("/tracer/record")
async def tracer_record(data: TracerRecordRequest, _: dict = Depends(require_jwt_auth)):
    """记录 Agent 的一步决策"""
    from services import get_decision_tracer

    tracer = get_decision_tracer()
    node_id = tracer.record_step(
        observation=data.observation,
        action=data.action,
        reward=data.reward,
        thought=data.thought,
        tools=data.tools,
        confidence=data.confidence,
        error=data.error,
    )
    return {"node_id": node_id, "step": tracer.total_reward}


@router.get("/tracer/tree")
async def tracer_get_tree():
    """获取当前 Agent 的完整决策树"""
    from services import get_decision_tracer
    from agent_tracer import DecisionTreeTracer

    tracer = get_decision_tracer()
    tree = tracer.get_tree_data()
    timeline = DecisionTreeTracer.format_as_timeline(tree)
    return {"tree_data": tree, "timeline": timeline, "summary": tracer.summary()}
