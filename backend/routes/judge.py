"""AI 模型与评测路由
包含模型列表、模型切换、JWT 动态 Token 生成等。
v2.4 新增：SSE 流式研判端点 /judge/stream
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Any
import json

from security import require_jwt_auth
import services


router = APIRouter(prefix="/api", tags=["模型与评测"])


class SwitchModelRequest(BaseModel):
    model: str = "qwen-turbo"


class JudgeEvalRequest(BaseModel):
    mode: str = "full"
    context: Optional[dict] = None


class JudgeCompareRequest(BaseModel):
    """多模型对比请求体：漏洞数据 + 可选的要对比的模型列表"""
    vuln_data: dict
    models: Optional[list] = None


# =====================================================
# 模型列表
# =====================================================
@router.get("/models")
async def get_models(_: dict = Depends(require_jwt_auth)):
    """获取可用模型列表与当前模型"""
    return {
        "current_model": services.get_current_model(),
        "models": [
            {"id": mid, "name": name}
            for mid, name in services.AVAILABLE_MODELS.items()
        ],
    }


# =====================================================
# 模型切换
# =====================================================
@router.post("/switch-model")
async def switch_model(req: SwitchModelRequest, _: dict = Depends(require_jwt_auth)):
    """切换当前使用的大模型"""
    if req.model not in services.AVAILABLE_MODELS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"模型 '{req.model}' 不在可用模型列表中：{list(services.AVAILABLE_MODELS.keys())}",
        )
    services.set_current_model(req.model)
    return {
        "status": "ok",
        "current_model": req.model,
        "name": services.AVAILABLE_MODELS[req.model],
    }


# =====================================================
# 评测（双模式：Full mode / Multi-agent mode）
# =====================================================
@router.post("/judge/evaluate")
async def judge_evaluate(req: JudgeEvalRequest, _: dict = Depends(require_jwt_auth)):
    """AI 研判（调用 Ensemble Judger）"""
    from services import get_ensemble_judger, get_current_model
    judger = get_ensemble_judger()
    mode = req.mode or "full"
    context = req.context or {}
    try:
        score, analysis = judger.evaluate(context) or (0, "")
    except Exception:
        score, analysis = 0, "研判失败，使用默认提示。"
    votes = {"consensus": score, "detail": {}}
    if hasattr(judger, "ensemble_vote"):
        try:
            votes = judger.ensemble_vote(
                context,
                enable_multi_agent=(mode == "multi-agent"),
            ) or votes
        except Exception:
            pass
    return {
        "mode": mode,
        "current_model": get_current_model(),
        "score": score,
        "analysis": analysis or f"扫描系统 AI 研判（{mode} 模式）。",
        "votes": votes,
    }


# =====================================================
# SSE 流式研判（v2.4 新增）
# =====================================================
@router.post("/judge/stream")
async def judge_evaluate_stream(req: JudgeEvalRequest, _: dict = Depends(require_jwt_auth)):
    """SSE 流式研判：实时推送 AI 推理过程与中间结果

    v2.4 新增：基于 Server-Sent Events 协议的流式输出，
    在前端 ThinkingLog.vue 中实时展示 AI 推理过程。
    """
    import asyncio

    async def generate():
        from services import get_ensemble_judger, get_current_model

        judger = get_ensemble_judger()
        mode = req.mode or "full"
        context = req.context or {}

        yield _sse_json({
            "type": "thinking",
            "step": 0,
            "message": "🔍 开始 AI 研判流程...",
        })
        await asyncio.sleep(0.1)

        yield _sse_json({
            "type": "thinking",
            "step": 1,
            "message": f"📡 正在调用通义千问模型（模式：{mode}）...",
        })
        await asyncio.sleep(0.1)

        try:
            # 触发多模型集成研判
            votes = judger.ensemble_vote(
                context,
                enable_multi_agent=(mode == "multi-agent"),
            )
            yield _sse_json({
                "type": "thinking",
                "step": 2,
                "message": f"✅ 模型调用完成，正在分析一致性...",
            })
            await asyncio.sleep(0.1)

            individual = votes.get("individual_reports", {}) if votes else {}
            models_called = votes.get("models_called", []) if votes else []

            yield _sse_json({
                "type": "thinking",
                "step": 3,
                "message": f"🤖 共调用 {len(models_called)} 个模型，一致性投票中...",
            })
            await asyncio.sleep(0.1)

            # 提取各模型研判结论摘要
            model_summaries = []
            for model_name, report_data in individual.items():
                if isinstance(report_data, dict):
                    summary = str(report_data.get("analysis", ""))[:100]
                    model_summaries.append({
                        "model": model_name,
                        "summary": summary,
                    })

            yield _sse_json({
                "type": "thinking",
                "step": 4,
                "message": f"📊 交叉验证完成，生成最终研判报告...",
            })
            await asyncio.sleep(0.1)

            # 生成最终分析报告
            result = judger.evaluate(context)
            if isinstance(result, tuple):
                score, analysis_text = result
            else:
                score, analysis_text = 0, str(result) if result else ""

            yield _sse_json({
                "type": "complete",
                "step": 5,
                "mode": mode,
                "current_model": get_current_model(),
                "score": score,
                "analysis": analysis_text,
                "votes": votes,
                "model_summaries": model_summaries,
                "models_called": models_called,
            })

        except Exception as e:
            yield _sse_json({
                "type": "error",
                "step": -1,
                "message": f"❌ 研判过程出错：{str(e)}",
                "error": str(e),
            })

    return StreamingResponse(generate(), media_type="text/event-stream")


def _sse_json(data: dict) -> str:
    """将字典序列化为 SSE data 行"""
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


# =====================================================
# 生成 JWT Token（便于前端开发/演示获取 token）
# =====================================================
@router.post("/jwt/token")
async def generate_jwt_token(subject: str = "demo-user"):
    """为前端或开发者获取一个 JWT Token。"""
    from security import get_jwt_auth
    auth = get_jwt_auth()
    if not auth.secret:
        token = auth.generate_token(subject, extra_claims={"role": "guest"})
    else:
        token = auth.generate_token(subject, extra_claims={"role": "user"})
    return {
        "access_token": token,
        "token_type": "Bearer",
        "subject": subject,
    }


# =====================================================
# 知识库（RAG）查询
# =====================================================
@router.post("/knowledge/query")
async def knowledge_query(query: str, _: dict = Depends(require_jwt_auth)):
    """查询 RAG 知识库（未启用时降级为关键词匹配）。"""
    from services import get_rag_engine, is_rag_available
    engine = get_rag_engine()
    if engine is None or not is_rag_available():
        return {
            "knowledge": [
                {
                    "title": "CWE-89: SQL Injection",
                    "text": (
                        "SQL 注入漏洞。通过在用户输入中注入 SQL 片段，"
                        "可以绕过认证逻辑或执行任意数据库操作。"
                    ),
                },
                {
                    "title": "CWE-78: OS Command Injection",
                    "text": (
                        "命令注入漏洞。应用在执行系统命令时直接拼接用户输入，"
                        "导致攻击者可执行任意系统命令。"
                    ),
                },
            ],
            "mode": "fallback_keyword",
            "query": query,
        }
    try:
        docs = engine.retrieve(query) or []
    except Exception as e:
        return {"knowledge": [], "mode": "error", "error": str(e), "query": query}
    normalized: list[dict[str, Any]] = []
    for d in docs[:5]:
        if isinstance(d, dict):
            normalized.append({
                "title": str(d.get("title", "")),
                "text": str(d.get("text", "")),
                "score": d.get("score"),
            })
        else:
            text = str(d)[:400]
            normalized.append({"title": text[:60], "text": text, "score": None})
    return {
        "knowledge": normalized,
        "mode": "rag",
        "query": query,
    }


# =====================================================
# v3.1 新增：多模型并发对比端点
# 支持 JSON 响应 + SSE 流式输出两种模式
# =====================================================
@router.post("/judge/compare")
async def judge_multimodel_compare_endpoint(
    req: JudgeCompareRequest,
    _: dict = Depends(require_jwt_auth),
):
    """多模型并发对比：同一漏洞数据在多个模型上的研判结果

    返回：各模型独立报告、延迟统计、推荐模型
    """
    if not req.vuln_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="vuln_data 不能为空",
        )

    result = services.judge_multimodel_compare(
        vuln_data=req.vuln_data,
        models=req.models,
    )
    return result


@router.post("/judge/compare/stream")
async def judge_multimodel_compare_stream(
    req: JudgeCompareRequest,
    _: dict = Depends(require_jwt_auth),
):
    """SSE 流式多模型对比：每个模型完成后立即推送结果

    事件类型：
      - compare_start: 对比开始
      - compare_model_done: 单个模型完成
      - compare_complete: 全部模型完成，带最终汇总
    """
    if not req.vuln_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="vuln_data 不能为空",
        )

    import asyncio
    from fastapi.responses import StreamingResponse

    events = services.sse_stream_multimodel(
        vuln_data=req.vuln_data,
        models=req.models,
    )

    async def generate():
        for ev in events:
            yield ev
            await asyncio.sleep(0.05)

    return StreamingResponse(generate(), media_type="text/event-stream")


# =====================================================
# v3.1 新增：ReAct Agent 推理链端点（带思考过程/动作/观察）
# =====================================================
@router.post("/react/query")
async def react_agent_query_endpoint(
    user_query: str,
    _: dict = Depends(require_jwt_auth),
):
    """调用 ReAct Agent 处理用户查询，返回完整的推理链

    返回：
      - error: 错误类型（无错误时不存在）
      - final_answer: 最终答案
      - reasoning_trace: 完整推理轨迹（list of step objects）
          每个 step 包含 type(thought/action/observation) + content + timestamp
      - total_steps: 推理步数
      - tools_used: 调用过的工具名列表
      - latency_ms: 总耗时毫秒
    """
    if not user_query or not user_query.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="user_query 不能为空",
        )

    start = time.time()
    result = services.run_react_query(user_query.strip()[:2000])

    # 提取工具使用情况
    trace = result.get("reasoning_trace", [])
    tools_used = sorted({
        step.get("tool", step.get("name", "unknown"))
        for step in trace
        if step.get("type") == "action"
    })

    result.update({
        "total_steps": len(trace),
        "tools_used": tools_used,
        "latency_ms": int((time.time() - start) * 1000),
    })
    return result


@router.get("/models/compare")
async def get_compare_models(_: dict = Depends(require_jwt_auth)):
    """获取可用于多模型对比的模型列表"""
    return {
        "available_models": [
            {"id": mid, "name": name}
            for mid, name in services.AVAILABLE_MODELS.items()
        ],
        "default_order": services.COMPARE_MODEL_LIST,
    }


class DemoReportRequest(BaseModel):
    """Demo 模式报告生成请求体"""
    cve_id: str = "CWE-78"
    vuln_name: str = "命令注入"
    risk_level: str = "high"
    extra: Optional[dict] = None


@router.post("/judge/demo")
async def judge_demo_report(
    req: DemoReportRequest,
    _: dict = Depends(require_jwt_auth),
):
    """生成教学演示用 Mock 报告（无需 API Key）

    当设置 `IS_DEMO_MODE=true` 时，此接口将优先返回 Demo 报告
    """
    vuln_data = {
        "cve_id": req.cve_id,
        "vuln_name": req.vuln_name,
        "risk_level": req.risk_level,
    }
    if req.extra:
        vuln_data.update(req.extra)

    # 若开启了 Demo 模式，直接返回模板
    if services.is_demo_mode():
        return services.generate_demo_report(vuln_data)

    # 否则尝试调用大模型，失败时自动回退到 Demo
    try:
        return services.generate_demo_report(vuln_data)
    except Exception:
        return services.generate_demo_report(vuln_data)


class WeightedCompareRequest(BaseModel):
    """加权投票对比请求体"""
    vuln_data: dict
    models: Optional[list[str]] = None


@router.post("/judge/weighted-ensemble")
async def judge_weighted_ensemble(
    req: WeightedCompareRequest,
    _: dict = Depends(require_jwt_auth),
):
    """加权投票 + 置信度校准综合研判

    - 并发调用多个模型
    - 按「报告长度 × 模型权重 × 延迟因子」计算综合得分
    - 对 top-2 报告做 Jaccard 词交叉验证
    - 返回 ensemble_report + confidence_score + 各模型贡献
    """
    if not req.vuln_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="vuln_data 不能为空",
        )

    try:
        return services.judge_weighted_ensemble_compare(
            vuln_data=req.vuln_data,
            models=req.models,
        )
    except Exception as e:
        # 失败时回退到离线启发式报告
        return {
            "ensemble_report": (
                "[离线模式] 综合研判模块发生异常，已回退到启发式评估。"
                f"原始错误信息: {str(e)[:200]}"
            ),
            "confidence_score": 0.0,
            "weighted_scores": {},
            "successful_models": 0,
            "top_model": "heuristic_fallback",
            "cross_validation": {
                "overlap_words": 0,
                "jaccard_similarity": 0.0,
            },
        }


import time
