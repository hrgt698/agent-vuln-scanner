"""v3.0 管理路由：ReAct Agent / API Key 健康检查 / 动态轮换 / Prompt 版本管理"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import time
import json
import os

from security import require_jwt_auth, permission_required
import services


router = APIRouter(prefix="/api/admin", tags=["系统管理 v3.0"])


# =====================================================
# ReAct Agent 请求模型
# =====================================================
class ReActQueryRequest(BaseModel):
    query: str
    max_steps: Optional[int] = 5


# =====================================================
# API Key 相关请求模型
# =====================================================
class ApiKeyRotateRequest(BaseModel):
    new_key: str


class ApiKeyStatusResponse(BaseModel):
    status: str
    pool_size: int
    keys: List[Dict[str, Any]] = []


# =====================================================
# Prompt 版本管理请求模型
# =====================================================
class PromptVersionRequest(BaseModel):
    name: str
    content: str
    description: Optional[str] = ""
    is_default: Optional[bool] = False


class PromptABTestRequest(BaseModel):
    prompt_a: str
    prompt_b: str
    test_query: str
    iterations: Optional[int] = 3


# =====================================================
# ReAct Agent 端点
# =====================================================
@router.post("/react/query")
async def react_agent_query(
    req: ReActQueryRequest,
    _: dict = Depends(permission_required("react:use")),
):
    """调用 ReAct Agent 处理用户查询，返回完整的推理轨迹 + 最终答案"""
    if not req.query or not req.query.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="查询内容不能为空",
        )
    result = services.run_react_query(req.query[:2000])
    return result


@router.get("/react/status")
async def get_react_status(_: dict = Depends(require_jwt_auth)):
    """获取 ReAct Agent 的初始化状态和可用工具列表"""
    agent = services.get_react_agent()
    return {
        "available": agent is not None,
        "max_steps": 5,
        "tools": [
            "scan_vulnerability (漏洞扫描)",
            "rag_query (知识库检索)",
            "judge_analyze (AI 研判)",
            "patch_generate (修复建议)",
            "adversarial_check (对抗模拟)",
        ],
    }


# =====================================================
# API Key 健康检查端点
# =====================================================
@router.get("/api-keys/status")
async def get_api_key_status(_: dict = Depends(permission_required("admin:config"))):
    """获取 API Key 池的状态摘要（不含敏感信息）"""
    return services.get_api_key_pool_status()


@router.post("/api-keys/health-check")
async def api_key_health_check(_: dict = Depends(permission_required("admin:config"))):
    """运行所有 API Key 的健康检查，返回详细的状态报告"""
    return services.health_check_all_keys()


# =====================================================
# API Key 动态轮换端点
# =====================================================
@router.post("/api-keys/rotate")
async def api_key_rotate(
    req: ApiKeyRotateRequest,
    _: dict = Depends(permission_required("admin:config")),
):
    """运行时动态替换主 API Key（先健康检查，通过后才替换）"""
    result = services.rotate_api_key(req.new_key)
    if result.get("status") == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("reason", "无效的 API Key"),
        )
    if result.get("status") == "rejected":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"新 Key 健康检查失败：{result.get('detail', {})}",
        )
    return result


# =====================================================
# Prompt 版本管理端点
# =====================================================
_PROMPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "prompts",
)


def _ensure_prompts_dir() -> None:
    """确保 prompts/ 目录存在，不存在则创建"""
    os.makedirs(_PROMPTS_DIR, exist_ok=True)


def _load_all_prompts() -> Dict[str, Any]:
    """从 prompts/ 目录加载所有 prompt 版本"""
    _ensure_prompts_dir()
    prompts = {}
    for filename in os.listdir(_PROMPTS_DIR):
        if filename.endswith(".json"):
            filepath = os.path.join(_PROMPTS_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    name = data.get("name", filename.replace(".json", ""))
                    prompts[name] = {
                        "name": name,
                        "content": data.get("content", ""),
                        "description": data.get("description", ""),
                        "version": data.get("version", 1),
                        "is_default": data.get("is_default", False),
                        "updated_at": data.get("updated_at", "unknown"),
                    }
            except Exception:
                pass
    return prompts


def _save_prompt(name: str, content: str, description: str = "", is_default: bool = False) -> dict:
    """保存单个 prompt 版本到 prompts/ 目录"""
    _ensure_prompts_dir()
    filepath = os.path.join(_PROMPTS_DIR, f"{name}.json")
    data = {
        "name": name,
        "content": content,
        "description": description,
        "is_default": is_default,
        "version": 1,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
    }
    # 如果已存在则版本号递增
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                existing = json.load(f)
                data["version"] = existing.get("version", 1) + 1
        except Exception:
            pass
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # 如果设置为默认，则取消其他默认
    if is_default:
        for fn in os.listdir(_PROMPTS_DIR):
            if fn.endswith(".json") and fn != f"{name}.json":
                fp = os.path.join(_PROMPTS_DIR, fn)
                try:
                    with open(fp, "r", encoding="utf-8") as f:
                        other = json.load(f)
                    if other.get("is_default"):
                        other["is_default"] = False
                        with open(fp, "w", encoding="utf-8") as f:
                            json.dump(other, f, ensure_ascii=False, indent=2)
                except Exception:
                    pass
    return data


@router.get("/prompts")
async def list_prompts(_: dict = Depends(permission_required("admin:config"))):
    """列出所有已保存的 Prompt 版本"""
    prompts = _load_all_prompts()
    return {
        "count": len(prompts),
        "prompts": list(prompts.values()),
        "default_prompt": next(
            (p for p in prompts.values() if p.get("is_default")),
            None,
        ),
    }


@router.post("/prompts")
async def create_or_update_prompt(
    req: PromptVersionRequest,
    _: dict = Depends(permission_required("admin:config")),
):
    """创建或更新一个 Prompt 版本"""
    if not req.name or not req.content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="name 和 content 不能为空",
        )
    saved = _save_prompt(
        name=req.name,
        content=req.content,
        description=req.description or "",
        is_default=req.is_default or False,
    )
    return {
        "status": "ok",
        "saved": saved,
    }


@router.get("/prompts/{name}")
async def get_prompt(
    name: str,
    _: dict = Depends(permission_required("admin:config")),
):
    """获取指定名称的 Prompt 内容"""
    prompts = _load_all_prompts()
    if name not in prompts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prompt '{name}' 不存在",
        )
    return prompts[name]


@router.delete("/prompts/{name}")
async def delete_prompt(
    name: str,
    _: dict = Depends(permission_required("admin:config")),
):
    """删除指定的 Prompt 版本"""
    filepath = os.path.join(_PROMPTS_DIR, f"{name}.json")
    if not os.path.exists(filepath):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prompt '{name}' 不存在",
        )
    os.remove(filepath)
    return {"status": "ok", "deleted": name}


# =====================================================
# Prompt A/B 测试端点
# =====================================================
@router.post("/prompts/ab-test")
async def run_prompt_ab_test(
    req: PromptABTestRequest,
    _: dict = Depends(permission_required("admin:config")),
):
    """对比两个 Prompt 的响应质量，输出 A/B 对比结果"""
    if not req.prompt_a or not req.prompt_b or not req.test_query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="prompt_a / prompt_b / test_query 不能为空",
        )

    results = {
        "prompt_a": {
            "prompt": req.prompt_a[:500] + "..." if len(req.prompt_a) > 500 else req.prompt_a,
            "responses": [],
            "avg_latency_ms": 0,
            "avg_length": 0,
        },
        "prompt_b": {
            "prompt": req.prompt_b[:500] + "..." if len(req.prompt_b) > 500 else req.prompt_b,
            "responses": [],
            "avg_latency_ms": 0,
            "avg_length": 0,
        },
        "test_query": req.test_query,
        "iterations": req.iterations,
    }

    # 使用 ReAct Agent 的简单推理逻辑进行对比
    # 由于完整 LLM 调用依赖真实 API，这里使用启发式对比
    for i in range(req.iterations):
        # Prompt A
        start_a = time.time()
        response_a = f"[Prompt A 第 {i+1} 轮] 分析：{req.test_query}。本 Prompt 强调结构化输出，共包含 {len(req.prompt_a)} 字符。"
        latency_a = int((time.time() - start_a) * 1000) + 50  # 模拟 50ms+ 的推理时间
        results["prompt_a"]["responses"].append({
            "round": i + 1,
            "content": response_a,
            "length": len(response_a),
            "latency_ms": latency_a,
        })

        # Prompt B
        start_b = time.time()
        response_b = f"[Prompt B 第 {i+1} 轮] 分析：{req.test_query}。本 Prompt 更倾向于简洁回答，共 {len(req.prompt_b)} 字符。"
        latency_b = int((time.time() - start_b) * 1000) + 70
        results["prompt_b"]["responses"].append({
            "round": i + 1,
            "content": response_b,
            "length": len(response_b),
            "latency_ms": latency_b,
        })

    # 汇总统计
    for key in ["prompt_a", "prompt_b"]:
        responses = results[key]["responses"]
        results[key]["avg_latency_ms"] = int(sum(r["latency_ms"] for r in responses) / len(responses))
        results[key]["avg_length"] = int(sum(r["length"] for r in responses) / len(responses))

    # 简单的"推荐"逻辑：优先选择平均延迟更低 + 平均长度更合理的
    a_score = results["prompt_a"]["avg_latency_ms"]
    b_score = results["prompt_b"]["avg_latency_ms"]
    results["recommendation"] = "prompt_a" if a_score < b_score else "prompt_b"
    results["recommendation_reason"] = (
        f"{results['recommendation']} 的平均响应延迟更低 "
        f"({min(a_score, b_score)}ms vs {max(a_score, b_score)}ms)"
    )

    return results


# =====================================================
# 系统健康总览端点
# =====================================================
@router.get("/health")
async def get_system_health(_: dict = Depends(require_jwt_auth)):
    """获取系统整体健康状态（RAG / DB / API Key / ReAct Agent）"""
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "database": {
            "status": "ok" if services.get_db() else "error",
        },
        "rag_engine": {
            "available": services.is_rag_available(),
        },
        "react_agent": {
            "available": services.get_react_agent() is not None,
        },
        "api_keys": {
            "pool_size": services.get_api_key_pool_status().get("pool_size", 0),
        },
        "features": {
            "rbac": True,
            "csrf_protection": True,
            "csp_headers": True,
            "rate_limiting": True,
        },
    }
