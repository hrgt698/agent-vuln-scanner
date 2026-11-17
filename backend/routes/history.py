"""
历史记录与统计路由
"""

from fastapi import APIRouter, Depends
from typing import Optional

from security import require_jwt_auth

router = APIRouter(prefix="/api", tags=["历史记录与统计"])


@router.get("/history/scans")
async def get_scan_history(
    target_url: Optional[str] = None,
    cve_id: Optional[str] = None,
    limit: int = 100,
):
    """获取扫描历史记录"""
    from services import get_db
    return get_db().get_scan_history(target_url=target_url, cve_id=cve_id, limit=limit)


@router.get("/history/stats")
async def get_scan_stats(target_url: Optional[str] = None):
    """获取扫描统计信息"""
    from services import get_db
    return get_db().get_scan_stats(target_url=target_url)


@router.get("/history/patches")
async def get_patch_history(limit: int = 20):
    """获取补丁历史记录"""
    from services import get_db
    return get_db().get_patch_history(limit=limit)


@router.get("/history/adversarial")
async def get_adversarial_history(limit: int = 20):
    """获取对抗历史记录"""
    from services import get_db
    return get_db().get_adversarial_history(limit=limit)


@router.get("/history/model-eval")
async def get_model_eval_history(
    eval_mode: Optional[str] = None,
    limit: int = 50,
):
    """获取模型评估历史（v2.4 新增）"""
    from services import get_db
    return get_db().get_model_eval_history(eval_mode=eval_mode, limit=limit)


@router.get("/history/model-eval/best")
async def get_model_eval_best(eval_mode: str = "full"):
    """获取某评估模式下的最高分记录"""
    from services import get_db
    return get_db().get_model_eval_best(eval_mode=eval_mode)


# =====================================================
# 性能基准测试（已添加 JWT 鉴权）
# =====================================================
@router.get("/benchmark")
async def run_benchmark(_: dict = Depends(require_jwt_auth)):
    """运行性能基准测试（需 JWT 鉴权）"""
    from benchmark import run_all_benchmarks
    result = run_all_benchmarks()
    return {"benchmark_report": result}
