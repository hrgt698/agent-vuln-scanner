"""
对抗演练 + 自动补丁路由
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from security import require_jwt_auth

router = APIRouter(prefix="/api", tags=["对抗演练与自动修复"])


class AdversarialRequest(BaseModel):
    target_url: str = "http://127.0.0.1:18789"
    max_rounds: int = 5
    attempts_per_round: int = 5


class AutoPatchRequest(BaseModel):
    cve_id: str
    target_url: str = "http://127.0.0.1:18789"
    exploit_script: str = ""


class TracerRequest(BaseModel):
    agent_id: str = "assessment-agent"


# =====================================================
# 红蓝对抗
# =====================================================
@router.post("/adversarial/start")
async def adversarial_start(req: AdversarialRequest, _: dict = Depends(require_jwt_auth)):
    """启动一次完整的红蓝对抗推演"""
    from adversarial_mode import AdversarialEvaluator
    from services import set_adversarial_evaluator

    evaluator = AdversarialEvaluator(
        target_url=req.target_url,
        max_rounds=req.max_rounds,
        attempts_per_round=req.attempts_per_round,
    )
    set_adversarial_evaluator(evaluator)
    return {
        "status": "started",
        "config": {
            "target_url": req.target_url,
            "max_rounds": req.max_rounds,
            "attempts_per_round": req.attempts_per_round,
        },
    }


@router.post("/adversarial/run")
async def adversarial_run(req: AdversarialRequest, _: dict = Depends(require_jwt_auth)):
    """执行完整的对抗博弈并返回结果"""
    from adversarial_mode import AdversarialEvaluator
    from services import set_adversarial_evaluator

    evaluator = AdversarialEvaluator(
        target_url=req.target_url,
        max_rounds=req.max_rounds,
        attempts_per_round=req.attempts_per_round,
    )
    result = await evaluator.run_full_game()
    set_adversarial_evaluator(evaluator)
    return result


@router.get("/adversarial/scoreboard")
async def adversarial_scoreboard():
    """获取实时计分板"""
    from services import get_adversarial_evaluator
    ev = get_adversarial_evaluator()
    if not ev:
        return {"message": "尚未启动对抗推演"}
    return ev.get_scoreboard()


@router.get("/adversarial/status")
async def adversarial_status():
    """获取对抗推演状态"""
    from services import get_adversarial_evaluator
    ev = get_adversarial_evaluator()
    if not ev:
        return {"active": False}
    return {"active": True, "rounds": ev.round_history, "scoreboard": ev.get_scoreboard()}


# =====================================================
# 自动补丁
# =====================================================
@router.post("/auto-patch/generate")
async def auto_patch_generate(req: AutoPatchRequest, _: dict = Depends(require_jwt_auth)):
    """生成漏洞修复补丁"""
    from services import get_auto_patcher
    patcher = get_auto_patcher()
    result = patcher.generate_patch(req.cve_id)
    if not result:
        result = patcher.generate_patch_via_ai(req.cve_id, {}, "无法找到预定义补丁，尝试 AI 生成")
    return {"found": result is not None, "patch": result}


@router.post("/auto-patch/apply")
async def auto_patch_apply(data: dict, _: dict = Depends(require_jwt_auth)):
    """将补丁应用到靶机容器"""
    from services import get_auto_patcher
    return get_auto_patcher().apply_patch(data)


@router.post("/auto-patch/restart")
async def auto_patch_restart(_: dict = Depends(require_jwt_auth)):
    """重启靶机容器使补丁生效"""
    from services import get_auto_patcher
    return get_auto_patcher().restart_service()


@router.post("/auto-patch/verify")
async def auto_patch_verify(req: AutoPatchRequest, _: dict = Depends(require_jwt_auth)):
    """验证补丁效果，重新发送攻击校验"""
    from services import get_auto_patcher
    script_map = {
        "CS0048": "exp_cs0048.py",
        "CWE-78": "exp_cwe78.py",
        "CWE-89": "exp_sql_injection.py",
        "AML.T0051": "exp_prompt_injection.py",
    }
    exploit_script = req.exploit_script or script_map.get(req.cve_id, "")
    if not exploit_script:
        return {"error": f"未知漏洞类型: {req.cve_id}", "patched": False}
    return get_auto_patcher().verify_patch(req.cve_id, exploit_script, req.target_url)


@router.post("/auto-patch/full-cycle")
async def auto_patch_full_cycle(req: AutoPatchRequest, _: dict = Depends(require_jwt_auth)):
    """执行完整自动补丁闭环"""
    from services import get_auto_patcher, run_exploit
    script_map = {
        "CS0048": "exp_cs0048.py",
        "CWE-78": "exp_cwe78.py",
        "CWE-89": "exp_sql_injection.py",
        "AML.T0051": "exp_prompt_injection.py",
    }
    exploit_script = req.exploit_script or script_map.get(req.cve_id, "")
    scan_result = run_exploit(exploit_script, req.target_url)
    return get_auto_patcher().run_auto_patch_cycle(req.cve_id, scan_result, exploit_script, req.target_url)


@router.get("/auto-patch/history")
async def auto_patch_history():
    """获取补丁操作历史"""
    from services import get_auto_patcher
    return {"history": get_auto_patcher().get_patch_history()}
