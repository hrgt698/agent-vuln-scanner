"""
扫描路由
包含流式扫描、批量扫描等核心功能。
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
import asyncio

from security import require_jwt_auth

router = APIRouter(prefix="/api", tags=["漏洞扫描"])


class ScanRequest(BaseModel):
    target_url: str = "http://127.0.0.1:18789"
    model: Optional[str] = "qwen-turbo"
    enable_fuzzer: Optional[bool] = True
    enable_ensemble: Optional[bool] = False


# =====================================================
# 流式扫描
# =====================================================
@router.post("/scan/stream")
async def scan_stream(req: ScanRequest, _: dict = Depends(require_jwt_auth)):
    """流式扫描：DAG 调度 + Fuzzer 变异 + SSE 实时推送"""
    from services import (
        build_default_scheduler, SCRIPTS_INFO, run_exploit,
        get_adaptive_scheduler, get_attack_graph,
        sse_data, try_fuzz_payload,
    )
    from fuzzer import PayloadFuzzer

    async def generate():
        scheduler = build_default_scheduler()
        name_map = {info[2]: info[1] for info in SCRIPTS_INFO}
        total = len(SCRIPTS_INFO)

        yield sse_data({"type": "dag_order", "order": scheduler.get_execution_order()})

        results = []
        for idx, cve in enumerate(scheduler.get_execution_order()):
            script = None
            for info in SCRIPTS_INFO:
                if info[2] == cve:
                    script = info[0]
                    break
            if not script:
                continue

            name = name_map.get(cve, cve)
            yield sse_data({"type": "start", "index": idx + 1, "total": total, "name": name, "cve": cve})
            await asyncio.sleep(0.05)
            yield sse_data({"type": "progress", "message": f"🔍 [{idx+1}/{total}] 正在执行 {name}..."})
            await asyncio.sleep(0.05)

            start_time = asyncio.get_event_loop().time()
            result_data = run_exploit(script, req.target_url, attempt=1)

            if result_data.get("status") != "success" and req.enable_fuzzer:
                fuzzer = PayloadFuzzer.get_fuzzer_for_cve(cve)
                if fuzzer:
                    yield sse_data({"type": "log", "message": "⚡ 初始利用失败，启动 Fuzzer 变异 Payload..."})
                    for variant in fuzzer:
                        variant_result = try_fuzz_payload(cve, variant, req.target_url)
                        if variant_result.get("status") == "success":
                            result_data = variant_result
                            yield sse_data({"type": "log", "message": f"✅ Fuzzer 变异 Payload 成功！({variant[:40]}...)"})
                            break

            duration = asyncio.get_event_loop().time() - start_time
            get_adaptive_scheduler().record_result(cve, result_data.get("status") == "success", duration)
            result_data["analysis_report"] = result_data.get("analysis_report", "")
            results.append(result_data)

            exec_log = result_data.get("execution_log", "")
            if exec_log:
                for log_line in exec_log.strip().split("\n")[-5:]:
                    if log_line.strip():
                        yield sse_data({"type": "log", "message": log_line})
                        await asyncio.sleep(0.08)

            status_text = "✅ 利用成功" if result_data.get("status") == "success" else "❌ 利用失败"
            yield sse_data({
                "type": "result", "name": name, "cve": cve,
                "status": result_data.get("status"),
                "status_text": status_text,
                "leaked_data": result_data.get("leaked_data"),
                "full_result": result_data,
            })
            await asyncio.sleep(0.1)

        graph = get_attack_graph().analyze(results)
        yield sse_data({"type": "attack_graph", "analysis": graph})
        yield sse_data({"type": "complete"})

    return StreamingResponse(generate(), media_type="text/event-stream")


# =====================================================
# 批量扫描
# =====================================================
@router.post("/scan/all")
async def scan_all(req: ScanRequest, _: dict = Depends(require_jwt_auth)):
    """批量扫描：DAG 调度 + 攻击图关联分析"""
    from services import (
        SCRIPTS_INFO, run_exploit, generate_report,
        get_adaptive_scheduler, get_attack_graph,
        get_db, ScanRecord,
    )

    task_results = {}
    for info in SCRIPTS_INFO:
        script, cve = info[0], info[2]
        start_time = asyncio.get_event_loop().time()
        result = run_exploit(script, req.target_url)
        duration = asyncio.get_event_loop().time() - start_time

        get_adaptive_scheduler().record_result(cve, result.get("status") == "success", duration)
        result["analysis_report"] = generate_report(result)
        task_results[cve] = result

        # 持久化
        scan_record = ScanRecord(
            target_url=req.target_url,
            cve_id=cve,
            vuln_name=result.get("vuln_name", ""),
            status=result.get("status", ""),
            risk_level=result.get("risk_level", ""),
            leaked_data=result.get("leaked_data"),
            execution_log=result.get("execution_log", ""),
            analysis_report=result.get("analysis_report", ""),
            timestamp=int(asyncio.get_event_loop().time()),
            duration=duration,
        )
        get_db().save_scan_record(scan_record)

    results_list = [task_results[info[2]] for info in SCRIPTS_INFO]
    graph_analysis = get_attack_graph().analyze(results_list)

    return {
        "total": len(results_list),
        "success": sum(1 for r in results_list if r.get("status") == "success"),
        "results": results_list,
        "attack_graph_analysis": graph_analysis,
        "scheduler_stats": {
            info[2]: get_adaptive_scheduler().get_stats(info[2]) for info in SCRIPTS_INFO
        },
    }
