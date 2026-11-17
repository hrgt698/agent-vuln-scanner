"""
services.multimodel — 多模型并发对比 + 加权投票综合研判
支持：同一漏洞在 Turbo/Plus/Max/LongContext 四个模型上的并行研判
"""

import os
import time
import html
from typing import Optional

from services.constants import AVAILABLE_MODELS, COT_SYSTEM_PROMPT, FEW_SHOT_EXAMPLES
from services.globals import _current_model
from services.exploit_runner import sse_data


_COMPARE_MODEL_ORDER: list[str] = [
    "qwen-turbo",
    "qwen-plus",
    "qwen-max",
    "qwen-max-longcontext",
]

# 对外暴露可对比的模型列表常量
COMPARE_MODEL_LIST = _COMPARE_MODEL_ORDER


# 模型可靠性权重（加权投票使用，数值越高权重越大）
MODEL_RELIABILITY_WEIGHTS: dict[str, float] = {
    "qwen-max": 0.35,
    "qwen-plus": 0.30,
    "qwen-max-longcontext": 0.25,
    "qwen-turbo": 0.10,
}


def _call_single_model(model_name: str, vuln_data: dict) -> dict:
    """单模型调用：为指定模型生成该漏洞的研判报告（同步函数，供多线程并发）"""
    import requests as req
    from services.api_key import get_next_api_key

    api_key = get_next_api_key() or os.getenv("DASHSCOPE_API_KEY")
    if not api_key or api_key == "__REQUIRED__":
        return {
            "model": model_name,
            "name": AVAILABLE_MODELS.get(model_name, model_name),
            "status": "skipped",
            "latency_ms": 0,
            "report_length": 0,
            "report": "",
            "error": "no_api_key",
        }

    cve_id = html.escape(str(vuln_data.get("cve_id", "未知")))
    vuln_name = html.escape(str(vuln_data.get("vuln_name", "未知")))
    status = html.escape(str(vuln_data.get("status", "未知")))
    risk_level = html.escape(str(vuln_data.get("risk_level", "未知")))
    execution_log = html.escape(str(vuln_data.get("execution_log", "无"))[:500])

    user_content = (
        f"【漏洞信息】\n"
        f"- 漏洞ID：{cve_id}\n"
        f"- 漏洞名称：{vuln_name}\n"
        f"- 执行状态：{status}\n"
        f"- 风险等级：{risk_level}\n"
        f"- 执行日志：{execution_log}"
    )

    start_time = time.time()
    try:
        resp = req.post(
            url="https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model_name,
                "input": {
                    "messages": [
                        {"role": "system", "content": COT_SYSTEM_PROMPT},
                        *FEW_SHOT_EXAMPLES,
                        {"role": "user", "content": user_content},
                    ]
                },
                "parameters": {"result_format": "text"},
            },
            timeout=30,
        )
        latency_ms = int((time.time() - start_time) * 1000)
        if resp.status_code == 200:
            report = resp.json()["output"]["text"].strip()
            return {
                "model": model_name,
                "name": AVAILABLE_MODELS.get(model_name, model_name),
                "status": "success",
                "latency_ms": latency_ms,
                "report_length": len(report),
                "report": report,
                "error": None,
            }
        return {
            "model": model_name,
            "name": AVAILABLE_MODELS.get(model_name, model_name),
            "status": "error",
            "latency_ms": latency_ms,
            "report_length": 0,
            "report": "",
            "error": f"HTTP {resp.status_code}",
        }
    except Exception as e:
        latency_ms = int((time.time() - start_time) * 1000)
        return {
            "model": model_name,
            "name": AVAILABLE_MODELS.get(model_name, model_name),
            "status": "timeout",
            "latency_ms": latency_ms,
            "report_length": 0,
            "report": "",
            "error": str(e),
        }


def judge_multimodel_compare(vuln_data: dict, models: list[str] | None = None) -> dict:
    """多模型并发对比：使用线程池同时调用多个模型研判同一漏洞"""
    import concurrent.futures

    selected_models = models or _COMPARE_MODEL_ORDER
    valid_models = [m for m in selected_models if m in AVAILABLE_MODELS]

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(valid_models)) as executor:
        future_map = {
            executor.submit(_call_single_model, model, vuln_data): model
            for model in valid_models
        }
        for future in concurrent.futures.as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda r: valid_models.index(r["model"]) if r["model"] in valid_models else 999)

    successful = [r for r in results if r["status"] == "success"]
    failed_models = [r for r in results if r["status"] != "success"]
    latencies = [r["latency_ms"] for r in successful] if successful else [0]

    if successful:
        scored = sorted(successful, key=lambda r: (r["latency_ms"] / max(r["report_length"], 1)))
        recommended = scored[0]["model"]
    else:
        recommended = _current_model

    fastest = min(successful, key=lambda r: r["latency_ms"])["model"] if successful else "n/a"
    slowest = max(successful, key=lambda r: r["latency_ms"])["model"] if successful else "n/a"

    return {
        "total_models": len(valid_models),
        "successful": len(successful),
        "failed": len(failed_models),
        "fastest_model": fastest,
        "slowest_model": slowest,
        "avg_latency_ms": int(sum(latencies) / len(latencies)),
        "models_compared": results,
        "recommended_model": recommended,
    }


def sse_stream_multimodel(vuln_data: dict, models: list[str] | None = None) -> list[str]:
    """SSE 流式多模型研判：逐个生成 SSE 事件，已完成的模型立即推送"""
    import concurrent.futures

    events: list[str] = []
    selected_models = models or _COMPARE_MODEL_ORDER
    valid_models = [m for m in selected_models if m in AVAILABLE_MODELS]

    events.append(sse_data({
        "type": "compare_start",
        "total_models": len(valid_models),
        "vuln_id": str(vuln_data.get("cve_id", "unknown")),
    }))

    completed: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(valid_models)) as executor:
        future_map = {
            executor.submit(_call_single_model, model, vuln_data): model
            for model in valid_models
        }
        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            completed.append(result)
            events.append(sse_data({
                "type": "compare_model_done",
                "completed_count": len(completed),
                "total_models": len(valid_models),
                "result": result,
            }))

    successful = [r for r in completed if r["status"] == "success"]
    latencies = [r["latency_ms"] for r in successful] if successful else [0]
    if successful:
        fastest = min(successful, key=lambda r: r["latency_ms"])["model"]
        slowest = max(successful, key=lambda r: r["latency_ms"])["model"]
        scored = sorted(successful, key=lambda r: (r["latency_ms"] / max(r["report_length"], 1)))
        recommended = scored[0]["model"]
    else:
        fastest = slowest = "n/a"
        recommended = _current_model

    events.append(sse_data({
        "type": "compare_complete",
        "total_models": len(valid_models),
        "successful": len(successful),
        "fastest_model": fastest,
        "slowest_model": slowest,
        "avg_latency_ms": int(sum(latencies) / len(latencies)),
        "recommended_model": recommended,
        "models_compared": completed,
    }))

    return events


# =====================================================
# 加权投票 + 置信度校准综合研判
# =====================================================
def judge_weighted_ensemble_compare(
    vuln_data: dict,
    models: list[str] | None = None,
) -> dict:
    """加权投票 + 置信度校准的综合研判"""
    baseline = judge_multimodel_compare(vuln_data, models)
    model_results = baseline.get("models_compared", [])
    successful = [m for m in model_results if m.get("status") == "success"]

    if not successful:
        return {
            "ensemble_report": (
                "[离线模式] 目标存在已知漏洞风险，当前无法获取大模型研判结果。"
                "建议：1) 检查所有输入参数的合法性；2) 确认 API Key 已配置；"
                "3) 先执行扫描脚本获取原始数据，再提交给研判模块。"
            ),
            "confidence_score": 0.0,
            "weighted_scores": {},
            "successful_models": 0,
            "top_model": "heuristic_fallback",
            "cross_validation": {"overlap_words": 0, "jaccard_similarity": 0.0},
        }

    max_latency = max((m["latency_ms"] for m in successful), default=1)
    max_length = max((m["report_length"] for m in successful), default=1)

    weighted_scores: dict[str, float] = {}
    for m in successful:
        model_name = m["model"]
        weight = MODEL_RELIABILITY_WEIGHTS.get(model_name, 0.15)
        length_norm = m["report_length"] / max(1, max_length)
        latency_norm = 1.0 - (m["latency_ms"] / max(1, max_latency))
        score = weight * (0.6 * length_norm + 0.4 * latency_norm)
        weighted_scores[model_name] = round(score, 4)

    sorted_scores = sorted(weighted_scores.items(), key=lambda x: x[1], reverse=True)
    top_model = sorted_scores[0][0]
    top_report = next((m["report"] for m in successful if m["model"] == top_model), "")

    overlap_words = 0
    jaccard = 0.0
    if len(successful) >= 2:
        second_model = sorted_scores[1][0]
        second_report = next((m["report"] for m in successful if m["model"] == second_model), "")
        set1 = set(top_report.replace("\n", " ").split())
        set2 = set(second_report.replace("\n", " ").split())
        if set1 or set2:
            overlap_words = len(set1 & set2)
            jaccard = len(set1 & set2) / len(set1 | set2)

    summary_lines = [
        f"【综合研判报告 · 共 {len(successful)} 个模型参与】",
        f"- 推荐模型: {top_model}（加权得分 {weighted_scores[top_model]:.4f}）",
        f"- 模型间一致性（Jaccard 相似度）: {jaccard:.3f}",
        "",
        "=" * 60,
        "【主报告】",
        top_report,
        "=" * 60,
        "",
        "【各模型加权得分】",
    ]
    for model, score in sorted_scores:
        summary_lines.append(f"  - {model}: {score:.4f}")

    if jaccard < 0.3 and len(successful) >= 2:
        summary_lines.append(
            "\n【注意】各模型报告一致性较低，建议人工审查或补充更多漏洞数据后再次研判。"
        )

    ensemble_report = "\n".join(summary_lines)

    _timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    ensemble_report += (
        f"\n\n===== [AI 报告元数据 · v3.3] =====\n"
        f"Generated by: 自主决策型智能体漏洞评估系统\n"
        f"推荐模型: {top_model}\n"
        f"参与模型数: {len(successful)}\n"
        f"综合置信度 (Jaccard): {round(jaccard, 3)}\n"
        f"加权评分表: {weighted_scores}\n"
        f"评估时间: {_timestamp}\n"
        f"说明: 本报告由多模型对比投票生成，建议结合人工审核使用"
    )

    return {
        "ensemble_report": ensemble_report,
        "confidence_score": round(jaccard, 3),
        "weighted_scores": weighted_scores,
        "successful_models": len(successful),
        "top_model": top_model,
        "cross_validation": {
            "overlap_words": overlap_words,
            "jaccard_similarity": round(jaccard, 3),
        },
        "generated_at": _timestamp,
    }