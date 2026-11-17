"""
多模型集成研判引擎（Ensemble Judger）
同时调用多个大模型进行一致性投票，交叉验证研判结果，提升报告可信度。
使用方式：from ensemble_judge import EnsembleJudger
"""

import asyncio
import os
import re
import html
from typing import Dict, List, Optional

import httpx  # httpx 已作为核心依赖，必须安装

class EnsembleJudger:
    """多模型集成研判引擎
    同时调用多个大模型对同一漏洞数据进行研判，
    收集各模型输出后进行一致性分析，生成综合报告。
    """

    AVAILABLE_MODELS = ["qwen-turbo", "qwen-plus", "qwen-max"]

    COT_SYSTEM_PROMPT = """你是资深网络安全工程师，请按照以下推理链逐步分析漏洞：

**步骤1 - 漏洞定位**：判断漏洞的真实类型和触发条件。
**步骤2 - 深入分析**：分析该漏洞的利用链、前置依赖和后置影响。
**步骤3 - 风险量化**：参照 CVSS 3.1 标准评估严重程度（攻击向量、攻击复杂度、权限要求、用户交互、影响范围、机密性/完整性/可用性影响）。
**步骤4 - 根因追溯**：推断漏洞产生的工程原因（如未做输入校验、使用了危险函数、配置不当等）。
**步骤5 - 分级修复**：给出立即修复（热补丁）、短期修复（代码重构）、长期修复（架构优化）三级建议。

最终按以下格式输出：
### 一、漏洞概述
（简要描述漏洞情况）

### 二、风险分析（含CVSS评分）
（分析该漏洞的风险等级、潜在危害）

### 三、根因分析
（分析漏洞产生的工程根因）

### 四、修复建议（分级）
- **立即修复**：...
- **短期修复**：...
- **长期优化**：...
"""

    def __init__(self):
        self.api_key = os.getenv("DASHSCOPE_API_KEY")

    async def judge(
        self,
        vuln_data: dict,
        models: Optional[List[str]] = None,
    ) -> dict:
        """多模型集成研判入口
        Args:
            vuln_data: 漏洞扫描结果
            models: 要调用的模型列表（默认所有可用模型）
        Returns:
            包含各模型独立报告和一致性分析的综合结果
        """
        if not self.api_key:
            return {
                "consensus_level": "none",
                "message": "未配置大模型API密钥，跳过集成研判",
                "individual_reports": {},
            }

        if models is None:
            models = self.AVAILABLE_MODELS

        # 并行调用多个模型
        tasks = [self._call_single_model(model, vuln_data) for model in models]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        reports = {}
        for model, result in zip(models, results):
            if isinstance(result, Exception):
                reports[model] = {"status": "error", "error": str(result)}
            else:
                reports[model] = {"status": "success", "report": result}

        # 一致性分析
        consensus = self._analyze_consensus(reports)

        return {
            "consensus_level": consensus["level"],
            "consensus_suggestions": consensus["suggestions"],
            "consensus_score": consensus["score"],
            "model_count": len([r for r in reports.values() if r["status"] == "success"]),
            "models_called": models,
            "individual_reports": reports,
        }

    async def _call_single_model(self, model: str, vuln_data: dict) -> str:
        """调用单个大模型进行分析（httpx 异步客户端）"""
        cve_id = html.escape(str(vuln_data.get("cve_id", "未知")))
        vuln_name = html.escape(str(vuln_data.get("vuln_name", "未知")))
        status = html.escape(str(vuln_data.get("status", "未知")))
        risk_level = html.escape(str(vuln_data.get("risk_level", "未知")))
        raw_log = str(vuln_data.get("execution_log", "无"))
        execution_log = html.escape(raw_log[:500])

        user_content = (
            f"【漏洞信息】\n"
            f"- 漏洞ID：{cve_id}\n"
            f"- 漏洞名称：{vuln_name}\n"
            f"- 执行状态：{status}\n"
            f"- 风险等级：{risk_level}\n"
            f"- 执行日志：{execution_log}"
        )

        # v2.4 新增：优先使用 JSON mode 获取结构化输出
        json_payload = {
            "model": model,
            "input": {
                "messages": [
                    {"role": "system", "content": self.COT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ]
            },
            "parameters": {"result_format": "message"},
        }

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0, read=30.0)
            ) as client:
                # 首先尝试 JSON mode
                json_response = await client.post(
                    url="https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={**json_payload, "parameters": {"result_format": "message", "response_format": {"type": "json_object"}}},
                )

                if json_response.status_code == 200:
                    json_text = json_response.json().get("output", {}).get("text", "")
                    # 尝试解析 JSON
                    try:
                        import json as _json_mod
                        parsed = _json_mod.loads(json_text)
                        return self._format_structured_output(parsed)
                    except Exception:
                        # JSON 解析失败，降级为纯文本
                        pass

                # 降级：使用普通 text mode
                text_response = await client.post(
                    url="https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={**json_payload, "parameters": {"result_format": "text"}},
                )

                if text_response.status_code == 200:
                    return text_response.json()["output"]["text"].strip()
                else:
                    return f"模型 {model} 调用失败: {text_response.status_code}"

        except Exception as e:
            return f"模型 {model} 调用异常: {str(e)}"

    def _format_structured_output(self, parsed: dict) -> str:
        """将 JSON 格式的结构化输出转换为标准文本格式"""
        sections = []
        if parsed.get("漏洞概述"):
            sections.append(f"### 一、漏洞概述\n{parsed['漏洞概述']}")
        if parsed.get("风险分析"):
            sections.append(f"### 二、风险分析\n{parsed['风险分析']}")
            if parsed.get("cvss_score"):
                sections.append(f"CVSS 评分: {parsed['cvss_score']}")
        if parsed.get("根因分析"):
            sections.append(f"### 三、根因分析\n{parsed['根因分析']}")
        if parsed.get("修复建议"):
            suggestions = parsed["修复建议"]
            sections.append("### 四、修复建议（分级）")
            if isinstance(suggestions, dict):
                for level, items in suggestions.items():
                    sections.append(f"- **{level}**：{items}")
            elif isinstance(suggestions, list):
                for item in suggestions:
                    sections.append(f"- {item}")
        if parsed.get("similar_cases"):
            sections.append("### 五、相似历史案例参考")
            for case in parsed["similar_cases"]:
                sections.append(f"- **{case.get('cve', 'N/A')}** ({case.get('year', 'N/A')}): {case.get('description', '')}")
        return "\n\n".join(sections)

    def _analyze_consensus(self, reports: Dict[str, dict]) -> dict:
        """对多个模型的报告做一致性分析
        提取各模型的修复建议关键词，统计重叠度和分歧点
        """
        successful_reports = []
        for model, r in reports.items():
            if r.get("status") == "success" and r.get("report"):
                successful_reports.append(r["report"])

        if not successful_reports:
            return {"level": "none", "suggestions": [], "score": 0.0}

        if len(successful_reports) == 1:
            return {
                "level": "single",
                "suggestions": self._extract_suggestions(successful_reports[0]),
                "score": 0.5,
            }

        # 对所有报告的修复建议做交叉分析
        all_suggestions = [
            set(self._extract_suggestions(report))
            for report in successful_reports
        ]

        common_suggestions = set.intersection(*all_suggestions) if len(all_suggestions) > 1 else set()
        union_suggestions = set.union(*all_suggestions) if all_suggestions else set()

        if union_suggestions:
            agreement_ratio = len(common_suggestions) / len(union_suggestions)
        else:
            agreement_ratio = 0.0

        if agreement_ratio >= 0.6:
            level = "high"
        elif agreement_ratio >= 0.3:
            level = "medium"
        else:
            level = "low"

        return {
            "level": level,
            "suggestions": list(common_suggestions) if common_suggestions else list(union_suggestions),
            "score": round(agreement_ratio, 2),
            "total_reports": len(successful_reports),
            "agreement_ratio": agreement_ratio,
        }

    def _extract_suggestions(self, report: str) -> List[str]:
        """从 AI 报告中提取核心修复建议（v2.4：增加多种匹配策略和 fallback）"""
        if not report or not isinstance(report, str):
            return []

        suggestions = []

        # 策略1：匹配结构化 JSON 格式（v2.4 新增）
        try:
            import json as _json_mod
            # 尝试从报告文本中提取 JSON 对象
            json_match = re.search(r"\{[\s\S]*\}", report)
            if json_match:
                parsed = _json_mod.loads(json_match.group())
                if isinstance(parsed, dict):
                    if parsed.get("修复建议"):
                        rec = parsed["修复建议"]
                        if isinstance(rec, list):
                            suggestions.extend([str(r) for r in rec[:8] if len(str(r)) > 5])
                        elif isinstance(rec, dict):
                            for v in rec.values():
                                if isinstance(v, list):
                                    suggestions.extend([str(i) for i in v[:4] if len(str(i)) > 5])
                                elif isinstance(v, str) and len(v) > 5:
                                    suggestions.append(v)
                    if parsed.get("cvss_score"):
                        suggestions.append(f"CVSS 评分: {parsed['cvss_score']}")
                    if suggestions:
                        return suggestions[:8]
        except Exception:
            pass  # JSON 解析失败，继续用正则

        # 策略2：匹配「修复建议」段落
        fix_section = re.search(
            r"(?:修复建议|建议|推荐修复|修复方案).*?(?=\n###|\n##|\n---|$)",
            report,
            re.DOTALL | re.IGNORECASE,
        )
        if fix_section:
            section_text = fix_section.group()
            # 提取列表项（支持多种格式）
            items = re.findall(
                r"[-*\d]+\.?\s*(.+?)(?=\n[-*\d]|\n###|\n##|\n---|$)",
                section_text,
            )
            suggestions.extend(
                item.strip() for item in items if len(item.strip()) > 5
            )

        # 策略3：匹配 **加粗** 关键词（常见于修复项）
        bold_items = re.findall(r"\*\*([^*]{10,80}?)\*\*", report)
        suggestions.extend(
            item.strip()
            for item in bold_items
            if any(kw in item for kw in ["修复", "建议", "防护", "参数化", "校验", "隔离", "token"])
        )

        # 策略4：匹配 CVSS 评分
        cvss_match = re.search(
            r"CVSS\s*[:：]?\s*(\d+\.?\d*)",
            report,
            re.IGNORECASE,
        )
        if cvss_match:
            suggestions.append(f"CVSS 评分: {cvss_match.group(1)}")

        # 策略5（最终fallback）：如果什么都没提取到，返回报告前 200 字作为摘要
        if not suggestions:
            clean = re.sub(r"#{1,3}\s+", "", report[:200]).strip()
            if clean:
                suggestions.append(f"报告摘要: {clean}")

        # 去重并返回最多 8 条
        seen, result = set(), []
        for s in suggestions:
            norm = s.lower().strip()
            if norm and norm not in seen:
                seen.add(norm)
                result.append(s)
        return result[:8]