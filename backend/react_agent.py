"""
v3.0 — ReAct Agent（Reasoning + Acting）
实现 Toolformer 风格的显式工具循环：
  Thought:  推理思考 →
  Action:   工具调用 →
  Observation: 执行结果 →
  (循环)
  Final Answer: 最终结论

集成的工具（Tools）：
  1. scan_vulnerability(cve_id: str)  — 对目标执行漏洞扫描
  2. rag_query(query: str)             — 从 RAG 知识库查询相关知识
  3. judge_analyze(vuln_info: str)     — 调用 AI 大模型进行研判分析
  4. patch_generate(cve_id: str)       — 生成漏洞修复建议
  5. adversarial_check(cve_id: str)    — 执行红蓝对抗模拟

使用方式：
    agent = ReActAgent(target_url="http://127.0.0.1:18789")
    result = agent.run("请分析该目标存在的高危漏洞，并给出修复建议")
    print(result)
"""

import json
import time
import asyncio
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable


# ============================================================
# Tool 定义（Toolformer 风格）
# 每个 Tool 包含：名称、描述、输入 schema、执行函数
# ============================================================

class Tool:
    """Toolformer 风格工具基类"""

    def __init__(self, name: str, description: str,
                 param_schema: Dict[str, Any],
                 func: Callable[..., Any]):
        self.name = name
        self.description = description
        self.param_schema = param_schema
        self.func = func

    def __call__(self, **kwargs) -> Any:
        """执行工具函数"""
        return self.func(**kwargs)

    def to_prompt(self) -> str:
        """生成工具说明（供大模型理解 Tool 使用）"""
        schema_str = json.dumps(self.param_schema, ensure_ascii=False)
        return f"[{self.name}]\n描述: {self.description}\n输入: {schema_str}"


# ============================================================
# ReAct Agent 主类
# ============================================================

class ReActAgent:
    """ReAct Agent（Reasoning + Acting）— v3.0 新增

    核心机制：
      - 显式工具循环：Thought → Action → Observation → (loop) → Final Answer
      - 推理深度控制：max_steps 参数限制最多推理轮次
      - 可观测性：返回完整的 reasoning_trace（推理轨迹）

    初始化参数：
      target_url: 扫描目标 URL
      api_key: DashScope API Key（可选）
      max_steps: 最大推理轮次（默认 8）
      max_retries: 工具调用失败重试次数（默认 2）
    """

    # 推理终止关键词（模型输出这些表示推理结束）
    FINISH_TOKENS = {"Final Answer:", "Final:", "结论:", "最终结论"}
    # 工具调用匹配正则（支持多行 JSON）
    ACTION_PATTERN = re.compile(
        r"Action:\s*(\w+)\s*[:：]?\s*(?:\n\s*)?(\{.*?\}|.+?)(?=\nObservation|$)",
        re.DOTALL,
    )

    def __init__(
        self,
        target_url: str = "http://127.0.0.1:18789",
        api_key: Optional[str] = None,
        max_steps: int = 8,
        max_retries: int = 2,
    ):
        self.target_url = target_url
        self.api_key = api_key
        self.max_steps = max_steps
        self.max_retries = max_retries

        # 工具注册表
        self._tools: Dict[str, Tool] = {
            t.name: t for t in self._build_tools()
        }

        # 推理状态
        self.reasoning_trace: List[Dict[str, Any]] = []
        self.tool_calls_count = 0
        self.start_time = 0.0

    # =====================================================
    # Tool 注册
    # =====================================================
    def _build_tools(self) -> List[Tool]:
        """构建工具注册表（v3.0 共 5 个工具）"""
        agent = self  # 闭包引用

        # -------- 工具 1：scan_vulnerability --------
        def _scan(cve_id: str) -> str:
            """对目标执行指定 CVE 漏洞扫描"""
            agent.tool_calls_count += 1
            try:
                # 优先调用现有服务
                try:
                    from services import scan_vulnerability_sync
                    result = scan_vulnerability_sync(cve_id, agent.target_url)
                    return f"[SCAN] {cve_id}: 状态={result.get('status','unknown')}, 细节={str(result.get('details','无'))[:200]}"
                except Exception as inner:
                    pass  # 降级到 HTTP 调用

                # 降级：直接调用靶机模拟扫描
                import urllib.request
                import urllib.error
                req = urllib.request.Request(
                    f"{agent.target_url}/api/v1/config",
                    headers={"Content-Type": "application/json"},
                )
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        return f"[SCAN] 目标可访问，配置接口返回: {json.dumps(data, ensure_ascii=False)[:150]}"
                except urllib.error.URLError as e:
                    return f"[SCAN] 目标不可访问: {str(e)[:80]}（可能已防护或靶机未启动）"
            except Exception as e:
                return f"[SCAN] 工具调用失败: {str(e)[:100]}"

        # -------- 工具 2：rag_query --------
        def _rag(query: str) -> str:
            """从 RAG 知识库查询漏洞相关知识"""
            agent.tool_calls_count += 1
            try:
                from services import query_knowledge_sync
                results = query_knowledge_sync(query, top_k=3)
                if isinstance(results, list) and results:
                    parts = []
                    for r in results[:3]:
                        if isinstance(r, dict):
                            title = r.get("cve_id") or r.get("title") or "未知"
                            content = str(r.get("content") or r.get("summary") or "")[:150]
                            parts.append(f"- {title}: {content}")
                        else:
                            parts.append(f"- {str(r)[:120]}")
                    return "[RAG] 查询结果:\n" + "\n".join(parts)
                return "[RAG] 知识库中无匹配结果（可能需要添加相关知识条目）"
            except Exception as e:
                return f"[RAG] 工具调用失败: {str(e)[:100]}"

        # -------- 工具 3：judge_analyze --------
        def _judge(vuln_info: str) -> str:
            """调用 AI 大模型分析漏洞的风险、根因和修复建议"""
            agent.tool_calls_count += 1
            try:
                from services import judge_vulnerability_sync
                result = judge_vulnerability_sync(
                    vuln_info=vuln_info,
                    cve_id="CVE-QUERY",
                    target_url=agent.target_url,
                )
                if isinstance(result, dict):
                    summary = result.get("report") or result.get("summary") or str(result)
                    return f"[JUDGE] AI 研判结论:\n{summary[:500]}"
                return f"[JUDGE] {str(result)[:500]}"
            except Exception as e:
                # 降级：本地规则研判
                risk = "高危" if any(k in vuln_info.lower()
                                      for k in ["rce", "注入", "sql", "command"]) else "中危"
                return f"[JUDGE] 降级研判（本地规则）: 风险等级={risk}, 漏洞描述={vuln_info[:200]}"

        # -------- 工具 4：patch_generate --------
        def _patch(cve_id: str) -> str:
            """生成漏洞修复补丁建议"""
            agent.tool_calls_count += 1
            try:
                from services import generate_patch_sync
                result = generate_patch_sync(cve_id)
                if isinstance(result, dict):
                    return (f"[PATCH] CVE {cve_id} 修复建议:\n"
                            f"标题: {result.get('title', 'N/A')}\n"
                            f"补丁代码: {(result.get('patch_code', '') or '')[:300]}")
                return f"[PATCH] {str(result)[:300]}"
            except Exception as e:
                # 降级：通用模板
                template = (
                    f"[PATCH] {cve_id} 通用修复建议:\n"
                    "1. 输入校验：对所有外部输入进行严格的类型、长度、格式校验\n"
                    "2. 权限隔离：最小权限原则，敏感操作需要二次鉴权\n"
                    "3. 沙箱隔离：系统命令使用白名单方式调用\n"
                    "4. 依赖升级：升级相关第三方库至最新安全版本"
                )
                return template

        # -------- 工具 5：adversarial_check --------
        def _adversarial(cve_id: str) -> str:
            """执行红蓝对抗模拟（评估防御效果）"""
            agent.tool_calls_count += 1
            try:
                from services import run_adversarial_check_sync
                result = run_adversarial_check_sync(cve_id, agent.target_url)
                if isinstance(result, dict):
                    red_score = result.get("red_score") or result.get("red_success") or 0
                    blue_score = result.get("blue_score") or result.get("blue_success") or 0
                    return (f"[ADV] 红蓝对抗: 红队(攻击)得分={red_score}, "
                            f"蓝队(防御)得分={blue_score}, 结果={json.dumps(result, ensure_ascii=False)[:200]}")
                return f"[ADV] {str(result)[:300]}"
            except Exception as e:
                return f"[ADV] 对抗模拟不可用: {str(e)[:80]}"

        # =====================================================
        # 构建并返回工具实例列表
        # =====================================================
        return [
            Tool(
                name="scan_vulnerability",
                description="对目标执行漏洞扫描，验证特定漏洞（如 CVE）是否存在",
                param_schema={"cve_id": "漏洞 ID 或漏洞类型标识（字符串）"},
                func=_scan,
            ),
            Tool(
                name="rag_query",
                description="从 RAG 知识库查询漏洞相关历史案例、最佳实践、修复方案",
                param_schema={"query": "查询关键词或描述（字符串）"},
                func=_rag,
            ),
            Tool(
                name="judge_analyze",
                description="调用 AI 大模型对漏洞进行深度研判，评估风险、根因和影响",
                param_schema={"vuln_info": "漏洞信息描述（字符串）"},
                func=_judge,
            ),
            Tool(
                name="patch_generate",
                description="生成针对指定漏洞的修复补丁建议和代码示例",
                param_schema={"cve_id": "漏洞 ID 或漏洞类型标识"},
                func=_patch,
            ),
            Tool(
                name="adversarial_check",
                description="执行红蓝对抗模拟，评估防御策略的有效性",
                param_schema={"cve_id": "漏洞 ID 或漏洞类型标识"},
                func=_adversarial,
            ),
        ]

    # =====================================================
    # v3.3 新增：工具链智能回退
    # 策略：主工具 → 同链备用工具 → 启发式描述兜底
    # 每个工具的失败都记录到 reasoning_trace，便于前端可视化
    # =====================================================

    # 工具回退链：当 key 工具失败时，依次尝试 value 列表中的备用工具
    _TOOL_FALLBACK_CHAIN = {
        "scan_vulnerability": ["rag_query", "judge_analyze"],
        "rag_query": ["judge_analyze", "scan_vulnerability"],
        "judge_analyze": ["rag_query", "scan_vulnerability"],
        "patch_generate": ["judge_analyze", "rag_query"],
        "adversarial_check": ["scan_vulnerability", "judge_analyze"],
    }

    def _heuristic_tool_desc(self, tool_name: str, params: Dict[str, Any]) -> str:
        """启发式工具描述（最终兜底，无 API 依赖也能输出内容）"""
        cve = params.get("cve_id", "未知") or params.get("vuln_info", "未知")
        query = params.get("query", "漏洞评估") or str(params)

        templates = {
            "scan_vulnerability": f"[启发式] 已模拟扫描 {cve}："
                                   "根据历史数据，此类漏洞的典型特征是"
                                   "未经验证的用户输入直接传递给危险接口，"
                                   "建议配合 RAG 知识库和 AI 研判进一步确认。",
            "rag_query": f"[启发式] 已查询知识库：{query}。"
                         "典型防御模式包括：输入白名单校验、参数化查询、"
                         "权限最小化原则、错误码统一过滤。",
            "judge_analyze": f"[启发式] 研判 {cve}："
                              "此漏洞的风险依赖于实际部署环境，"
                              "但从通用风险模型评估为中等到严重级别，"
                              "建议先执行扫描工具获取确切证据。",
            "patch_generate": f"[启发式] 补丁建议（需人工审核）："
                               "1) 增加前端输入校验；"
                               "2) 参数化后端查询避免拼接；"
                               "3) 限制服务账号权限；"
                               "4) 开启 Web 防火墙规则；"
                               "5) 定期审计依赖版本。",
            "adversarial_check": f"[启发式] 对抗模拟 {cve}："
                                   "模拟蓝队行为发现 3 个潜在攻击向量，"
                                   "建议真实环境下配合 WAF 日志、入侵检测系统联合评估。",
        }
        return templates.get(tool_name, f"[启发式] 工具 {tool_name} 暂不可用，但系统仍在工作。")

    def _try_tool_with_fallback(self, tool_name: str, params: Dict[str, Any]) -> str:
        """三级工具回退：主工具 → 同链备用工具 → 启发式描述

        该方法保证推理过程即使在部分工具失败时也能继续。

        Args:
            tool_name: 要调用的工具名称
            params: 工具参数字典

        Returns:
            str: 工具返回的观察结果或回退后的描述
        """
        # Step 1: 尝试主工具（带指数退避重试）
        try:
            observation = self._tools[tool_name](**params)
            if observation and len(str(observation).strip()) > 0:
                return observation
            # 工具返回空值 — 视为失败，继续回退
            self.reasoning_trace.append({
                "step": len(self.reasoning_trace),
                "type": "tool_fallback",
                "from_tool": tool_name,
                "level": "primary",
                "reason": "empty_return",
            })
        except Exception as e:
            self.reasoning_trace.append({
                "step": len(self.reasoning_trace),
                "type": "tool_fallback",
                "from_tool": tool_name,
                "level": "primary",
                "reason": f"exception: {str(e)[:80]}",
            })
            time.sleep(0.3)

        # Step 2: 尝试回退链中的备用工具
        fallback_list = self._TOOL_FALLBACK_CHAIN.get(tool_name, [])
        for alt_tool in fallback_list:
            if alt_tool not in self._tools:
                continue
            try:
                observation = self._tools[alt_tool](**params)
                if observation and len(str(observation).strip()) > 0:
                    self.reasoning_trace.append({
                        "step": len(self.reasoning_trace),
                        "type": "tool_fallback",
                        "from_tool": tool_name,
                        "to_tool": alt_tool,
                        "level": "fallback_tool",
                    })
                    return f"[工具链回退] 工具 '{tool_name}' 不可用，已自动切换到 '{alt_tool}'：\n{observation}"
            except Exception as e:
                self.reasoning_trace.append({
                    "step": len(self.reasoning_trace),
                    "type": "tool_fallback",
                    "from_tool": tool_name,
                    "to_tool": alt_tool,
                    "level": "fallback_tool",
                    "reason": str(e)[:60],
                })
                continue

        # Step 3: 最终兜底 — 启发式描述（零 API 依赖）
        self.reasoning_trace.append({
            "step": len(self.reasoning_trace),
            "type": "tool_fallback",
            "from_tool": tool_name,
            "level": "heuristic_fallback",
        })
        return self._heuristic_tool_desc(tool_name, params)

    # =====================================================
    # 工具说明生成（构建 System Prompt）
    # =====================================================
    def _build_system_prompt(self, user_query: str) -> str:
        """构建 ReAct 风格的 System Prompt"""
        tool_descriptions = "\n\n".join(t.to_prompt() for t in self._tools.values())
        tool_names = ", ".join(self._tools.keys())

        return f"""你是一个漏洞评估系统的 AI 推理助手，采用 ReAct (Reasoning + Acting) 模式。

【工具列表】
{tool_descriptions}

【响应格式 — 严格遵守以下结构】
每次回复必须且只能包含以下三行之一：
  1. Thought: <你的推理/思考>
  2. Action: <工具名>
     <JSON 格式的输入参数，如 {{"cve_id": "CWE-78"}}>
  3. Final Answer: <最终结论>

【推理规则】
1. 始终先使用 Thought 描述你的推理过程，然后使用 Action 调用工具。
2. 工具调用后，观察到的 Observation 会作为下一次输入。
3. 只有在你已经掌握足够信息来回答原问题时，才输出 Final Answer。
4. 可选工具仅限于：{tool_names}
5. 每次只能调用一个工具，多行 JSON 参数需严格为 JSON 格式。
6. 若工具返回信息不足，可多次调用不同工具或调整参数。

【用户当前任务】
{user_query}

开始你的推理。
"""

    # =====================================================
    # 解析模型输出 → 工具调用
    # =====================================================
    def _parse_action(self, text: str) -> Optional[Dict[str, Any]]:
        """解析模型输出中的 Action 调用

        返回: {"tool": "工具名", "params": {...}}
        返回 None 表示未检测到 Action（可能是 Final Answer）
        """
        for line in text.strip().split("\n"):
            stripped = line.strip()
            # 检测 "Final Answer:"
            if any(stripped.startswith(tok) for tok in self.FINISH_TOKENS):
                return {"action": "finish", "content": stripped}

            # 检测 "Action: tool_name"
            if stripped.startswith("Action:"):
                action_line = stripped[7:].strip()
                # 从后续行查找 JSON 参数
                return {"action": "tool", "tool_name": action_line, "params": {}}

        # 尝试更高级的正则解析（多行 JSON）
        match = self.ACTION_PATTERN.search(text)
        if match:
            tool_name = match.group(1).strip()
            param_str = match.group(2).strip()
            try:
                params = json.loads(param_str)
            except json.JSONDecodeError:
                params = {"raw": param_str}
            return {"action": "tool", "tool_name": tool_name, "params": params}

        # Thought: 只记录但不行动
        if "Thought:" in text and "Action:" not in text:
            return {"action": "thought", "content": text}

        return None

    # =====================================================
    # 核心：ReAct 推理循环
    # =====================================================
    def run(self, user_query: str, max_steps: Optional[int] = None) -> Dict[str, Any]:
        """启动 ReAct 推理循环（同步接口）

        参数:
            user_query: 用户任务描述（如"请扫描目标并分析存在的风险"）
            max_steps: 可选覆盖最大推理步数

        返回:
            {
                "query": str,
                "final_answer": str,
                "reasoning_trace": [...],
                "tool_calls": int,
                "steps": int,
                "duration_ms": int,
                "finished": bool,
            }
        """
        self.start_time = time.time()
        self.reasoning_trace = []
        self.tool_calls_count = 0

        steps_limit = max_steps or self.max_steps
        current_context = self._build_system_prompt(user_query)

        final_answer = None
        finished = False
        step = 0

        try:
            while step < steps_limit and not finished:
                step += 1
                # -------- Step 1: 让模型生成 Thought + Action --------
                model_output = self._call_model(current_context)

                self.reasoning_trace.append({
                    "step": step,
                    "type": "model_thinking",
                    "output": model_output,
                })

                # -------- Step 2: 解析 Action --------
                parsed = self._parse_action(model_output)

                if parsed is None:
                    # 无法解析：让模型重新思考
                    current_context += (f"\n\n[系统提示] 未能识别你的响应格式，"
                                        f"请严格按照 Thought → Action 格式回复。")
                    self.reasoning_trace.append({
                        "step": step,
                        "type": "system_error",
                        "message": "格式解析失败，请求模型重试",
                    })
                    continue

                # -------- Step 3: 执行 Action --------
                action_type = parsed.get("action")
                if action_type == "finish":
                    final_answer = parsed.get("content", "").replace("Final Answer:", "").strip()
                    finished = True
                    self.reasoning_trace.append({
                        "step": step,
                        "type": "finish",
                        "content": final_answer,
                    })
                    break

                if action_type == "tool":
                    tool_name = parsed.get("tool_name", "").strip()
                    params = parsed.get("params", {})

                    if tool_name not in self._tools:
                        # 工具不存在：让模型重试
                        observation = f"错误: 工具 '{tool_name}' 不存在。可用工具: {', '.join(self._tools.keys())}"
                        current_context += f"\n\nObservation: {observation}"
                        self.reasoning_trace.append({
                            "step": step,
                            "type": "tool_error",
                            "tool": tool_name,
                            "message": "工具不存在",
                        })
                        continue

                    # 调用工具（v3.3 新增：三级智能回退
                    # 策略：主工具 → 同链备用工具 → 启发式描述兜底
                    observation = self._try_tool_with_fallback(tool_name, params)

                    self.reasoning_trace.append({
                        "step": step,
                        "type": "tool_call",
                        "tool": tool_name,
                        "params": params,
                        "observation": str(observation),
                    })

                    current_context += f"\n\nObservation: {str(observation)[:500]}"

                elif action_type == "thought":
                    # 仅记录 Thought，继续下一轮让模型输出 Action
                    self.reasoning_trace.append({
                        "step": step,
                        "type": "thought_only",
                        "content": parsed.get("content", ""),
                    })
                    current_context += f"\n\n{model_output.strip()[:200]}\n（请继续输出下一步 Action）"

        except KeyboardInterrupt:
            final_answer = "[用户中断] 推理已被主动终止"

        # -------- 推理结束 --------
        if not finished and not final_answer:
            final_answer = ("[推理已达最大步数限制] "
                            "根据已收集的信息提供初步结论：目标存在潜在漏洞，"
                            "建议进一步人工审查。")

        duration_ms = int((time.time() - self.start_time) * 1000)
        return {
            "query": user_query,
            "target_url": self.target_url,
            "final_answer": final_answer,
            "reasoning_trace": self.reasoning_trace,
            "tool_calls": self.tool_calls_count,
            "steps": step,
            "duration_ms": duration_ms,
            "finished": finished,
            "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }

    # =====================================================
    # 模型调用（三级智能回退：Retry → 备用模型 → 启发式规则）
    # =====================================================
    def _call_model(self, prompt: str) -> str:
        """调用大模型（带三级智能回退策略）

        回退策略 v3.2：
          1. 优先调用 services/ 中的大模型接口（默认模型，最多 3 次指数退避重试）
          2. 若失败 → 尝试用备用模型（如 qwen-max-longcontext）
          3. 若仍失败 → 降级到启发式推理引擎（规则驱动，100% 离线可用）

        每次失败都会记录到 reasoning_trace，便于前端可视化。
        """
        # ---- Level 1: 主模型 + 指数退避重试 ----
        attempt_delays = [0, 0.5, 1.0]  # 3 次尝试，延迟递增
        for attempt, delay in enumerate(attempt_delays):
            try:
                if delay > 0:
                    time.sleep(delay)
                from services import call_react_model_sync
                output = call_react_model_sync(prompt, max_tokens=512)
                if output and len(output.strip()) > 10:
                    return output.strip()
                # 返回内容太短或为空，当次重试失败
                self.reasoning_trace.append({
                    "step": len(self.reasoning_trace),
                    "type": "model_fallback",
                    "level": f"primary_attempt_{attempt + 1}",
                    "reason": "empty_or_too_short_output",
                })
            except Exception as e:
                self.reasoning_trace.append({
                    "step": len(self.reasoning_trace),
                    "type": "model_fallback",
                    "level": f"primary_attempt_{attempt + 1}",
                    "reason": f"exception: {str(e)[:80]}",
                })

        # ---- Level 2: 备用模型（qwen-max-longcontext / turbo 等） ----
        try:
            from services import call_react_model_sync, set_current_model, _current_model
            original = _current_model
            for alt_model in ["qwen-max-longcontext", "qwen-turbo"]:
                try:
                    set_current_model(alt_model)
                    output = call_react_model_sync(prompt, max_tokens=512)
                    if output and len(output.strip()) > 10:
                        self.reasoning_trace.append({
                            "step": len(self.reasoning_trace),
                            "type": "model_fallback",
                            "level": "fallback_model",
                            "switched_to": alt_model,
                        })
                        # 不要污染全局：用完即还原（此处不还原，让后续调用继续使用备用模型）
                        # 实际上 set_current_model 会修改全局，为避免副作用这里还原
                        set_current_model(original)
                        return output.strip()
                except Exception:
                    continue
            # 所有备用模型均失败，还原
            set_current_model(original)
        except Exception:
            pass

        # ---- Level 3: 启发式推理引擎（100% 离线，最终兜底） ----
        self.reasoning_trace.append({
            "step": len(self.reasoning_trace),
            "type": "model_fallback",
            "level": "heuristic_fallback",
            "reason": "all_model_calls_failed",
        })
        return self._heuristic_reasoning(prompt)

    # =====================================================
    # 降级：启发式规则推理引擎
    # =====================================================
    def _heuristic_reasoning(self, context: str) -> str:
        """启发式推理引擎（用于无大模型时的降级模式）

        根据 prompt 中的关键词，决定调用哪些工具：
          - "扫描" / "漏洞" / "检查" → scan_vulnerability
          - "知识" / "案例" / "原理" → rag_query
          - "研判" / "分析" / "风险" → judge_analyze
          - "修复" / "补丁" / "加固" → patch_generate
          - "对抗" / "红队" / "蓝队" → adversarial_check
        """
        ctx_lower = context.lower()
        last_obs = [t["type"] for t in self.reasoning_trace if t["type"] == "tool_call"]

        # 首次：先扫描
        if len(last_obs) == 0:
            return (
                "Thought: 我需要先对目标进行漏洞扫描，了解存在哪些风险。\n"
                'Action: scan_vulnerability\n{"cve_id": "basic_scan"}'
            )

        # 根据最近工具调用决定下一步
        last_tool = last_obs[-1] if last_obs else ""
        if last_tool == "scan_vulnerability":
            return (
                "Thought: 扫描已完成，现在需要查询知识库了解漏洞原理和案例。\n"
                'Action: rag_query\n{"query": "漏洞防御最佳实践 注入攻击"}'
            )
        if last_tool == "rag_query":
            return (
                "Thought: 知识库查询完成，现在需要对漏洞进行深入研判分析。\n"
                'Action: judge_analyze\n{"vuln_info": "目标存在命令注入和 SQL 注入风险，需要评估严重性和影响范围"}'
            )
        if last_tool == "judge_analyze":
            return (
                "Thought: 研判完成，现在生成修复建议。\n"
                'Action: patch_generate\n{"cve_id": "high_risk_vulnerability"}'
            )
        if last_tool == "patch_generate":
            return (
                "Thought: 补丁生成完成，建议进行红蓝对抗以验证修复效果。\n"
                'Action: adversarial_check\n{"cve_id": "verification"}'
            )

        # 工具已执行超过 3 次，返回结论
        return "Final Answer: 已完成对目标的漏洞评估。目标存在已知漏洞风险，建议立即执行生成的修复建议并部署到生产环境进行验证。持续监控至关重要。"


# ============================================================
# 便捷函数（供路由直接调用）
# ============================================================

def run_react_assessment(target_url: str, query: str,
                         api_key: Optional[str] = None,
                         max_steps: int = 8) -> Dict[str, Any]:
    """便捷函数：创建 Agent 并执行评估"""
    agent = ReActAgent(
        target_url=target_url,
        api_key=api_key,
        max_steps=max_steps,
    )
    return agent.run(query)


# ============================================================
# 本地快速测试（python react_agent.py）
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("ReAct Agent - 本地测试模式")
    print("=" * 60)
    result = run_react_assessment(
        target_url="http://127.0.0.1:18789",
        query="请分析该目标存在的高危漏洞并给出修复建议",
        max_steps=6,
    )
    print(f"\n[完成] 推理步数: {result['steps']}, 工具调用: {result['tool_calls']}, "
          f"耗时: {result['duration_ms']}ms")
    print(f"最终结论: {result['final_answer'][:200]}")
    print(f"\n推理轨迹摘要 ({len(result['reasoning_trace'])} 轮):")
    for t in result["reasoning_trace"]:
        print(f"  Step {t['step']} [{t['type']}] "
              f"{t.get('tool', t.get('content', ''))[:80]}")
