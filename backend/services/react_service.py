"""
services.react_service — ReAct Agent 集成
"""

import os
from typing import Optional, Any


_react_agent: Optional[Any] = None


def get_react_agent() -> Optional[Any]:
    """获取或初始化 ReAct Agent 实例（延迟加载）"""
    global _react_agent
    if _react_agent is not None:
        return _react_agent
    try:
        from react_agent import ReActAgent
        from services.api_key import get_next_api_key
        api_key = get_next_api_key() or os.getenv("DASHSCOPE_API_KEY")
        _react_agent = ReActAgent(
            api_key=api_key,
            max_steps=5,
        )
        print("[Services] ReAct Agent 初始化完成")
    except Exception as e:
        print(f"[WARN] ReActAgent 初始化失败：{e}")
        _react_agent = None
    return _react_agent


def run_react_query(user_query: str) -> dict:
    """调用 ReAct Agent 处理用户查询，返回结构化的推理轨迹 + 最终答案"""
    agent = get_react_agent()
    if not agent:
        return {
            "error": "react_agent_not_available",
            "final_answer": "ReAct Agent 当前不可用，请检查 API Key 配置。",
            "reasoning_trace": [],
        }
    try:
        result = agent.run(user_query)
        return result
    except Exception as e:
        return {
            "error": "react_agent_execution_failed",
            "final_answer": f"ReAct Agent 执行出错：{e}",
            "reasoning_trace": [],
        }