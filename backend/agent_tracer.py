"""
Agent 决策轨迹追踪器
拦截 Agent 的每一步推理，记录完整的决策树，支持前端交互式可视化回放。
使用方式：from agent_tracer import DecisionTreeTracer, DecisionNode
"""

import time
import json
import uuid
from typing import List, Dict, Optional


class DecisionNode:
    """决策树节点，记录 Agent 单步决策的完整上下文"""

    def __init__(self, agent_id: str, step: int, observation: str,
                 action: str, reward: float, parent_id: Optional[str] = None):
        self.node_id = str(uuid.uuid4())[:8]
        self.agent_id = agent_id
        self.step = step
        self.timestamp = time.time()
        self.observation = observation          # Agent 观察到的环境状态
        self.action = action                     # Agent 选择的动作
        self.reward = reward                     # 环境反馈的奖励信号
        self.parent_id = parent_id
        self.children: List[str] = []
        self.thought_process = ""                # CoT 推理过程
        self.used_tools: List[str] = []          # 调用的工具
        self.confidence = 0.0                    # 决策置信度 (0~1)
        self.error_message = ""                  # 错误信息（如果有）

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "agent_id": self.agent_id,
            "step": self.step,
            "timestamp": self.timestamp,
            "observation": self.observation[:150],
            "action": self.action,
            "reward": self.reward,
            "parent_id": self.parent_id,
            "children": self.children,
            "thought": self.thought_process[:300],
            "tools": self.used_tools,
            "confidence": self.confidence,
            "error": self.error_message,
        }


class DecisionTreeTracer:
    """决策树追踪器
    职责：
    1. 每个评估回合创建一个决策树
    2. 记录 Agent 每一步的观察、动作、奖励
    3. 支持回溯任意节点的完整决策路径
    4. 导出数据供前端 D3.js/ECharts 可视化
    """

    def __init__(self, agent_id: str = "default_agent"):
        self.agent_id = agent_id
        self.nodes: Dict[str, DecisionNode] = {}
        self.root: Optional[DecisionNode] = None
        self.current_parent: Optional[str] = None
        self.episode_id = str(uuid.uuid4())[:8]
        self.start_time = time.time()
        self.total_reward = 0.0
        self.successful_actions = 0
        self.failed_actions = 0

    def start_episode(self, initial_observation: str, task_desc: str = "") -> str:
        """开始一个评估回合，创建根节点"""
        node = DecisionNode(self.agent_id, 0, initial_observation,
                           "START", 0.0)
        node.thought_process = task_desc
        self.root = node
        self.nodes[node.node_id] = node
        self.current_parent = node.node_id
        self.start_time = time.time()
        return node.node_id

    def record_step(self, observation: str, action: str, reward: float,
                   thought: str = "", tools: Optional[List[str]] = None,
                   confidence: float = 0.0, error: str = "") -> str:
        """记录 Agent 的一步决策"""
        step = len(self.nodes)
        node = DecisionNode(self.agent_id, step, observation, action,
                           reward, parent_id=self.current_parent)
        node.thought_process = thought
        node.used_tools = tools or []
        node.confidence = confidence
        node.error_message = error

        # 挂载到父节点
        if self.current_parent and self.current_parent in self.nodes:
            self.nodes[self.current_parent].children.append(node.node_id)

        self.nodes[node.node_id] = node
        self.current_parent = node.node_id
        self.total_reward += reward
        if reward > 0:
            self.successful_actions += 1
        elif error:
            self.failed_actions += 1
        return node.node_id

    def get_decision_path(self, target_node_id: str) -> List[dict]:
        """回溯从 root 到目标节点的完整决策路径"""
        path = []
        node = self.nodes.get(target_node_id)
        while node:
            path.append(node.to_dict())
            node = self.nodes.get(node.parent_id) if node.parent_id else None
        return list(reversed(path))

    def get_tree_data(self) -> dict:
        """返回完整的决策树数据（供前端可视化渲染）"""
        duration = time.time() - self.start_time
        return {
            "episode_id": self.episode_id,
            "agent_id": self.agent_id,
            "total_steps": len(self.nodes),
            "duration_seconds": round(duration, 2),
            "total_reward": round(self.total_reward, 2),
            "successful_actions": self.successful_actions,
            "failed_actions": self.failed_actions,
            "nodes": [n.to_dict() for n in sorted(self.nodes.values(),
                                                   key=lambda n: n.step)],
        }

    def summary(self) -> str:
        """生成决策过程的自然语言摘要"""
        node_count = len(self.nodes)
        return (
            f"Agent [{self.agent_id}] 完成 {node_count - 1} 步决策\n"
            f"  总奖励: {round(self.total_reward, 2)}\n"
            f"  成功: {self.successful_actions} | 失败: {self.failed_actions}\n"
            f"  耗时: {round(time.time() - self.start_time, 2)}s"
        )

    @staticmethod
    def format_as_timeline(tree_data: dict) -> str:
        """将决策树格式化为时间线文本（用于 AI 报告引用）"""
        lines = ["## Agent 决策轨迹时间线\n"]
        for node in sorted(tree_data["nodes"], key=lambda n: n["step"]):
            if node["step"] == 0:
                continue
            icon = "✅" if node["reward"] > 0 else "❌" if node["error"] else "⏳"
            lines.append(
                f"{icon} **Step {node['step']}** | 动作: `{node['action']}` "
                f"| 奖励: {node['reward']} | 置信度: {node['confidence']:.2f}"
            )
            if node["tools"]:
                lines.append(f"   🔧 工具调用: {', '.join(node['tools'])}")
            if node["thought"]:
                lines.append(f"   💭 推理: {node['thought'][:100]}")
        return "\n".join(lines)