"""
v3.0 — Q-Learning 强化学习攻击 Agent
基于 Q-Learning + 经验回放 + Double Q-Learning 的自主攻击路径学习 Agent。
Agent 在攻击过程中学习最优动作序列，通过 epsilon-greedy 策略平衡探索与利用。

核心算法：
  - Q-Learning: 基于 Bellman 方程更新 Q(s, a) 值
  - Experience Replay: 存储历史经验，随机采样打破时间相关性
  - Double Q-Learning: 双 Q 网络消除过估计偏差
  - Epsilon Decay: 探索率随时间衰减，逐步收敛到最优策略

使用方式：
    from rl_agent import RLAttackAgent, RLConfig
    agent = RLAttackAgent(RLConfig(epsilon=0.3))
    action = agent.choose_action(current_state)
    agent.update(state, action, reward, next_state, done)
"""

import random
import math
from collections import deque
from typing import Dict, List, Tuple, Optional, Deque
from dataclasses import dataclass, field


@dataclass
class RLConfig:
    """Q-Learning 配置"""
    epsilon: float = 0.3           # 初始探索率
    epsilon_decay: float = 0.995   # 探索率衰减因子
    epsilon_min: float = 0.01      # 最小探索率
    learning_rate: float = 0.1     # 学习率 α
    discount_factor: float = 0.9   # 折扣因子 γ
    replay_buffer_size: int = 1000 # 经验回放缓冲区大小
    batch_size: int = 32           # 批量学习大小
    double_q: bool = True          # 是否使用 Double Q-Learning


@dataclass
class Experience:
    """经验元组"""
    state: str
    action: str
    reward: float
    next_state: str
    done: bool


class RLAttackAgent:
    """Q-Learning 强化学习攻击 Agent"""

    # 默认动作空间
    DEFAULT_ACTIONS = [
        "probe_endpoint", "send_payload", "fuzz_parameter",
        "bypass_waf", "chain_exploit", "escalate_privilege",
        "extract_data", "report_finding", "retry_with_variant",
    ]

    def __init__(self, config: Optional[RLConfig] = None):
        self.config = config or RLConfig()
        self.epsilon = self.config.epsilon
        # Q 表: {state: {action: q_value}}
        self.q_table: Dict[str, Dict[str, float]] = {}
        # 双 Q 表
        self.q_table_b: Dict[str, Dict[str, float]] = {}
        # 经验回放缓冲区
        self.replay_buffer: Deque[Experience] = deque(maxlen=self.config.replay_buffer_size)
        # 动作空间
        self.actions = list(self.DEFAULT_ACTIONS)

    def choose_action(self, state: str, available_actions: Optional[List[str]] = None) -> str:
        """epsilon-greedy 策略选择动作

        Args:
            state: 当前状态
            available_actions: 可用动作列表（可选，默认全部动作）

        Returns:
            选择的动作名称
        """
        actions = available_actions or self.actions

        # 探索：随机选择
        if random.random() < self.epsilon:
            return random.choice(actions)

        # 利用：选择 Q 值最大的动作
        return self.get_best_action(state, actions)

    def get_best_action(self, state: str, available_actions: Optional[List[str]] = None) -> str:
        """获取当前状态下 Q 值最大的动作"""
        actions = available_actions or self.actions
        q_values = self._get_q_values(state)

        best_action = actions[0]
        best_q = float('-inf')
        for a in actions:
            q = q_values.get(a, 0.0)
            if self.config.double_q:
                q_b = self._get_q_values(state, use_b=True).get(a, 0.0)
                q = (q + q_b) / 2  # 双 Q 平均
            if q > best_q:
                best_q = q
                best_action = a
        return best_action

    def update(self, state: str, action: str, reward: float, next_state: str, done: bool):
        """更新 Q 表（基于 Bellman 方程）

        Args:
            state: 当前状态
            action: 执行的动作
            reward: 获得的奖励
            next_state: 下一状态
            done: 是否终止
        """
        # 存储经验
        self.replay_buffer.append(Experience(state, action, reward, next_state, done))

        # 初始化 Q 值
        if state not in self.q_table:
            self.q_table[state] = {a: 0.0 for a in self.actions}
        if self.config.double_q and state not in self.q_table_b:
            self.q_table_b[state] = {a: 0.0 for a in self.actions}

        # 计算目标 Q 值
        if done:
            target = reward
        else:
            next_q = self._get_q_values(next_state)
            if self.config.double_q:
                # Double Q-Learning: 用 Q 表选择动作，用 Q_b 表评估
                best_next_action = max(next_q, key=next_q.get) if next_q else self.actions[0]
                next_q_b = self._get_q_values(next_state, use_b=True)
                max_next_q = next_q_b.get(best_next_action, 0.0)
            else:
                max_next_q = max(next_q.values()) if next_q else 0.0
            target = reward + self.config.discount_factor * max_next_q

        # Q-Learning 更新
        current_q = self.q_table[state].get(action, 0.0)
        self.q_table[state][action] = current_q + self.config.learning_rate * (target - current_q)

        # Double Q 更新（交替更新）
        if self.config.double_q and random.random() < 0.5:
            current_q_b = self.q_table_b[state].get(action, 0.0)
            self.q_table_b[state][action] = current_q_b + self.config.learning_rate * (target - current_q_b)

        # 衰减 epsilon
        self.epsilon = max(self.config.epsilon_min, self.epsilon * self.config.epsilon_decay)

    def replay(self, batch_size: Optional[int] = None):
        """经验回放：从缓冲区采样批量学习"""
        batch_size = batch_size or self.config.batch_size
        if len(self.replay_buffer) < batch_size:
            return

        batch = random.sample(list(self.replay_buffer), batch_size)
        for exp in batch:
            self.update(exp.state, exp.action, exp.reward, exp.next_state, exp.done)

    def get_q_table_stats(self) -> Dict:
        """获取 Q 表统计信息"""
        total_states = len(self.q_table)
        total_entries = sum(len(actions) for actions in self.q_table.values())
        return {
            "total_states": total_states,
            "total_entries": total_entries,
            "epsilon": self.epsilon,
            "replay_buffer_size": len(self.replay_buffer),
            "double_q": self.config.double_q,
        }

    def _get_q_values(self, state: str, use_b: bool = False) -> Dict[str, float]:
        """获取状态的 Q 值"""
        table = self.q_table_b if use_b else self.q_table
        if state not in table:
            table[state] = {a: 0.0 for a in self.actions}
        return table[state]