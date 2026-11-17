"""
v3.0 — 自主探测自适应反馈 Agent
基于 MAB（Multi-Armed Bandit）+ UCB 策略的自主探测引擎。
Agent 自适应选择探测向量，根据反馈调整策略，最大化信息增益。

核心算法：
  - UCB (Upper Confidence Bound): 平衡探索与利用，选择 UCB 值最高的探测向量
  - 自适应反馈: 根据响应调整探测策略，跳过已被检测的策略
  - 信息增益: 计算每个探测向量的信息增益（熵减），优先选择信息量大的向量
  - 向量池管理: 动态添加/移除探测向量，支持优先级调整

使用方式：
    from autonomous_prober import AutonomousProber, ProbeConfig
    prober = AutonomousProber(ProbeConfig())
    prober.build_default()
    vector = prober.select_vector()
    prober.update_feedback(vector.vector_id, success=True)
"""

import math
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class ProbeConfig:
    """探测配置"""
    ucb_c: float = 2.0          # UCB 探索参数
    min_confidence: float = 0.1  # 最小置信度
    decay_factor: float = 0.99   # 衰减因子
    max_retries: int = 3         # 最大重试次数


@dataclass
class ProbeVector:
    """探测向量"""
    vector_id: str
    name: str
    description: str
    target: str            # 目标资产类型
    success_count: int = 0
    total_count: int = 0
    priority: float = 0.5  # 初始优先级
    active: bool = True    # 是否启用
    cooldown: int = 0      # 冷却轮次


@dataclass
class ProbeResult:
    """探测结果"""
    vector_id: str
    success: bool
    response_time: float
    response_size: int
    confidence: float
    new_knowledge: Dict[str, Any] = field(default_factory=dict)


class AutonomousProber:
    """自主探测自适应反馈 Agent"""

    def __init__(self, config: Optional[ProbeConfig] = None):
        self.config = config or ProbeConfig()
        self.vectors: Dict[str, ProbeVector] = {}
        self.history: List[ProbeResult] = []
        self.total_rounds: int = 0
        self.knowledge_base: Dict[str, Any] = {}
        self.blocked_vectors: set = set()

    def add_vector(self, vector: ProbeVector):
        """添加探测向量"""
        self.vectors[vector.vector_id] = vector

    def build_default(self):
        """构建默认探测向量池"""
        defaults = [
            ("PV-001", "API 端点探测", "枚举 API 端点，检测未授权访问", "ASSET-API"),
            ("PV-002", "参数模糊测试", "对 API 参数进行模糊测试", "ASSET-API"),
            ("PV-003", "命令注入探测", "测试命令注入点", "ASSET-OS"),
            ("PV-004", "SQL 注入探测", "测试 SQL 注入点", "ASSET-DB"),
            ("PV-005", "Prompt 注入探测", "测试 LLM 提示词注入", "ASSET-LLM"),
            ("PV-006", "认证绕过测试", "测试认证机制绕过", "ASSET-API"),
            ("PV-007", "文件上传探测", "测试文件上传漏洞", "ASSET-API"),
            ("PV-008", "XXE 注入探测", "测试 XML 外部实体注入", "ASSET-API"),
        ]
        for vid, name, desc, target in defaults:
            self.add_vector(ProbeVector(vid, name, desc, target))

    def select_vector(self, available_targets: Optional[List[str]] = None) -> Optional[ProbeVector]:
        """UCB 策略选择最优探测向量

        Args:
            available_targets: 可用目标列表（可选）

        Returns:
            选择的探测向量，或 None（无可用向量）
        """
        active_vectors = [v for v in self.vectors.values() if v.active and v.cooldown <= 0]
        if available_targets:
            active_vectors = [v for v in active_vectors if v.target in available_targets]

        if not active_vectors:
            return None

        best_vector = None
        best_ucb = -float('inf')

        for v in active_vectors:
            if v.total_count == 0:
                # 冷启动：优先选择未探测的向量
                return v

            # UCB 计算
            exploit = v.success_count / v.total_count  # 成功率
            # 惩罚已被检测到的向量
            if v.vector_id in self.blocked_vectors:
                exploit *= 0.5

            explore = self.config.ucb_c * math.sqrt(
                math.log(self.total_rounds + 1) / v.total_count
            )
            ucb = exploit + explore + v.priority * 0.1

            if ucb > best_ucb:
                best_ucb = ucb
                best_vector = v

        return best_vector

    def update_feedback(self, vector_id: str, success: bool, response_time: float = 0,
                        response_size: int = 0, confidence: float = 0.5):
        """更新探测反馈

        Args:
            vector_id: 探测向量 ID
            success: 探测是否成功
            response_time: 响应时间
            response_size: 响应大小
            confidence: 置信度
        """
        if vector_id not in self.vectors:
            return

        vector = self.vectors[vector_id]
        vector.total_count += 1
        if success:
            vector.success_count += 1
            vector.priority = min(1.0, vector.priority + 0.1)
        else:
            vector.priority = max(0.1, vector.priority - 0.05)

        # 记录结果
        self.history.append(ProbeResult(
            vector_id=vector_id,
            success=success,
            response_time=response_time,
            response_size=response_size,
            confidence=confidence,
        ))
        self.total_rounds += 1

        # 自适应：如果连续失败，增加冷却时间
        recent_failures = sum(
            1 for r in self.history[-3:]
            if r.vector_id == vector_id and not r.success
        )
        if recent_failures >= 3:
            vector.cooldown = 3
            self.blocked_vectors.add(vector_id)

        # 冷却衰减
        for v in self.vectors.values():
            if v.cooldown > 0:
                v.cooldown = max(0, v.cooldown - 1)
                if v.cooldown == 0:
                    self.blocked_vectors.discard(v.vector_id)

    def information_gain(self, vector_id: str) -> float:
        """计算探测向量的信息增益（熵减）

        Args:
            vector_id: 探测向量 ID

        Returns:
            信息增益值
        """
        vector = self.vectors.get(vector_id)
        if not vector or vector.total_count == 0:
            return 1.0  # 未探测的有最大信息增益

        success_rate = vector.success_count / vector.total_count
        if success_rate == 0 or success_rate == 1:
            return 0.0  # 确定性结果，无信息增益

        # 熵
        entropy = -(success_rate * math.log2(success_rate) +
                    (1 - success_rate) * math.log2(1 - success_rate))
        return entropy

    def get_stats(self) -> Dict:
        """获取探测统计"""
        stats = []
        for v in self.vectors.values():
            if v.total_count > 0:
                stats.append({
                    "vector_id": v.vector_id,
                    "name": v.name,
                    "success_rate": round(v.success_count / v.total_count, 3) if v.total_count > 0 else 0,
                    "total_attempts": v.total_count,
                    "priority": round(v.priority, 3),
                    "information_gain": round(self.information_gain(v.vector_id), 3),
                    "active": v.active and v.cooldown <= 0,
                })

        return {
            "vectors": sorted(stats, key=lambda x: x["success_rate"], reverse=True),
            "total_rounds": self.total_rounds,
            "blocked_count": len(self.blocked_vectors),
            "ucb_param": self.config.ucb_c,
        }