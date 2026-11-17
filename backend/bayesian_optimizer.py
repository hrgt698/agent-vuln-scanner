"""
v3.0 — 贝叶斯优化攻击策略选择器
基于 Thompson Sampling（Beta 分布采样）平衡探索与利用，
为每个攻击策略维护 Beta(α, β) 分布，根据历史成功/失败更新参数。

核心算法：
  - Thompson Sampling: 从 Beta 分布采样，选择期望奖励最高的策略
  - 自适应学习: 每次执行后更新 α(成功) 或 β(失败)
  - 冷启动: 先验 Beta(1, 1) 均匀分布，无偏探索

使用方式：
    from bayesian_optimizer import BayesianAttackOptimizer
    opt = BayesianAttackOptimizer()
    opt.build_default()
    strategy = opt.select()  # 选择最优策略
    opt.update(strategy.strategy_name, success=True)  # 更新
"""

import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class AttackStrategy:
    """攻击策略"""
    name: str
    description: str
    alpha: float = 1.0  # Beta 分布 α (成功次数 + 1)
    beta: float = 1.0   # Beta 分布 β (失败次数 + 1)
    total_attempts: int = 0
    total_successes: int = 0


@dataclass
class StrategySelection:
    """策略选择结果"""
    strategy_name: str
    description: str
    confidence: Optional[float] = None  # 采样值
    success_rate: float = 0.0
    total_attempts: int = 0


class BayesianAttackOptimizer:
    """贝叶斯优化攻击策略选择器"""

    # 默认策略模板
    DEFAULT_STRATEGIES = [
        ("direct_exploit", "直接利用已知漏洞"),
        ("payload_fuzzing", "Payload 变异模糊测试"),
        ("chain_exploit", "漏洞链组合利用"),
        ("bypass_waf", "WAF 绕过测试"),
        ("privilege_escalation", "权限提升"),
        ("information_disclosure", "信息泄露探测"),
        ("side_channel", "侧信道攻击"),
        ("social_engineering", "社工模拟"),
    ]

    def __init__(self, seed: int = 42):
        self.strategies: Dict[str, AttackStrategy] = {}
        random.seed(seed)

    def build_default(self):
        """构建默认策略集"""
        for name, desc in self.DEFAULT_STRATEGIES:
            self.strategies[name] = AttackStrategy(name=name, description=desc)

    def add_strategy(self, name: str, description: str):
        """添加自定义策略"""
        self.strategies[name] = AttackStrategy(name=name, description=description)

    def select(self, top_k: int = 1) -> StrategySelection:
        """Thompson Sampling 选择最优策略

        Args:
            top_k: 返回前 k 个策略

        Returns:
            StrategySelection 包含策略名称、置信度、成功率
        """
        if not self.strategies:
            raise ValueError("未添加任何策略，请先调用 build_default() 或 add_strategy()")

        best = None
        best_sample = -1.0

        for name, strategy in self.strategies.items():
            # 从 Beta(α, β) 分布采样
            sample = random.betavariate(strategy.alpha, strategy.beta)
            if sample > best_sample:
                best_sample = sample
                best = strategy

        if best is None:
            raise ValueError("策略选择失败")

        return StrategySelection(
            strategy_name=best.name,
            description=best.description,
            confidence=best_sample,
            success_rate=self._success_rate(best),
            total_attempts=best.total_attempts,
        )

    def update(self, strategy_name: str, success: bool):
        """更新策略的 Beta 分布参数

        Args:
            strategy_name: 策略名称
            success: 是否成功
        """
        if strategy_name not in self.strategies:
            raise ValueError(f"未知策略: {strategy_name}")

        strategy = self.strategies[strategy_name]
        strategy.total_attempts += 1
        if success:
            strategy.alpha += 1.0
            strategy.total_successes += 1
        else:
            strategy.beta += 1.0

    def get_all_stats(self) -> List[Dict]:
        """获取所有策略的统计信息"""
        stats = []
        for name, s in self.strategies.items():
            stats.append({
                "name": name,
                "description": s.description,
                "alpha": s.alpha,
                "beta": s.beta,
                "success_rate": self._success_rate(s),
                "total_attempts": s.total_attempts,
                "total_successes": s.total_successes,
                "expected_value": s.alpha / (s.alpha + s.beta) if (s.alpha + s.beta) > 0 else 0.5,
            })
        return sorted(stats, key=lambda x: x["expected_value"], reverse=True)

    def _success_rate(self, strategy: AttackStrategy) -> float:
        """计算成功率"""
        if strategy.total_attempts == 0:
            return 0.0
        return strategy.total_successes / strategy.total_attempts