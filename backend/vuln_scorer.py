"""
v3.0 — 多目标熵权 TOPSIS 漏洞评分算法
基于信息熵客观赋权，替代 CVSS 主观评分体系。
对漏洞的 7 个维度进行综合评分，产出可比较的优先级排序。

核心算法：
  - 信息熵: 客观计算各维度的权重（熵越大，权重越小）
  - TOPSIS: 计算各漏洞到正理想解和负理想解的距离，排序
  - 7 维度: 可利用性、影响面、严重程度、普遍性、修复复杂度、攻击向量、优先级

使用方式：
    from vuln_scorer import EntropyWeightedTOPSIS, VulnProfile
    scorer = EntropyWeightedTOPSIS()
    scorer.build_default()
    results = scorer.evaluate()
"""

import math
import numpy as np
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class VulnProfile:
    """漏洞评分剖面"""
    vuln_id: str
    name: str
    exploitability: float = 0.5   # 可利用性
    impact: float = 0.5           # 影响面
    severity: float = 5.0         # 严重程度 (CVSS)
    prevalence: float = 0.5       # 普遍性
    fix_complexity: float = 0.5   # 修复复杂度（反向：越高越好修）
    attack_vector: float = 0.5    # 攻击向量
    priority_score: float = 0.5   # 优先级


@dataclass
class VulnScoreResult:
    """评分结果"""
    vuln_id: str
    name: str
    score: float        # TOPSIS 综合得分
    rank: int           # 排名
    dimensions: Dict[str, float]  # 各维度归一化值


class EntropyWeightedTOPSIS:
    """熵权 TOPSIS 漏洞评分"""

    DIMENSIONS = [
        "exploitability", "impact", "severity",
        "prevalence", "fix_complexity", "attack_vector", "priority_score",
    ]

    def __init__(self):
        self.profiles: List[VulnProfile] = []
        self.decision_matrix: Optional[np.ndarray] = None
        self.entropy_weights: Optional[Dict[str, float]] = None

    def add_vuln(self, profile: VulnProfile):
        """添加漏洞"""
        self.profiles.append(profile)

    def build_default(self):
        """构建默认漏洞集"""
        self.profiles = [
            VulnProfile("CS0048", "API 未授权访问", 0.9, 0.8, 7.5, 0.7, 0.2, 0.7, 0.8),
            VulnProfile("CWE-78", "命令注入 RCE", 0.8, 0.95, 9.8, 0.6, 0.3, 0.8, 0.95),
            VulnProfile("CWE-89", "SQL 注入", 0.7, 0.85, 8.6, 0.8, 0.4, 0.6, 0.85),
            VulnProfile("AML.T0051", "提示词注入", 0.6, 0.6, 6.5, 0.4, 0.5, 0.5, 0.6),
        ]

    def _build_matrix(self) -> np.ndarray:
        """构建决策矩阵"""
        n = len(self.profiles)
        m = len(self.DIMENSIONS)
        matrix = np.zeros((n, m))
        for i, p in enumerate(self.profiles):
            for j, dim in enumerate(self.DIMENSIONS):
                matrix[i, j] = getattr(p, dim, 0.5)
        return matrix

    def _normalize(self, matrix: np.ndarray) -> np.ndarray:
        """向量归一化"""
        norms = np.sqrt(np.sum(matrix ** 2, axis=0))
        norms[norms == 0] = 1  # 避免除零
        return matrix / norms

    def _compute_entropy_weights(self, matrix: np.ndarray) -> Dict[str, float]:
        """信息熵客观赋权"""
        n, m = matrix.shape
        # 归一化到 [0.0001, 1] 避免 log(0)
        norm = self._normalize(matrix)
        norm = np.clip(norm, 0.0001, 1.0)

        weights = {}
        for j, dim in enumerate(self.DIMENSIONS):
            p = norm[:, j] / np.sum(norm[:, j])
            entropy = -np.sum(p * np.log(p)) / np.log(n) if n > 1 else 0
            # 熵越大，信息量越小，权重越小
            w = (1 - entropy) / (len(self.DIMENSIONS) - sum(1 - entropy for entropy in
                 [(1 + np.sum(p * np.log(p)) / np.log(n)) if n > 1 else 0 for p in [norm[:, k] / np.sum(norm[:, k]) for k in range(m)]]))
            # 简化：直接使用 1 - entropy
            weights[dim] = max(0.01, 1 - entropy)

        # 归一化权重
        total = sum(weights.values())
        if total > 0:
            weights = {k: v / total for k, v in weights.items()}

        return weights

    def evaluate(self) -> List[VulnScoreResult]:
        """执行 TOPSIS 评分"""
        matrix = self._build_matrix()
        self.decision_matrix = matrix

        # 熵权
        self.entropy_weights = self._compute_entropy_weights(matrix)
        weight_array = np.array([self.entropy_weights[d] for d in self.DIMENSIONS])

        # 归一化 + 加权
        norm = self._normalize(matrix)
        weighted = norm * weight_array

        # 正/负理想解
        ideal_best = np.max(weighted, axis=0)
        ideal_worst = np.min(weighted, axis=0)

        # 距离
        dist_best = np.sqrt(np.sum((weighted - ideal_best) ** 2, axis=1))
        dist_worst = np.sqrt(np.sum((weighted - ideal_worst) ** 2, axis=1))

        # TOPSIS 得分
        scores = dist_worst / (dist_best + dist_worst + 1e-10)

        # 排名
        order = np.argsort(-scores)
        results = []
        for rank, idx in enumerate(order):
            results.append(VulnScoreResult(
                vuln_id=self.profiles[idx].vuln_id,
                name=self.profiles[idx].name,
                score=round(float(scores[idx]), 4),
                rank=rank + 1,
                dimensions={
                    dim: round(float(norm[idx, j]), 4)
                    for j, dim in enumerate(self.DIMENSIONS)
                },
            ))

        return results

    def get_weights(self) -> Dict[str, float]:
        """获取熵权"""
        if self.entropy_weights is None:
            self.evaluate()
        return self.entropy_weights or {}