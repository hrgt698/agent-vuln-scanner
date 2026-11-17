"""
基于攻击图的漏洞关联分析器
对多个漏洞之间的利用链条进行建模，评估复合攻击路径的总体风险。
使用方式：from attack_graph import AttackGraphAnalyzer
"""

from typing import List, Dict, Set, Optional


class VulnNode:
    """攻击图中的漏洞节点"""
    def __init__(
        self,
        cve_id: str,
        name: str,
        risk: str = "high",
        pre_conditions: Set[str] = None,
        post_conditions: Set[str] = None,
        cvss_score: float = 7.5,
    ):
        self.cve_id = cve_id
        self.name = name
        self.risk = risk
        self.pre_conditions = pre_conditions or set()
        self.post_conditions = post_conditions or set()
        self.cvss_score = cvss_score

    def __repr__(self):
        return f"VulnNode({self.cve_id}, risk={self.risk})"


class AttackGraphAnalyzer:
    """基于攻击图的漏洞关联分析器
    内置常见漏洞之间的利用链关系：
      CS0048 (API未授权) → 泄露配置 → 增强后续攻击效果
      CWE-89  (SQL注入)  → 脱库泄露 → 获取敏感数据
      CWE-78  (命令注入) → RCE     → 完全控制
      AML.T0051 (提示词注入) → 越权 → Agent 劫持
    """

    def __init__(self):
        self.nodes: Dict[str, VulnNode] = {}
        self._build_default_graph()

    def _build_default_graph(self):
        """构建默认的漏洞关联关系图"""
        self.add_node(VulnNode(
            cve_id="CS0048",
            name="API未授权访问配置泄露",
            risk="high",
            post_conditions={"has_admin_config"},
            cvss_score=7.5,
        ))
        self.add_node(VulnNode(
            cve_id="CWE-89",
            name="SQL注入漏洞",
            risk="high",
            pre_conditions=set(),      # 独立可执行
            post_conditions={"has_database_dump"},
            cvss_score=8.5,
        ))
        self.add_node(VulnNode(
            cve_id="CWE-78",
            name="系统命令注入漏洞 (RCE)",
            risk="critical",
            pre_conditions=set(),
            post_conditions={"has_rce"},
            cvss_score=10.0,
        ))
        self.add_node(VulnNode(
            cve_id="AML.T0051",
            name="LLM提示词越权注入",
            risk="high",
            pre_conditions=set(),
            post_conditions={"has_agent_control"},
            cvss_score=8.0,
        ))

    def add_node(self, node: VulnNode):
        """添加一个漏洞节点"""
        self.nodes[node.cve_id] = node

    def analyze(self, scan_results: List[dict]) -> dict:
        """分析已触发的漏洞，评估攻击路径与复合风险"""
        triggered_cves = set()
        achieved_conditions: Set[str] = set()

        for result in scan_results:
            cve = result.get("cve_id", "")
            if result.get("status") == "success" and cve in self.nodes:
                triggered_cves.add(cve)
                node = self.nodes[cve]
                achieved_conditions.update(node.post_conditions)

        # 找出条件已满足但尚未触发的潜在下一步攻击目标
        next_targets = []
        for cve_id, node in self.nodes.items():
            if cve_id in triggered_cves:
                continue
            if node.pre_conditions and node.pre_conditions.issubset(achieved_conditions):
                next_targets.append({
                    "cve": cve_id,
                    "name": node.name,
                    "reason": f"前置条件已满足: {node.pre_conditions}",
                    "risk": node.risk,
                })

        # 计算复合风险评分
        overall_risk_score = self._calc_compound_risk_score(list(triggered_cves))

        return {
            "attack_path": list(triggered_cves),
            "attack_chain_length": len(triggered_cves),
            "achieved_conditions": list(achieved_conditions),
            "next_targets": next_targets,
            "overall_risk_score": round(overall_risk_score, 2),
            "risk_level": self._risk_level_label(overall_risk_score),
        }

    def _calc_compound_risk_score(self, triggered_cves: List[str]) -> float:
        """计算复合风险评分（类比 CVSS 的 Attack Graph 评分规则）
        规则：
        - 基础分 = 各漏洞 CVSS 评分的加权和
        - 链加成 = 0.3 × (链长 - 1)，链越长风险越大
        - 上限 10.0
        """
        if not triggered_cves:
            return 0.0

        base_score = sum(
            self.nodes[cve].cvss_score for cve in triggered_cves if cve in self.nodes
        )
        chain_bonus = 0.3 * (len(triggered_cves) - 1)

        return min(base_score + chain_bonus, 10.0)

    def _risk_level_label(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"

    def get_attack_chain_description(self, triggered_cves: List[str]) -> str:
        """生成攻击链的自然语言描述"""
        if not triggered_cves:
            return "暂未触发任何漏洞，系统处于安全状态。"

        names = [self.nodes[c].name for c in triggered_cves if c in self.nodes]
        chain = " → ".join(names)

        return (
            f"已观测到攻击链: {chain}\n"
            f"攻击路径长度: {len(triggered_cves)} 步\n"
            f"复合风险评分: {self._calc_compound_risk_score(triggered_cves):.1f}/10.0"
        )