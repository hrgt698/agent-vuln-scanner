"""攻击图关联分析器 — 单元测试"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from attack_graph import AttackGraphAnalyzer, VulnNode


class TestAttackGraphAnalyzer:
    """测试攻击图分析器的节点管理和风险评分"""

    def setup_method(self):
        self.analyzer = AttackGraphAnalyzer()

    def test_default_nodes(self):
        """默认应包含 4 个漏洞节点"""
        assert len(self.analyzer.nodes) == 4
        assert "CS0048" in self.analyzer.nodes
        assert "CWE-78" in self.analyzer.nodes
        assert "CWE-89" in self.analyzer.nodes
        assert "AML.T0051" in self.analyzer.nodes

    def test_add_custom_node(self):
        """应支持添加自定义漏洞节点"""
        self.analyzer.add_node(VulnNode(
            cve_id="CUSTOM-01",
            name="自定义漏洞",
            risk="medium",
            cvss_score=5.0,
        ))
        assert "CUSTOM-01" in self.analyzer.nodes

    def test_analyze_no_triggers(self):
        """无触发漏洞时返回安全状态"""
        result = self.analyzer.analyze([])
        assert result["overall_risk_score"] == 0.0
        assert result["risk_level"] == "low"

    def test_analyze_single_vuln(self):
        """单个漏洞触发的评分"""
        result = self.analyzer.analyze([
            {"cve_id": "CWE-78", "status": "success"},
        ])
        assert result["overall_risk_score"] == 10.0
        assert result["attack_chain_length"] == 1

    def test_analyze_multiple_vulns(self):
        """多个漏洞应有链加成"""
        result = self.analyzer.analyze([
            {"cve_id": "CS0048", "status": "success"},
            {"cve_id": "CWE-89", "status": "success"},
            {"cve_id": "CWE-78", "status": "success"},
        ])
        # 基础分: 7.5 + 8.5 + 10.0 = 26.0, 链加成 0.3*2 = 0.6, 上限 10.0
        assert result["overall_risk_score"] == 10.0
        assert result["attack_chain_length"] == 3
        assert result["risk_level"] == "critical"

    def test_chain_description(self):
        """攻击链描述应包含漏洞名称"""
        desc = self.analyzer.get_attack_chain_description(["CWE-78", "CS0048"])
        assert "RCE" in desc or "命令" in desc or "API" in desc

    def test_next_targets_detection(self):
        """应检测出条件已满足的下一步攻击目标"""
        # CS0048 的 post_conditions 设为 {"has_admin_config"}
        # 暂无漏洞依赖此条件，所以 next_targets 应为空
        result = self.analyzer.analyze([
            {"cve_id": "CS0048", "status": "success"},
        ])
        assert isinstance(result["next_targets"], list)

    def test_node_cvss_scores(self):
        """节点应有合理的 CVSS 评分"""
        assert self.analyzer.nodes["CWE-78"].cvss_score >= 9.0
        assert self.analyzer.nodes["CS0048"].cvss_score >= 7.0