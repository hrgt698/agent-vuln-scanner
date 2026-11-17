"""RAG 知识库增强引擎 — 单元测试"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rag_advice import RAGAdviceEngine


class TestRAGAdviceEngine:
    """测试 RAG 知识库增强功能"""

    def setup_method(self):
        self.engine = RAGAdviceEngine()

    def test_known_cve_has_knowledge(self):
        """已知漏洞应有知识库条目"""
        for cve in ["CS0048", "CWE-78", "CWE-89", "AML.T0051"]:
            entry = self.engine.get_kb_entry(cve)
            assert entry is not None, f"{cve} 应存在知识库条目"
            assert "vuln_type" in entry
            assert "best_practices" in entry
            assert "fix_example" in entry

    def test_unknown_cve_returns_none(self):
        """未知漏洞应返回 None"""
        assert self.engine.get_kb_entry("CVE-UNKNOWN") is None

    def test_enhance_report_appends_knowledge(self):
        """增强报告应追加知识库内容"""
        original = "### 一、漏洞概述\n这是一个 SQL 注入漏洞。"
        enhanced = self.engine.enhance_report("CWE-89", original)
        assert len(enhanced) > len(original)
        assert "历史案例" in enhanced or "最佳实践" in enhanced or "参考代码" in enhanced

    def test_unknown_cve_enhance_no_change(self):
        """未知 CVE 的增强应返回原始内容"""
        original = "测试报告"
        enhanced = self.engine.enhance_report("CVE-X", original)
        assert enhanced == original

    def test_kb_summary_format(self):
        """知识库摘要应返回正确的结构"""
        summary = self.engine.get_kb_summary("CWE-78")
        assert summary["has_knowledge"] is True
        assert summary["vuln_type"] == "操作系统命令注入"
        assert summary["case_count"] >= 2
        assert summary["practice_count"] >= 3
        assert summary["has_fix_example"] is True

    def test_unknown_kb_summary(self):
        """未知漏洞的摘要应标记 has_knowledge=False"""
        summary = self.engine.get_kb_summary("CVE-X")
        assert summary["has_knowledge"] is False

    def test_similar_cases_link(self):
        """历史案例应包含 CVE 编号"""
        kb = self.engine.get_kb_entry("CS0048")
        for case in kb["similar_cases"]:
            assert "cve" in case
            assert "year" in case
            assert "description" in case