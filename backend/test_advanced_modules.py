"""
v3.0 高级算法模块单元测试
测试所有 8 个模块的核心算法逻辑。
"""

import pytest
import sys
import os

# 确保 backend 目录在 Python 路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ============================================================
# 1. Beam Search Test
# ============================================================
class TestPromptBeamSearch:
    def setup_method(self):
        from prompt_beam_search import PromptBeamSearch, BeamSearchConfig
        self.config = BeamSearchConfig(beam_width=3, max_generations=5)
        self.searcher = PromptBeamSearch(self.config)

    def test_search_basic(self):
        """测试基本搜索功能"""
        def reward_func(text: str) -> float:
            return sum(0.1 for kw in ["ignore", "system", "bypass"] if kw in text.lower())
        result = self.searcher.search(reward_func)
        assert result.total_generations > 0
        assert result.best_score >= 0

    def test_deduplication(self):
        """测试去重逻辑"""
        from prompt_beam_search import PromptCandidate
        candidates = [
            PromptCandidate(text="test1", score=0.8),
            PromptCandidate(text="test1", score=0.9),
            PromptCandidate(text="test2", score=0.7),
        ]
        deduped = self.searcher._deduplicate(candidates)
        assert len(deduped) == 2

    def test_text_similarity(self):
        """测试文本相似度计算"""
        sim = self.searcher._text_similarity("hello world", "hello world")
        assert sim == 1.0
        sim = self.searcher._text_similarity("hello world", "goodbye")
        assert sim == 0.0

    def test_has_converged(self):
        """测试收敛检测"""
        from prompt_beam_search import PromptCandidate
        # 分数相近 → 收敛
        beam = [
            PromptCandidate(text="a", score=0.81),
            PromptCandidate(text="b", score=0.80),
            PromptCandidate(text="c", score=0.79),
        ]
        assert self.searcher._has_converged(beam) is True

    def test_mutators(self):
        """测试所有 9 种变异算子"""
        seed = "hello world"
        for name, mutator in self.searcher.MUTATORS.items():
            result = mutator(seed)
            assert isinstance(result, str)
            assert len(result) > 0


# ============================================================
# 2. Bayesian Optimizer Test
# ============================================================
class TestBayesianOptimizer:
    def setup_method(self):
        from bayesian_optimizer import BayesianAttackOptimizer
        self.opt = BayesianAttackOptimizer()
        self.opt.build_default()

    def test_select(self):
        """测试策略选择"""
        result = self.opt.select()
        assert result.strategy_name in self.opt.strategies
        assert result.confidence is not None

    def test_update(self):
        """测试策略更新"""
        self.opt.update("direct_exploit", success=True)
        s = self.opt.strategies["direct_exploit"]
        assert s.total_attempts == 1
        assert s.alpha > 1.0  # 成功时 alpha 增加

    def test_update_failure(self):
        """测试失败更新"""
        self.opt.update("direct_exploit", success=False)
        s = self.opt.strategies["direct_exploit"]
        assert s.beta > 1.0  # 失败时 beta 增加

    def test_get_all_stats(self):
        """测试统计信息"""
        self.opt.update("direct_exploit", success=True)
        self.opt.update("direct_exploit", success=False)
        stats = self.opt.get_all_stats()
        assert len(stats) == len(self.opt.DEFAULT_STRATEGIES)
        assert stats[0]["expected_value"] >= 0


# ============================================================
# 3. RL Agent Test
# ============================================================
class TestRLAgent:
    def setup_method(self):
        from rl_agent import RLAttackAgent, RLConfig
        self.agent = RLAttackAgent(RLConfig(epsilon=0.0))  # 无探索

    def test_choose_action(self):
        """测试动作选择"""
        action = self.agent.choose_action("state_sql_injection")
        assert action in self.agent.actions

    def test_update(self):
        """测试 Q 值更新"""
        self.agent.update("state1", "send_payload", 1.0, "state2", False)
        q = self.agent.q_table["state1"]["send_payload"]
        assert q > 0  # 正奖励增加 Q 值

    def test_update_negative(self):
        """测试负奖励更新"""
        self.agent.update("state1", "send_payload", -1.0, "state2", True)
        q = self.agent.q_table["state1"]["send_payload"]
        assert q < 0  # 负奖励降低 Q 值

    def test_epsilon_decay(self):
        """测试 epsilon 衰减"""
        from rl_agent import RLAttackAgent, RLConfig
        agent = RLAttackAgent(RLConfig(epsilon=1.0, epsilon_decay=0.5))
        assert agent.epsilon == 1.0
        agent.update("s1", "a1", 0.0, "s2", False)
        assert agent.epsilon == 0.5  # 衰减后

    def test_replay(self):
        """测试经验回放"""
        for i in range(5):
            self.agent.update(f"state_{i}", "send_payload", 1.0, f"state_{i+1}", False)
        self.agent.replay(batch_size=3)
        assert len(self.agent.replay_buffer) >= 5

    def test_q_table_stats(self):
        """测试 Q 表统计"""
        self.agent.update("s1", "a1", 1.0, "s2", False)
        stats = self.agent.get_q_table_stats()
        assert stats["total_states"] >= 1
        assert 0 <= stats["epsilon"] <= 1


# ============================================================
# 4. Vuln Knowledge Graph Test
# ============================================================
class TestVulnKnowledgeGraph:
    def setup_method(self):
        from vuln_knowledge_graph import VulnKnowledgeGraph
        self.kg = VulnKnowledgeGraph()
        self.kg.build_default_graph()

    def test_pagerank(self):
        """测试 PageRank"""
        pr = self.kg.pagerank()
        assert len(pr) > 0
        assert all(0 <= v <= 1 for v in pr.values())

    def test_shortest_path(self):
        """测试最短路径搜索"""
        path = self.kg.shortest_exploit_path("CS0048", "ASSET-API")
        assert path is not None
        assert len(path) >= 2

    def test_shortest_path_unreachable(self):
        """测试不可达路径"""
        path = self.kg.shortest_exploit_path("CS0048", "NONEXISTENT")
        assert path is None

    def test_detect_communities(self):
        """测试社区检测"""
        communities = self.kg.detect_communities()
        assert len(communities) > 0
        assert len(set(communities.values())) >= 1

    def test_recommend_similar(self):
        """测试相似漏洞推荐"""
        similar = self.kg.recommend_similar("CS0048", top_k=2)
        assert len(similar) <= 2

    def test_get_related_fixes(self):
        """测试关联修复方案"""
        fixes = self.kg.get_related_fixes("CS0048")
        assert len(fixes) > 0


# ============================================================
# 5. Causal Analyzer Test
# ============================================================
class TestCausalAnalyzer:
    def setup_method(self):
        from causal_analyzer import CausalVulnAnalyzer
        self.analyzer = CausalVulnAnalyzer()
        self.analyzer.build_default_graph()

    def test_root_cause_analysis(self):
        """测试根因分析"""
        results = self.analyzer.root_cause_analysis()
        assert len(results) == len(self.analyzer.nodes)
        for r in results:
            assert r.rank > 0

    def test_counterfactual_analysis(self):
        """测试反事实分析"""
        cf = self.analyzer.counterfactual_analysis("CS0048")
        if cf:
            for affected, data in cf.items():
                assert "original_risk" in data
                assert "counterfactual_risk" in data
                assert "risk_reduction" in data
                assert data["risk_reduction"] >= 0

    def test_minimum_fix_set(self):
        """测试最小修复集"""
        fix_set = self.analyzer.minimum_fix_set()
        assert len(fix_set) > 0
        assert "CS0048" in fix_set or "CWE-78" in fix_set

    def test_average_causal_effect(self):
        """测试平均因果效应"""
        ace = self.analyzer.average_causal_effect("CS0048", "AML.T0051")
        assert ace >= 0

    def test_export_analysis(self):
        """测试导出分析结果"""
        result = self.analyzer.export_analysis()
        assert result.root_causes is not None
        assert result.minimum_fix_set is not None


# ============================================================
# 6. Cross Validator Test
# ============================================================
class TestCrossValidator:
    def setup_method(self):
        from cross_validator import CrossValidator
        self.cv = CrossValidator()
        self.cv.add_judgment("qwen-turbo", "CS0048", "high", 0.92, correct=True)
        self.cv.add_judgment("qwen-plus", "CS0048", "high", 0.88, correct=True)
        self.cv.add_judgment("qwen-max", "CS0048", "critical", 0.95, correct=True)
        self.cv.add_judgment("qwen-turbo", "CWE-78", "critical", 0.95, correct=True)
        self.cv.add_judgment("qwen-plus", "CWE-78", "critical", 0.91, correct=True)
        self.cv.add_judgment("qwen-max", "CWE-78", "critical", 0.97, correct=True)

    def test_fleiss_kappa(self):
        """测试 Fleiss' Kappa"""
        result = self.cv.fleiss_kappa()
        assert -1 <= result.kappa <= 1
        assert result.interpretation is not None

    def test_cohens_kappa(self):
        """测试 Cohen's Kappa"""
        kappa = self.cv.cohens_kappa("qwen-turbo", "qwen-plus")
        assert -1 <= kappa <= 1

    def test_generate_report(self):
        """测试完整报告生成"""
        report = self.cv.generate_report()
        assert report.fleiss_kappa is not None
        assert len(report.pairwise) >= 2
        assert len(report.model_rankings) >= 3
        assert 0 <= report.consensus_score <= 100

    def test_interpret_kappa(self):
        """测试 Kappa 解释"""
        assert self.cv._interpret_kappa(0.9) == "几乎完全一致"
        assert self.cv._interpret_kappa(0.7) == "高度一致"
        assert self.cv._interpret_kappa(0.1) == "轻微一致"


# ============================================================
# 7. Vuln Scorer Test
# ============================================================
class TestVulnScorer:
    def setup_method(self):
        from vuln_scorer import EntropyWeightedTOPSIS
        self.scorer = EntropyWeightedTOPSIS()
        self.scorer.build_default()

    def test_evaluate(self):
        """测试 TOPSIS 评分"""
        results = self.scorer.evaluate()
        assert len(results) >= 4
        assert results[0].rank == 1
        assert 0 <= results[0].score <= 1

    def test_ranking_order(self):
        """测试排名顺序"""
        results = self.scorer.evaluate()
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)  # 降序

    def test_entropy_weights(self):
        """测试熵权计算"""
        weights = self.scorer.get_weights()
        assert len(weights) == len(self.scorer.DIMENSIONS)
        total = sum(weights.values())
        assert abs(total - 1.0) < 0.01  # 权重和为 1


# ============================================================
# 8. Autonomous Prober Test
# ============================================================
class TestAutonomousProber:
    def setup_method(self):
        from autonomous_prober import AutonomousProber, ProbeConfig
        self.prober = AutonomousProber(ProbeConfig(ucb_c=2.0))
        self.prober.build_default()

    def test_select_vector(self):
        """测试向量选择"""
        vector = self.prober.select_vector()
        assert vector is not None
        assert vector.vector_id in self.prober.vectors

    def test_update_feedback(self):
        """测试反馈更新"""
        self.prober.update_feedback("PV-001", success=True, confidence=0.9)
        v = self.prober.vectors["PV-001"]
        assert v.total_count == 1
        assert v.success_count == 1

    def test_information_gain(self):
        """测试信息增益"""
        ig = self.prober.information_gain("PV-001")
        assert ig == 1.0  # 未探测 → 最大信息增益

    def test_stats(self):
        """测试统计信息"""
        self.prober.update_feedback("PV-001", success=True)
        stats = self.prober.get_stats()
        assert len(stats["vectors"]) >= 1
        assert stats["total_rounds"] == 1


# ============================================================
# 9. Auto Patch Generator Test
# ============================================================
class TestAutoPatchGenerator:
    def setup_method(self):
        from auto_patch_generator import AutoPatchGenerator, PatchConfig
        self.generator = AutoPatchGenerator(PatchConfig(sandbox_mode=False))

    def test_generate_patch(self):
        """测试补丁生成"""
        original = "def api_handler(request):\n    return get_data()"
        patch = self.generator.generate_patch("CS0048", "config.py", original)
        assert patch.patch_id != ""
        assert patch.vuln_id == "CS0048"
        assert patch.patched_code != original

    def test_apply_and_verify(self):
        """测试补丁应用"""
        original = "def api_handler(request):\n    return get_data()"
        patch = self.generator.generate_patch("CS0048", "config.py", original)
        result = self.generator.apply_and_verify(patch)
        assert result.success is True

    def test_rollback(self):
        """测试回滚"""
        original = "def api_handler(request):\n    return get_data()"
        patch = self.generator.generate_patch("CS0048", "config.py", original)
        self.generator.apply_and_verify(patch)
        success = self.generator.rollback(patch.patch_id)
        assert success is True

    def test_unknown_vuln(self):
        """测试未知漏洞类型"""
        original = "some code"
        patch = self.generator.generate_patch("UNKNOWN", "test.py", original)
        assert patch.patch_id == "" or patch.status.value == "failed"

    def test_patch_history(self):
        """测试补丁历史"""
        original = "def api_handler(request):\n    return get_data()"
        self.generator.generate_patch("CS0048", "config.py", original)
        history = self.generator.get_patch_history()
        assert len(history) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])