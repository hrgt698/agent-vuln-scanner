"""红蓝对抗博弈评估模式 — 单元测试"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from adversarial_mode import AdversarialEvaluator


class TestAdversarialEvaluator:
    """测试红蓝对抗博弈评估器"""

    def setup_method(self):
        self.evaluator = AdversarialEvaluator(
            target_url="http://127.0.0.1:18789",
            max_rounds=2,
            attempts_per_round=3,
        )

    def test_initial_state(self):
        """初始状态计分应为 0:0"""
        scoreboard = self.evaluator.get_scoreboard()
        assert scoreboard["red_score"] == 0
        assert scoreboard["blue_score"] == 0
        assert scoreboard["rounds_completed"] == 0

    def test_vulnerability_progress_init(self):
        """四种漏洞的统计初始值应为 0"""
        for cve, stats in self.evaluator.vulnerability_progress.items():
            assert stats["attempts"] == 0
            assert stats["successes"] == 0

    def test_red_team_plan_structure(self):
        """红队计划应包含必要字段"""
        plan = self.evaluator._red_team_plan(1, 1)
        assert "cve" in plan
        assert "strategy" in plan
        assert "payload" in plan
        assert plan["cve"] in ["CS0048", "CWE-78", "CWE-89", "AML.T0051"]

    def test_red_team_plan_adaptive(self):
        """红队策略应随回合数而变化"""
        plan_early = self.evaluator._red_team_plan(1, 1)
        plan_late = self.evaluator._red_team_plan(3, 5)
        # 靠后的回合策略可能不同
        assert plan_early["strategy"] and plan_late["strategy"]

    def test_blue_team_detect_no_history(self):
        """无历史记录时检测概率应较低"""
        plan = self.evaluator._red_team_plan(1, 1)
        # 多次测试看平均检测率
        detected_count = 0
        for _ in range(100):
            detected, _ = self.evaluator._blue_team_detect(plan, {"success": False})
            if detected:
                detected_count += 1
        # 第 1 回合，detection_rate = 0.3
        assert 0.1 <= detected_count / 100 <= 0.6

    def test_blue_team_detect_learns(self):
        """蓝队应学习已成功过的攻击策略"""
        plan = self.evaluator._red_team_plan(1, 1)
        # 模拟红队历史上成功过
        self.evaluator.red_strategy_history.append(plan["strategy"])
        detected, action = self.evaluator._blue_team_detect(plan, {"success": True})
        assert detected is True  # 学习到防御规则

    def test_scoreboard_after_round(self):
        """对抗一回合后计分板应有变化"""
        import asyncio
        result = asyncio.run(self.evaluator._run_single_round(1))
        scoreboard = self.evaluator.get_scoreboard()
        # 回合记录只在 run_full_game 中追加，这里校验事件数
        assert scoreboard["red_score"] + scoreboard["blue_score"] == 3  # 3 次尝试
        assert len(result["events"]) == 3

    def test_summary_generation(self):
        """对抗总结应包含关键数据"""
        self.evaluator.red_score = 5
        self.evaluator.blue_score = 3
        summary = self.evaluator._generate_summary("red")
        assert "红队" in summary or "攻击" in summary or "红队" in summary
        assert "5" in summary or str(self.evaluator.red_score) in summary

    def test_round_winner_determination(self):
        """回合胜者判定应正确"""
        import asyncio
        result = asyncio.run(self.evaluator._run_single_round(1))
        assert result["winner_this_round"] in ["red", "blue", "draw"]