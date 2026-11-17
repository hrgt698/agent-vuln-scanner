"""DAG 调度器与自适应调度器 — 单元测试"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scheduler import DAGScheduler, VulnTask, AdaptiveScheduler


class TestDAGScheduler:
    """测试 DAG 调度器的拓扑排序和依赖解析"""

    def setup_method(self):
        self.scheduler = DAGScheduler()
        self.scheduler.add_task(VulnTask(
            script="a.py", name="Task A", cve="CVE-A",
            dependencies=[], priority=3,
        ))
        self.scheduler.add_task(VulnTask(
            script="b.py", name="Task B", cve="CVE-B",
            dependencies=["CVE-A"], priority=2,
        ))
        self.scheduler.add_task(VulnTask(
            script="c.py", name="Task C", cve="CVE-C",
            dependencies=["CVE-B"], priority=1,
        ))

    def test_topological_order(self):
        """依赖关系中父节点应在子节点之前"""
        order = self.scheduler.get_execution_order()
        assert order.index("CVE-A") < order.index("CVE-B")
        assert order.index("CVE-B") < order.index("CVE-C")

    def test_priority_sorting_no_deps(self):
        """无依赖的任务按优先级降序排列"""
        s = DAGScheduler()
        s.add_task(VulnTask("1.py", "High", "HIGH", priority=5))
        s.add_task(VulnTask("2.py", "Low", "LOW", priority=1))
        order = s.get_execution_order()
        assert order[0] == "HIGH"

    def test_cyclic_dependency_handling(self):
        """有环时应抛出 ValueError 并在 execute_all 中返回错误结果"""
        s = DAGScheduler()
        s.add_task(VulnTask("a.py", "A", "CVE-A", dependencies=["CVE-B"]))
        s.add_task(VulnTask("b.py", "B", "CVE-B", dependencies=["CVE-A"]))
        # 直接调用 get_execution_order 应抛出 ValueError
        import pytest
        with pytest.raises(ValueError) as exc_info:
            s.get_execution_order()
        assert "环形依赖" in str(exc_info.value)
        # execute_all 应捕获异常并返回错误标记
        import asyncio
        results = asyncio.run(s.execute_all(lambda s, u: {}, "test"))
        assert "CYCLE_ERROR" in results
        assert results["CYCLE_ERROR"]["status"] == "error"

    def test_execute_all_empty(self):
        """空调度器应返回空结果"""
        s = DAGScheduler()
        import asyncio
        results = asyncio.run(s.execute_all(lambda s, u: {}, "test"))
        assert results == {}


class TestAdaptiveScheduler:
    """测试自适应调度器的统计和推荐算法"""

    def setup_method(self):
        self.scheduler = AdaptiveScheduler()

    def test_initial_stats(self):
        """未记录历史时返回默认值"""
        stats = self.scheduler.get_stats("CVE-UNKNOWN")
        assert stats["samples"] == 0

    def test_record_and_stats(self):
        """记录执行结果后应能正确统计"""
        self.scheduler.record_result("CVE-1", True, 1.0)
        self.scheduler.record_result("CVE-1", False, 2.0)
        stats = self.scheduler.get_stats("CVE-1")
        assert stats["samples"] == 2
        assert stats["avg_duration"] == 1.5
        assert stats["success_rate"] == 0.5

    def test_timeout_recommendation(self):
        """超时推荐应基于历史数据"""
        self.scheduler.record_result("CVE-1", True, 5.0)
        self.scheduler.record_result("CVE-1", True, 7.0)
        timeout = self.scheduler.get_recommended_timeout("CVE-1")
        expected = int(6.0 * 2.5)
        assert timeout == min(expected, 120)

    def test_retry_recommendation_low_success(self):
        """成功率低时应推荐更多重试"""
        self.scheduler.record_result("CVE-1", False, 1.0)
        self.scheduler.record_result("CVE-1", False, 1.0)
        assert self.scheduler.get_recommended_retries("CVE-1") == 2

    def test_retry_recommendation_high_success(self):
        """成功率高时应推荐一次重试"""
        self.scheduler.record_result("CVE-1", True, 1.0)
        self.scheduler.record_result("CVE-1", True, 1.0)
        assert self.scheduler.get_recommended_retries("CVE-1") == 1

    def test_history_window_enforced(self):
        """历史记录窗口应被限制"""
        for i in range(15):
            self.scheduler.record_result("CVE-1", True, 1.0)
        stats = self.scheduler.get_stats("CVE-1")
        assert stats["samples"] <= 10