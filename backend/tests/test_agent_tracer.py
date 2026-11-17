"""Agent 决策树追踪器 — 单元测试"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_tracer import DecisionTreeTracer, DecisionNode


class TestDecisionNode:
    """测试决策节点"""

    def test_node_creation(self):
        node = DecisionNode("agent1", 1, "观测到API端点", "GET /api/v1/config", 1.0)
        assert node.step == 1
        assert node.reward == 1.0
        assert len(node.node_id) == 8
        assert node.parent_id is None


class TestDecisionTreeTracer:
    """测试决策树追踪器"""

    def setup_method(self):
        self.tracer = DecisionTreeTracer("test-agent")

    def test_start_episode(self):
        """开始回合应创建根节点"""
        node_id = self.tracer.start_episode("初始观测", "测试任务")
        assert self.tracer.root is not None
        assert self.tracer.root.step == 0
        assert node_id == self.tracer.root.node_id

    def test_record_step(self):
        """记录一步应正确挂载"""
        self.tracer.start_episode("初始")
        child_id = self.tracer.record_step(
            observation="发现接口", action="注入攻击",
            reward=1.0, thought="尝试 SQL 注入",
            tools=["sqlfuzz"], confidence=0.85,
        )
        assert len(self.tracer.nodes) == 2
        assert child_id in self.tracer.nodes
        # 根节点的 children 应包含子节点
        assert child_id in self.tracer.root.children

    def test_total_reward_tracking(self):
        """总奖励应累加"""
        self.tracer.start_episode("初始")
        self.tracer.record_step("o1", "卫a1", reward=1.5)
        self.tracer.record_step("o2", "a2", reward=-0.5)
        assert self.tracer.total_reward == 1.0  # 1.5 + (-0.5)

    def test_get_decision_path(self):
        """路径回溯应正确"""
        self.tracer.start_episode("初始")
        id1 = self.tracer.record_step("o1", "a1", 1.0)
        id2 = self.tracer.record_step("o2", "a2", 0.5)
        path = self.tracer.get_decision_path(id2)
        assert len(path) == 3  # root + step1 + step2

    def test_get_tree_data(self):
        """树数据格式应完整"""
        self.tracer.start_episode("初始", "测试任务")
        self.tracer.record_step("o1", "a1", 1.0)
        data = self.tracer.get_tree_data()
        assert data["total_steps"] == 2
        assert data["agent_id"] == "test-agent"
        assert len(data["nodes"]) == 2
        assert data["total_reward"] == 1.0

    def test_summary_format(self):
        """摘要应包含关键信息"""
        self.tracer.start_episode("初始")
        self.tracer.record_step("o1", "a1", 1.0)
        summary = self.tracer.summary()
        assert "test-agent" in summary
        assert "1" in summary  # step count

    def test_format_as_timeline(self):
        """时间线格式化应包含 Step 标记"""
        self.tracer.start_episode("初始")
        self.tracer.record_step("o1", "攻击操作", 1.0, tools=["sqlmap"])
        data = self.tracer.get_tree_data()
        timeline = DecisionTreeTracer.format_as_timeline(data)
        assert "Step 1" in timeline
        assert "攻击操作" in timeline
        assert "sqlmap" in timeline

    def test_failed_action_tracking(self):
        """失败动作应被统计"""
        self.tracer.start_episode("初始")
        self.tracer.record_step("o1", "a1", 0.0, error="连接超时")
        assert self.tracer.failed_actions == 1