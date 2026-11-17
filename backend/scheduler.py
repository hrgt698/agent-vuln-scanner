"""
基于 DAG 的漏洞扫描任务调度器
将漏洞扫描任务建模为有向无环图，按拓扑排序结果执行，
支持依赖关系解析、自适应超时和并发执行。
使用方式：from scheduler import DAGScheduler, AdaptiveScheduler
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Awaitable


@dataclass
class VulnTask:
    """漏洞扫描任务定义"""
    script: str
    name: str
    cve: str
    dependencies: List[str] = field(default_factory=list)
    priority: int = 5
    weight: float = 1.0        # 预估耗时权重
    risk_level: str = "high"
    retry_on_failure: bool = True
    max_retries: int = 2


class DAGScheduler:
    """基于 DAG 的漏洞扫描任务调度器
    支持：拓扑排序、依赖解析、并行执行、失败跳过
    """

    def __init__(self):
        self.tasks: Dict[str, VulnTask] = {}

    def add_task(self, task: VulnTask):
        """注册一个漏洞扫描任务"""
        self.tasks[task.cve] = task

    def get_execution_order(self) -> List[str]:
        """返回拓扑排序后的执行顺序
        先按依赖关系拓扑排序，无依赖则按优先级降序

        异常：
            ValueError: 当检测到环形依赖时抛出
        """
        # 构建邻接表
        in_degree = {cve: 0 for cve in self.tasks}
        adj = {cve: [] for cve in self.tasks}

        for cve, task in self.tasks.items():
            for dep in task.dependencies:
                if dep in self.tasks:
                    adj.setdefault(dep, []).append(cve)
                    in_degree[cve] = in_degree.get(cve, 0) + 1

        # ========== v2.4 新增：环形依赖检测（DFS + 三色标记法）==========
        UNVISITED, VISITING, VISITED = 0, 1, 2
        color = {cve: UNVISITED for cve in self.tasks}
        cycle_path = []

        def dfs(node: str) -> bool:
            """DFS 检测环形依赖，返回是否发现环，更新 cycle_path"""
            color[node] = VISITING
            cycle_path.append(node)
            for neighbor in adj.get(node, []):
                if neighbor not in color:
                    continue
                if color[neighbor] == VISITING:
                    # 发现环：截取从环起点到当前节点的路径
                    cycle_start = cycle_path.index(neighbor)
                    cycle_nodes = cycle_path[cycle_start:]
                    raise ValueError(
                        f"环形依赖检测失败：CVE {' → '.join(cycle_nodes)} → {neighbor}"
                    )
                if color[neighbor] == UNVISITED:
                    if dfs(neighbor):
                        return True
            color[node] = VISITED
            cycle_path.pop()
            return False

        for cve in self.tasks:
            if color[cve] == UNVISITED:
                try:
                    dfs(cve)
                except ValueError:
                    raise  # 直接向上传播环形依赖异常

        # Kahn 拓扑排序
        queue = [cve for cve, deg in in_degree.items() if deg == 0]
        # 按优先级排序（优先级高的先执行）
        queue.sort(key=lambda c: self.tasks[c].priority, reverse=True)

        order = []
        while queue:
            node = queue.pop(0)
            order.append(node)
            for neighbor in adj.get(node, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    queue.sort(key=lambda c: self.tasks[c].priority, reverse=True)

        # 如果有环（未遍历完），将剩余节点按优先级追加
        remaining = [cve for cve in self.tasks if cve not in order]
        remaining.sort(key=lambda c: self.tasks[c].priority, reverse=True)
        order.extend(remaining)

        return order

    async def execute_all(
        self,
        run_func: Callable[[str, str], Awaitable[dict]],
        target_url: str,
    ) -> Dict[str, dict]:
        """按依赖关系执行所有任务
        同一层级的无依赖任务可以并行执行
        """
        try:
            order = self.get_execution_order()
        except ValueError as e:
            # 环形依赖：返回错误信息，不中断整个流程
            return {
                "CYCLE_ERROR": {
                    "cve_id": "CYCLE_DETECTED",
                    "vuln_name": "环形依赖检测",
                    "status": "error",
                    "execution_log": str(e),
                }
            }
        results: Dict[str, dict] = {}

        # 分层执行：每层可以并行
        executed = set()
        remaining = set(order)

        while remaining:
            # 找出当前层：所有依赖都已满足的任务
            current_layer = []
            for cve in list(remaining):
                task = self.tasks[cve]
                deps_ok = all(
                    dep in executed or dep not in self.tasks
                    for dep in task.dependencies
                )
                if deps_ok:
                    current_layer.append(cve)

            if not current_layer:
                # 死锁或依赖无法满足，直接执行剩余任务
                current_layer = list(remaining)
                break

            # 并行执行当前层的所有任务
            tasks_to_run = []
            for cve in current_layer:
                task = self.tasks[cve]
                tasks_to_run.append(self._run_with_retry(run_func, task, target_url))

            layer_results = await asyncio.gather(*tasks_to_run, return_exceptions=True)

            for cve, result in zip(current_layer, layer_results):
                if isinstance(result, Exception):
                    results[cve] = {
                        "cve_id": self.tasks[cve].cve,
                        "vuln_name": self.tasks[cve].name,
                        "status": "error",
                        "execution_log": f"调度执行异常: {str(result)}",
                    }
                else:
                    results[cve] = result
                executed.add(cve)
                remaining.discard(cve)

        return results

    async def _run_with_retry(
        self,
        run_func: Callable[[str, str], Awaitable[dict]],
        task: VulnTask,
        target_url: str,
    ) -> dict:
        """带重试机制的任务执行"""
        last_error = None
        max_attempts = task.max_retries if task.retry_on_failure else 1

        for attempt in range(1, max_attempts + 1):
            try:
                result = await run_func(task.script, target_url, attempt)
                if result.get("status") == "success":
                    result["execution_log"] = (
                        f"{result.get('execution_log', '')}\n"
                        f"[*] 第 {attempt}/{max_attempts} 次尝试成功"
                    )
                    return result
                last_error = result
            except Exception as e:
                last_error = {
                    "cve_id": task.cve,
                    "vuln_name": task.name,
                    "status": "error",
                    "execution_log": f"第 {attempt} 次尝试失败: {str(e)}",
                }

        last_error["execution_log"] = (
            f"{last_error.get('execution_log', '')}\n"
            f"[-] 重试 {max_attempts} 次后仍失败"
        )
        return last_error


class AdaptiveScheduler:
    """自适应调度器：根据历史数据动态调整执行策略"""

    def __init__(self, history_window: int = 10):
        self.history: Dict[str, List[dict]] = {}
        self.timeout_base = 60
        self.history_window = history_window

    def record_result(self, cve: str, success: bool, duration: float):
        """记录一次扫描的执行结果"""
        if cve not in self.history:
            self.history[cve] = []
        self.history[cve].append({"success": success, "duration": duration})
        # 保持历史窗口大小
        while len(self.history[cve]) > self.history_window:
            self.history[cve].pop(0)

    def get_stats(self, cve: str) -> dict:
        """获取某个漏洞的历史执行统计数据"""
        records = self.history.get(cve, [])
        if not records:
            return {
                "avg_duration": self.timeout_base,
                "success_rate": 0.5,
                "samples": 0,
            }
        avg_dur = sum(r["duration"] for r in records) / len(records)
        succ_rate = sum(1 for r in records if r["success"]) / len(records)
        return {
            "avg_duration": avg_dur,
            "success_rate": succ_rate,
            "samples": len(records),
        }

    def get_recommended_timeout(self, cve: str) -> int:
        """根据历史平均耗时动态推荐超时时间"""
        stats = self.get_stats(cve)
        if stats["samples"] == 0:
            return self.timeout_base
        return min(int(stats["avg_duration"] * 2.5), 120)

    def get_recommended_retries(self, cve: str) -> int:
        """失败率高的漏洞自动增加重试次数"""
        stats = self.get_stats(cve)
        if stats["samples"] == 0:
            return 1
        return 2 if stats["success_rate"] < 0.5 else 1