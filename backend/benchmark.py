"""
DAG 调度器性能基准测试模块 v2.4
评估不同并发规模下调度器的吞吐量、响应延迟、调度开销。
使用方式：python benchmark.py
"""

import asyncio
import time
import statistics
import json
from typing import List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class BenchmarkResult:
    """单次基准测试结果"""
    concurrency: int
    total_tasks: int
    duration_seconds: float
    throughput_tasks_per_sec: float = 0.0
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    success_count: int = 0
    error_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "concurrency": self.concurrency,
            "total_tasks": self.total_tasks,
            "duration_seconds": round(self.duration_seconds, 3),
            "throughput_tasks_per_sec": round(self.throughput_tasks_per_sec, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "p50_latency_ms": round(self.p50_latency_ms, 2),
            "p95_latency_ms": round(self.p95_latency_ms, 2),
            "p99_latency_ms": round(self.p99_latency_ms, 2),
            "max_latency_ms": round(self.max_latency_ms, 2),
            "min_latency_ms": round(self.min_latency_ms, 2),
            "success_count": self.success_count,
            "error_count": self.error_count,
        }


@dataclass
class TaskNode:
    """模拟任务节点"""
    task_id: str
    duration_ms: float
    dependencies: List[str] = field(default_factory=list)


def simulate_task(task: TaskNode) -> float:
    """模拟任务执行（sleep 指定毫秒）"""
    time.sleep(task.duration_ms / 1000.0)
    return task.duration_ms


def generate_dag层间并行(concurrency: int) -> List[List[TaskNode]]:
    """生成一个 DAG（每层节点可并行执行，模拟真实扫描场景）

    结构：layer_0 → layer_1 → layer_2 → layer_3
    每层 1~concurrency 个节点，节点 duration 随机（10~100ms）
    """
    import random
    import uuid

    layers = []
    for layer_idx in range(4):
        node_count = random.randint(1, concurrency)
        layer = []
        for node_idx in range(node_count):
            # 第一层节点无依赖，后续层依赖上一层的所有节点
            deps = (
                []
                if layer_idx == 0
                else [f"layer_{layer_idx - 1}_node_{i}"
                     for i in range(layers[layer_idx - 1])]
            )
            layer.append(TaskNode(
                task_id=f"layer_{layer_idx}_node_{node_idx}_{uuid.uuid4().hex[:4]}",
                duration_ms=random.uniform(10, 100),
                dependencies=deps,
            ))
        layers.append(layer)
    return layers


class DAGScheduler:
    """DAG 调度器基准测试封装"""

    def __init__(self):
        self.results: List[float] = []

    def kahn_topological_sort(self, layers: List[List[TaskNode]]) -> List[TaskNode]:
        """Kahn 拓扑排序（BFS 层级调度）"""
        all_nodes = {}
        in_degree = {}
        layer_map = {}

        for layer in layers:
            for node in layer:
                all_nodes[node.task_id] = node
                in_degree[node.task_id] = len(node.dependencies)
                layer_map[node.task_id] = 0

        for layer_idx, layer in enumerate(layers):
            for node in layer:
                layer_map[node.task_id] = layer_idx

        sorted_nodes = []
        current_layer = 0
        max_layer = len(layers)

        while current_layer < max_layer:
            current_layer_nodes = [
                node for node in layers[current_layer]
                if all_nodes[node.task_id] is not None
            ]

            if not current_layer_nodes:
                break

            for node in current_layer_nodes:
                sorted_nodes.append(node)
                all_nodes[node.task_id] = None  # 标记已处理

                # 降低所有子节点的入度
                for next_layer_idx in range(current_layer + 1, max_layer):
                    for next_node in layers[next_layer_idx]:
                        if node.task_id in next_node.dependencies:
                            in_degree[next_node.task_id] -= 1

            current_layer += 1

        return sorted_nodes

    async def execute_dag(self, layers: List[List[TaskNode]]) -> List[float]:
        """异步执行 DAG，模拟真实并发扫描"""
        self.results = []

        # 构建 layer_map（节点 → 层索引）
        layer_map: Dict[str, int] = {}
        for layer_idx, layer in enumerate(layers):
            for node in layer:
                layer_map[node.task_id] = layer_idx

        all_nodes = self.kahn_topological_sort(layers)

        async def execute_node(node: TaskNode) -> float:
            start = time.perf_counter()
            # 模拟任务执行延迟
            await asyncio.sleep(node.duration_ms / 1000.0)
            elapsed = (time.perf_counter() - start) * 1000
            self.results.append(elapsed)
            return elapsed

        # 按层间并行调度
        layer_nodes: Dict[int, List[TaskNode]] = {}
        for node in all_nodes:
            layer_idx = layer_map.get(node.task_id, 0)
            if layer_idx not in layer_nodes:
                layer_nodes[layer_idx] = []
            layer_nodes[layer_idx].append(node)

        for layer_idx in sorted(layer_nodes.keys()):
            nodes = layer_nodes[layer_idx]
            await asyncio.gather(*[execute_node(n) for n in nodes])

        return self.results


async def run_benchmark(
    concurrency_levels: List[int],
    total_tasks: int = 50,
) -> List[BenchmarkResult]:
    """运行基准测试，对多个并发级别进行评估"""
    results = []

    for concurrency in concurrency_levels:
        print(f"\n{'=' * 60}")
        print(f"  并发级别: {concurrency}")
        print(f"{'=' * 60}")

        scheduler = DAGScheduler()
        layers = generate_dag层间并行(concurrency)

        # 统计实际任务数
        actual_tasks = sum(len(layer) for layer in layers)
        print(f"  实际任务数: {actual_tasks}")

        # 执行基准测试
        start_time = time.perf_counter()
        all_times = await scheduler.execute_dag(layers)
        duration = time.perf_counter() - start_time

        if not all_times:
            print("  ⚠️ 无有效任务执行结果")
            continue

        all_times_sorted = sorted(all_times)
        n = len(all_times_sorted)

        result = BenchmarkResult(
            concurrency=concurrency,
            total_tasks=actual_tasks,
            duration_seconds=duration,
            throughput_tasks_per_sec=actual_tasks / duration,
            avg_latency_ms=statistics.mean(all_times),
            p50_latency_ms=all_times_sorted[int(n * 0.50)],
            p95_latency_ms=all_times_sorted[int(n * 0.95)] if n >= 20 else all_times_sorted[-1],
            p99_latency_ms=all_times_sorted[int(n * 0.99)] if n >= 100 else all_times_sorted[-1],
            max_latency_ms=max(all_times),
            min_latency_ms=min(all_times),
            success_count=len(all_times),
            error_count=0,
        )

        print(f"  总耗时:       {result.duration_seconds:.3f}s")
        print(f"  吞吐量:       {result.throughput_tasks_per_sec:.2f} 任务/秒")
        print(f"  平均延迟:     {result.avg_latency_ms:.2f}ms")
        print(f"  P50 延迟:     {result.p50_latency_ms:.2f}ms")
        print(f"  P95 延迟:     {result.p95_latency_ms:.2f}ms")
        print(f"  P99 延迟:     {result.p99_latency_ms:.2f}ms")
        print(f"  最大延迟:     {result.max_latency_ms:.2f}ms")
        print(f"  最小延迟:     {result.min_latency_ms:.2f}ms")

        results.append(result)

    return results


async def main():
    """主入口：运行标准基准测试套件"""
    print("=" * 60)
    print("  DAG 调度器性能基准测试 v2.4")
    print("  评估不同并发规模下的调度器性能表现")
    print("=" * 60)

    # 标准测试场景：10/50/100 并发级别
    concurrency_levels = [10, 50, 100]
    all_results = await run_benchmark(concurrency_levels)

    # 生成汇总报告
    print("\n" + "=" * 60)
    print("  基准测试汇总报告")
    print("=" * 60)
    print(f"{'并发':>8} {'任务数':>8} {'耗时(s)':>10} {'吞吐量':>12} {'P50(ms)':>10} {'P95(ms)':>10}")
    print("-" * 60)
    for r in all_results:
        print(
            f"{r.concurrency:>8} "
            f"{r.total_tasks:>8} "
            f"{r.duration_seconds:>10.3f} "
            f"{r.throughput_tasks_per_sec:>12.2f} "
            f"{r.p50_latency_ms:>10.2f} "
            f"{r.p95_latency_ms:>10.2f}"
        )

    # 导出 JSON 报告
    report_path = "./data/benchmark_results.json"
    import os
    os.makedirs("./data", exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in all_results], f, indent=2, ensure_ascii=False)
    print(f"\n📄 详细报告已导出: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())
