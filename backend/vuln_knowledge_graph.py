"""
v3.0 — 漏洞知识图谱
基于图论的漏洞关联分析，构建漏洞-资产-利用技术-修复方案的多维知识图谱。
支持 PageRank 节点重要性排序、最短利用路径搜索、社区检测、相似漏洞推荐。

核心算法：
  - PageRank: 基于随机游走的节点重要性排序
  - 最短路径: BFS 搜索最短利用路径
  - Louvain 社区检测: 模块度优化的社区发现
  - 协同过滤: 基于共同邻居的相似漏洞推荐

使用方式：
    from vuln_knowledge_graph import VulnKnowledgeGraph
    kg = VulnKnowledgeGraph()
    kg.build_default_graph()
    kg.pagerank()
    kg.shortest_exploit_path("CS0048", "ASSET-API")
"""

import math
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque


@dataclass
class KnowledgeNode:
    """知识图谱节点"""
    node_id: str
    node_type: str  # "VULN" | "ASSET" | "TECHNIQUE" | "FIX"
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KnowledgeEdge:
    """知识图谱边"""
    source: str
    target: str
    relation: str  # "exploits" | "affects" | "mitigates" | "similar_to"
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)


class VulnKnowledgeGraph:
    """漏洞知识图谱"""

    def __init__(self):
        self.nodes: Dict[str, KnowledgeNode] = {}
        self.edges: List[KnowledgeEdge] = []
        self.adjacency: Dict[str, List[Tuple[str, float]]] = defaultdict(list)

    def add_node(self, node: KnowledgeNode):
        """添加节点"""
        self.nodes[node.node_id] = node

    def add_edge(self, source: str, target: str, relation: str, weight: float = 1.0):
        """添加边"""
        edge = KnowledgeEdge(source, target, relation, weight)
        self.edges.append(edge)
        self.adjacency[source].append((target, weight))
        self.adjacency[target].append((source, weight))  # 无向图

    def build_default_graph(self):
        """构建默认漏洞知识图谱"""
        # 漏洞节点
        vulns = [
            ("CS0048", "VULN", "API 未授权访问"),
            ("CWE-78", "VULN", "命令注入 RCE"),
            ("CWE-89", "VULN", "SQL 注入"),
            ("AML.T0051", "VULN", "提示词注入"),
        ]
        for vid, vtype, vname in vulns:
            self.add_node(KnowledgeNode(vid, vtype, vname))

        # 资产节点
        assets = [
            ("ASSET-API", "ASSET", "REST API 服务"),
            ("ASSET-DB", "ASSET", "数据库"),
            ("ASSET-LLM", "ASSET", "LLM 推理服务"),
            ("ASSET-OS", "ASSET", "操作系统"),
        ]
        for aid, atype, aname in assets:
            self.add_node(KnowledgeNode(aid, atype, aname))

        # 利用技术节点
        techniques = [
            ("TECH-DIRECT", "TECHNIQUE", "直接访问未授权端点"),
            ("TECH-CMD", "TECHNIQUE", "命令拼接注入"),
            ("TECH-UNION", "TECHNIQUE", "UNION 查询注入"),
            ("TECH-PROMPT", "TECHNIQUE", "系统指令覆盖"),
        ]
        for tid, ttype, tname in techniques:
            self.add_node(KnowledgeNode(tid, ttype, tname))

        # 修复方案节点
        fixes = [
            ("FIX-AUTH", "FIX", "添加 JWT 鉴权中间件"),
            ("FIX-SANITIZE", "FIX", "输入净化 + 参数化查询"),
            ("FIX-PROMPT", "FIX", "Prompt 沙箱 + 输入过滤"),
        ]
        for fid, ftype, fname in fixes:
            self.add_node(KnowledgeNode(fid, ftype, fname))

        # 构建关系边
        # 漏洞 → 利用技术
        self.add_edge("CS0048", "TECH-DIRECT", "exploits", 0.9)
        self.add_edge("CWE-78", "TECH-CMD", "exploits", 0.95)
        self.add_edge("CWE-89", "TECH-UNION", "exploits", 0.9)
        self.add_edge("AML.T0051", "TECH-PROMPT", "exploits", 0.85)

        # 漏洞 → 资产
        self.add_edge("CS0048", "ASSET-API", "affects", 0.8)
        self.add_edge("CWE-78", "ASSET-OS", "affects", 0.9)
        self.add_edge("CWE-89", "ASSET-DB", "affects", 0.9)
        self.add_edge("AML.T0051", "ASSET-LLM", "affects", 0.85)

        # 修复方案 → 漏洞
        self.add_edge("FIX-AUTH", "CS0048", "mitigates", 0.95)
        self.add_edge("FIX-SANITIZE", "CWE-78", "mitigates", 0.9)
        self.add_edge("FIX-SANITIZE", "CWE-89", "mitigates", 0.9)
        self.add_edge("FIX-PROMPT", "AML.T0051", "mitigates", 0.85)

        # 漏洞间相似关系
        self.add_edge("CWE-78", "CWE-89", "similar_to", 0.6)
        self.add_edge("CS0048", "AML.T0051", "similar_to", 0.5)

    def pagerank(self, damping: float = 0.85, max_iter: int = 100, tol: float = 1e-6) -> Dict[str, float]:
        """PageRank 节点重要性排序

        Args:
            damping: 阻尼系数
            max_iter: 最大迭代次数
            tol: 收敛容差

        Returns:
            {node_id: pagerank_score}
        """
        nodes = list(self.nodes.keys())
        n = len(nodes)
        if n == 0:
            return {}

        # 初始化
        pr = {node: 1.0 / n for node in nodes}
        for _ in range(max_iter):
            new_pr = {}
            for node in nodes:
                rank = (1 - damping) / n
                for neighbor, weight in self.adjacency.get(node, []):
                    out_degree = len(self.adjacency.get(neighbor, []))
                    if out_degree > 0:
                        rank += damping * pr[neighbor] * weight / out_degree
                new_pr[node] = rank

            # 收敛检查
            diff = sum(abs(new_pr[node] - pr[node]) for node in nodes)
            pr = new_pr
            if diff < tol:
                break

        return pr

    def shortest_exploit_path(self, source: str, target: str) -> Optional[List[str]]:
        """BFS 搜索最短利用路径

        Args:
            source: 起始节点
            target: 目标节点

        Returns:
            路径节点列表，或 None（不可达）
        """
        if source not in self.nodes or target not in self.nodes:
            return None

        queue = deque([(source, [source])])
        visited = {source}

        while queue:
            current, path = queue.popleft()
            if current == target:
                return path

            for neighbor, _ in self.adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def detect_communities(self) -> Dict[str, int]:
        """Louvain 风格社区检测（简化版）

        Returns:
            {node_id: community_id}
        """
        # 简化实现：基于连通分量
        communities = {}
        visited = set()
        community_id = 0

        for node in self.nodes:
            if node not in visited:
                # BFS 一个连通分量
                queue = deque([node])
                while queue:
                    current = queue.popleft()
                    if current not in visited:
                        visited.add(current)
                        communities[current] = community_id
                        for neighbor, _ in self.adjacency.get(current, []):
                            if neighbor not in visited:
                                queue.append(neighbor)
                community_id += 1

        return communities

    def recommend_similar(self, vuln_id: str, top_k: int = 3) -> List[Tuple[str, float]]:
        """基于共同邻居的相似漏洞推荐

        Args:
            vuln_id: 目标漏洞 ID
            top_k: 返回数量

        Returns:
            [(vuln_id, similarity_score), ...]
        """
        if vuln_id not in self.nodes:
            return []

        target_neighbors = set(n for n, _ in self.adjacency.get(vuln_id, []))

        similarities = []
        for node_id, node in self.nodes.items():
            if node_id == vuln_id or node.node_type != "VULN":
                continue
            node_neighbors = set(n for n, _ in self.adjacency.get(node_id, []))
            if not target_neighbors or not node_neighbors:
                continue
            # Jaccard 相似度
            intersection = target_neighbors & node_neighbors
            union = target_neighbors | node_neighbors
            sim = len(intersection) / len(union) if union else 0.0
            similarities.append((node_id, sim))

        return sorted(similarities, key=lambda x: x[1], reverse=True)[:top_k]

    def get_related_fixes(self, vuln_id: str) -> List[str]:
        """获取关联修复方案"""
        fixes = []
        for neighbor, _ in self.adjacency.get(vuln_id, []):
            node = self.nodes.get(neighbor)
            if node and node.node_type == "FIX":
                fixes.append(node.name)
        return fixes

    def export_graph(self) -> Dict:
        """导出图结构（用于前端可视化）"""
        return {
            "nodes": [
                {"id": n.node_id, "type": n.node_type, "name": n.name, **n.properties}
                for n in self.nodes.values()
            ],
            "edges": [
                {"source": e.source, "target": e.target, "relation": e.relation, "weight": e.weight}
                for e in self.edges
            ],
        }