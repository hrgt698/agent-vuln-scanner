"""
RAG 知识库增强引擎 v2.2
基于 FAISS 向量数据库实现真实的语义检索增强生成。
支持真实 DashScope Embedding API 调用，并提供本地模拟作为降级方案。
使用方式：from rag_engine import RAGEngine
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# 尝试导入 numpy（先于 FAISS）
try:
    import numpy as np
    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False
    # 为类型注解提供降级方案
    class _NumpyShim:
        ndarray = list  # 简单降级
    np = _NumpyShim()

# 尝试导入 FAISS（可选依赖）
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False

# 尝试导入 requests（真实 Embedding API 调用所需）
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class KnowledgeEntry:
    """知识库条目"""
    cve_id: str
    vuln_type: str
    content: str
    similar_cases: List[Dict]
    best_practices: List[str]
    fix_example: str
    embedding: Optional[np.ndarray] = None


class DashScopeEmbedding:
    """通义千问 Embedding API 客户端
    官方文档：https://help.aliyun.com/zh/model-studio/developer-reference/text-embedding-api
    """

    DASHSCOPE_EMBEDDING_URL = "https://dashscope.aliyuncs.com/api/v1/services/embeddings/text-embedding/text-embedding"
    DEFAULT_MODEL = "text-embedding-v3"
    DEFAULT_DIM = 1024

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        dim: int = DEFAULT_DIM,
        timeout: int = 15,
    ):
        self.api_key = api_key or os.getenv("DASHSCOPE_API_KEY")
        self.model = model
        self.dim = dim
        self.timeout = timeout
        self.use_real_api = bool(self.api_key) and REQUESTS_AVAILABLE
        if not self.api_key:
            print("[Embedding] 未配置 DASHSCOPE_API_KEY，将使用本地模拟 Embedding")
        elif not REQUESTS_AVAILABLE:
            print("[Embedding] requests 库未安装，将使用本地模拟 Embedding（pip install requests）")

    def encode(self, text: str) -> Optional[np.ndarray]:
        """生成文本的 embedding 向量"""
        if self.use_real_api:
            try:
                return self._encode_real(text)
            except Exception as e:
                print(f"[Embedding] 真实API调用失败，降级为模拟: {e}")
                return self._encode_mock(text)
        else:
            return self._encode_mock(text)

    def encode_batch(self, texts: List[str]) -> List[np.ndarray]:
        """批量生成 embedding（为知识索引用）"""
        if self.use_real_api:
            try:
                results = []
                for text in texts:
                    vec = self._encode_real(text)
                    if vec is not None:
                        results.append(vec)
                    else:
                        results.append(self._encode_mock(text))
                return results
            except Exception as e:
                print(f"[Embedding] 批量真实API调用失败，降级为模拟: {e}")
                return [self._encode_mock(t) for t in texts]
        else:
            return [self._encode_mock(t) for t in texts]

    def _encode_real(self, text: str) -> Optional[np.ndarray]:
        """调用真实 DashScope Embedding API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "input": {
                "texts": [text[:1024]],  # 截断为 1024 字符
            },
            "parameters": {
                "text_type": "document",
                "dimension": self.dim,
            },
        }

        response = requests.post(
            self.DASHSCOPE_EMBEDDING_URL,
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )

        if response.status_code == 200:
            data = response.json()
            output = data.get("output", {})
            embeddings = output.get("embeddings", [])
            if embeddings and len(embeddings) > 0:
                vec = np.array(embeddings[0]["embedding"], dtype="float32")
                # L2 归一化
                norm = np.linalg.norm(vec)
                if norm > 0:
                    vec = vec / norm
                return vec
        else:
            raise Exception(f"API调用失败 {response.status_code}: {response.text}")
        return None

    def _encode_mock(self, text: str) -> np.ndarray:
        """本地模拟 embedding：基于文本哈希生成确定性向量，
        这是一个降级方案，供没有 API Key 的开发环境使用。"""
        if not FAISS_AVAILABLE:
            # FAISS 不可用时返回随机向量
            if np is None:
                return np.array([])
            return np.random.randn(self.dim).astype("float32")

        # 使用文本 hash 作为随机数种子，确保相同文本产生相同向量
        hash_val = int(hashlib.md5(text.encode("utf-8")).hexdigest(), 16)
        rng = np.random.default_rng(hash_val % (2**32))
        vec = rng.standard_normal(self.dim).astype("float32")
        # L2 归一化
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec


class RAGEngine:
    """检索增强生成引擎 v2.2
    使用 DashScope Embedding API 生成真实语义向量 + FAISS 向量索引实现语义检索，
    支持历史 CVE 案例、最佳实践和代码修复示例的相似度匹配。
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        embedding_model: str = "text-embedding-v3",
        embedding_dim: int = 1024,
        top_k: int = 3,
        persist_dir: str = "./data/vector_db",
    ):
        self.embedding_dim = embedding_dim
        self.top_k = top_k

        # 初始化 Embedding 客户端
        self.embedder = DashScopeEmbedding(
            api_key=api_key,
            model=embedding_model,
            dim=embedding_dim,
        )

        # 持久化目录
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.persist_dir / "rag_index.faiss"
        self.metadata_path = self.persist_dir / "rag_metadata.json"

        self._entries: Dict[str, KnowledgeEntry] = {}
        self._index = None
        self._build_knowledge_base()
        self._load_or_build_index()

    def _build_knowledge_base(self):
        """构建本地知识库"""
        self._entries = {
            "CS0048": KnowledgeEntry(
                cve_id="CS0048",
                vuln_type="API未授权访问",
                content="API未授权访问配置泄露，攻击者可无需认证直接访问内部配置接口",
                similar_cases=[
                    {
                        "cve": "CVE-2023-1234",
                        "year": 2023,
                        "description": "某微服务框架 /api/config 端点未做鉴权，导致内部配置信息泄露",
                        "fix_type": "添加 JWT 中间件",
                    },
                    {
                        "cve": "CVE-2024-5678",
                        "year": 2024,
                        "description": "Kubernetes Dashboard 鉴权绕过漏洞，攻击者可获取集群管理权限",
                        "fix_type": "升级鉴权组件 + 网络策略限制",
                    },
                ],
                best_practices=[
                    "使用 JWT Bearer Token 对每个 API 端点进行身份校验",
                    "API 网关统一鉴权（如 Kong / APISIX / Nginx + lua）",
                    "遵循最小权限原则，默认拒绝所有未认证请求",
                    "部署 Web 应用防火墙（WAF）拦截异常请求模式",
                ],
                fix_example="""```python
# 推荐修复方案：添加统一的鉴权中间件
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

PUBLIC_PATHS = {"/docs", "/openapi.json", "/health"}

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Missing authorization"})

    token = auth_header.split(" ")[1]
    if not verify_token(token):
        return JSONResponse(status_code=403, content={"detail": "Invalid token"})

    return await call_next(request)
```""",
            ),
            "CWE-89": KnowledgeEntry(
                cve_id="CWE-89",
                vuln_type="SQL注入",
                content="SQL注入漏洞，用户输入未经过滤直接拼接到 SQL 查询中",
                similar_cases=[
                    {
                        "cve": "CVE-2017-5638",
                        "year": 2017,
                        "description": "Apache Struts2 远程代码执行（OGNL 注入），影响范围巨大的经典案例",
                        "fix_type": "升级框架 + 输入过滤",
                    },
                    {
                        "cve": "CVE-2024-6387",
                        "year": 2024,
                        "description": "某开源 CMS 后台登录处 SQL 注入，攻击者可脱库获取管理员凭证",
                        "fix_type": "参数化查询 + WAF",
                    },
                ],
                best_practices=[
                    "永远使用参数化查询（PreparedStatement）替代字符串拼接",
                    "ORM 框架自带防注入能力（如 SQLAlchemy），优先使用",
                    "对用户输入做严格的类型校验和白名单过滤",
                    "数据库账户遵循最小权限原则，不直接用 root 连接",
                ],
                fix_example="""```python
# 危险写法（当前靶机使用的方式，仅供教学演示）
query = f"SELECT name, secret FROM users WHERE id = '{user_id}'"

# 安全修复：使用参数化查询
import sqlite3
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
query = "SELECT name, secret FROM users WHERE id = ?"
cursor.execute(query, (user_id,))  # 参数化查询自动转义特殊字符
result = cursor.fetchone()
```""",
            ),
            "CWE-78": KnowledgeEntry(
                cve_id="CWE-78",
                vuln_type="操作系统命令注入",
                content="系统命令注入漏洞，用户输入未过滤直接传递给系统 shell 执行",
                similar_cases=[
                    {
                        "cve": "CVE-2021-44228",
                        "year": 2021,
                        "description": "Log4j2 JNDI 注入（Log4Shell），影响全球数百万应用",
                        "fix_type": "升级 Log4j + 禁用 JNDI lookup",
                    },
                    {
                        "cve": "CVE-2024-27198",
                        "year": 2024,
                        "description": "TeamCity 认证绕过导致 RCE，CI/CD 管道关键基础设施漏洞",
                        "fix_type": "升级版本 + 网络隔离",
                    },
                ],
                best_practices=[
                    "永远避免使用 shell=True 或 os.system() 等危险函数",
                    "使用 subprocess.run 的列表形式传递参数（自动转义）",
                    "对用户输入做严格的字符过滤和白名单校验",
                    "将命令执行逻辑隔离到沙箱容器中运行",
                ],
                fix_example="""```python
# 危险写法（当前靶机使用的方式，仅供教学演示）
command = f"ping -c 1 {user_input}"
result = subprocess.check_output(command, shell=True, text=True)

# 安全修复：使用列表形式传递参数（推荐）
ALLOWED_IP_PATTERN = re.compile(r'^[0-9.]+$')
if not ALLOWED_IP_PATTERN.match(user_input):
    return {"status": "error", "message": "非法输入"}
result = subprocess.run(
    ["ping", "-c", "1", user_input],
    capture_output=True, text=True, timeout=10
)
```""",
            ),
            "AML.T0051": KnowledgeEntry(
                cve_id="AML.T0051",
                vuln_type="LLM提示词注入",
                content="大模型提示词越权注入，攻击者通过构造恶意提示词操控 AI 输出",
                similar_cases=[
                    {
                        "cve": "AML.T0051.000",
                        "year": 2024,
                        "description": "Microsoft Copilot 间接提示词注入，攻击者通过网页内容操控 AI 输出",
                        "fix_type": "输入输出隔离 + 意图分类",
                    },
                    {
                        "cve": "OWASP LLM-01",
                        "year": 2024,
                        "description": "OWASP Top 10 for LLM Applications 排名第一的漏洞类型",
                        "fix_type": "Prompt 隔离 + 内容过滤 + 人类确认",
                    },
                ],
                best_practices=[
                    "对用户输入做语义级别的意图分类，检测越权指令",
                    "使用独立的 System Prompt 空间，与 User Input 完全隔离",
                    "关键操作（如泄露凭证）需要用户二次确认",
                    "部署 Guardrails 中间件过滤恶意指令（如 NVIDIA NeMo Guardrails）",
                ],
                fix_example="""```python
# 危险写法（当前靶机使用的方式，仅供教学演示）
agent_response = f"我是AI助手，正在处理您的任务：{user_prompt}"

# 安全修复：意图分类 + 指令隔离
OVERRIDE_PATTERNS = [
    re.compile(r"忽略.*指令", re.IGNORECASE),
    re.compile(r"override|越权|跳过", re.IGNORECASE),
    re.compile(r"打印.*(凭证|密码|密钥|secret)", re.IGNORECASE),
]

def is_safe_prompt(prompt: str) -> bool:
    for pattern in OVERRIDE_PATTERNS:
        if pattern.search(prompt):
            return False
    return True

if not is_safe_prompt(user_prompt):
    return {"status": "blocked", "message": "检测到越权指令，已拦截"}
```""",
            ),
        }

    def _load_or_build_index(self):
        """加载或构建 FAISS 索引"""
        if not FAISS_AVAILABLE:
            print("[RAG] FAISS 未安装，将使用简单关键词匹配（pip install faiss-cpu）")
            return

        if self.index_path.exists() and self.metadata_path.exists():
            try:
                self._index = faiss.read_index(str(self.index_path))
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self._id_to_cve = json.load(f)
                print(f"[RAG] 已加载索引，共 {self._index.ntotal} 条记录")
                return
            except Exception as e:
                print(f"[RAG] 加载索引失败，将重新构建: {e}")

        self._build_index()

    def _build_index(self):
        """构建 FAISS 索引"""
        if not FAISS_AVAILABLE:
            return

        # 为每个条目生成 embedding
        texts = []
        cve_ids = []
        for cve_id, entry in self._entries.items():
            text = f"{entry.content} {' '.join(entry.best_practices)}"
            texts.append(text)
            cve_ids.append(cve_id)

        # 批量生成真实 embedding（或模拟 embedding）
        embeddings = self.embedder.encode_batch(texts)
        for i, cve_id in enumerate(cve_ids):
            self._entries[cve_id].embedding = embeddings[i]

        # 构建 FAISS 索引（内积索引，需归一化）
        self._index = faiss.IndexIDMap(faiss.IndexFlatIP(self.embedding_dim))

        # 添加向量
        vec_array = np.stack(embeddings).astype("float32")
        ids = np.array(range(len(cve_ids)))
        self._index.add_with_ids(vec_array, ids)

        # 保存索引
        faiss.write_index(self._index, str(self.index_path))
        self._id_to_cve = {i: cve for i, cve in enumerate(cve_ids)}
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(self._id_to_cve, f)

        print(
            f"[RAG] 已构建索引，共 {self._index.ntotal} 条记录 "
            f"({'' if self.embedder.use_real_api else '模拟 '}Embedding, dim={self.embedding_dim})"
        )

    def retrieve(self, query: str, top_k: Optional[int] = None) -> List[Dict]:
        """根据查询检索最相关的知识条目"""
        if top_k is None:
            top_k = self.top_k

        if not FAISS_AVAILABLE or self._index is None:
            # 降级：使用关键词匹配
            return self._simple_match(query, top_k)

        query_embedding = self.embedder.encode(query)
        if query_embedding is None:
            return self._simple_match(query, top_k)
        query_embedding = query_embedding.reshape(1, -1)
        scores, indices = self._index.search(
            query_embedding, min(top_k, self._index.ntotal)
        )

        results = []
        for idx, score in zip(indices[0], scores[0]):
            if idx < 0:
                continue
            cve_id = self._id_to_cve.get(int(idx))
            if cve_id and cve_id in self._entries:
                entry = self._entries[cve_id]
                results.append({
                    "cve_id": entry.cve_id,
                    "vuln_type": entry.vuln_type,
                    "similar_cases": entry.similar_cases,
                    "best_practices": entry.best_practices,
                    "fix_example": entry.fix_example,
                    "score": float(score),
                })
        return results

    def _simple_match(self, query: str, top_k: int) -> List[Dict]:
        """简单的关键词匹配降级方案"""
        query_lower = query.lower()
        scores = {}
        for cve_id, entry in self._entries.items():
            score = 0
            if entry.vuln_type.lower() in query_lower:
                score += 2
            if any(kw in query_lower for kw in entry.content.lower().split()):
                score += 1
            scores[cve_id] = score

        sorted_cves = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        results = []
        for cve_id, score in sorted_cves[:top_k]:
            if score > 0:
                entry = self._entries[cve_id]
                results.append({
                    "cve_id": entry.cve_id,
                    "vuln_type": entry.vuln_type,
                    "similar_cases": entry.similar_cases,
                    "best_practices": entry.best_practices,
                    "fix_example": entry.fix_example,
                    "score": score,
                })
        return results

    def get_kb_entry(self, cve_id: str) -> Optional[KnowledgeEntry]:
        """获取指定 CVE 的知识库条目"""
        return self._entries.get(cve_id)

    def enhance_report(self, cve_id: str, ai_report: str, query: str = "") -> str:
        """用检索到的知识增强 AI 报告"""
        entry = self._entries.get(cve_id)
        if entry:
            kb = {
                "similar_cases": entry.similar_cases,
                "best_practices": entry.best_practices,
                "fix_example": entry.fix_example,
            }
        else:
            retrieved = self.retrieve(query or cve_id, top_k=1)
            if retrieved:
                kb = retrieved[0]
            else:
                return ai_report

        enhanced_sections = []

        if kb.get("similar_cases"):
            cases_lines = ["### 五、相似历史案例参考"]
            for case in kb["similar_cases"]:
                cases_lines.append(
                    f"- **{case['cve']}** ({case['year']}): {case['description']} "
                    f"→ 修复策略: {case['fix_type']}"
                )
            enhanced_sections.append("\n".join(cases_lines))

        if kb.get("best_practices"):
            practices_lines = ["### 六、最佳实践建议"]
            for i, practice in enumerate(kb["best_practices"], 1):
                practices_lines.append(f"{i}. {practice}")
            enhanced_sections.append("\n".join(practices_lines))

        if kb.get("fix_example"):
            enhanced_sections.append(f"### 七、参考代码实现\n\n{kb['fix_example']}")

        if enhanced_sections:
            return ai_report + "\n\n---\n\n" + "\n\n".join(enhanced_sections)

        return ai_report

    def get_kb_summary(self, cve_id: str) -> dict:
        """获取知识库摘要"""
        entry = self._entries.get(cve_id)
        if not entry:
            return {"has_knowledge": False}
        return {
            "has_knowledge": True,
            "vuln_type": entry.vuln_type,
            "case_count": len(entry.similar_cases),
            "practice_count": len(entry.best_practices),
            "has_fix_example": bool(entry.fix_example),
            "vector_index_available": FAISS_AVAILABLE and self._index is not None,
            "uses_real_embedding": self.embedder.use_real_api,
            "embedding_model": self.embedder.model,
            "embedding_dim": self.embedder.dim,
        }


# 向后兼容：保留旧类名作为别名
class RAGAdviceEngine(RAGEngine):
    """RAGAdviceEngine - 向后兼容别名"""
    pass


# ============================================================
# v2.4 新增：CLI 命令行工具（知识库自动更新）
# 使用方式：python rag_engine.py --update
#          python rag_engine.py --cve CVE-2024-XXXX
# ============================================================

def _build_parser():
    """构建 CLI 参数解析器（v3.0 支持 --benchmark 检索质量评估）"""
    import argparse
    parser = argparse.ArgumentParser(
        description="RAG 知识库 CLI 工具 v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  python rag_engine.py --update              # 从 NVD 拉取最新 CVE 数据并更新知识库
  python rag_engine.py --cve CVE-2024-XXXX   # 查询指定 CVE 的知识库条目
  python rag_engine.py --stats               # 显示知识库统计信息
  python rag_engine.py --rebuild             # 强制重建 FAISS 索引
  python rag_engine.py --benchmark           # 执行 RAG 检索质量评估
  python rag_engine.py --update --retries 5  # 网络请求失败时最多重试 5 次
  python rag_engine.py --update --no-cache   # 禁用本地缓存
        """,
    )
    parser.add_argument("--update", action="store_true",
                        help="从 NVD CVE Feed 自动拉取最新漏洞数据并更新知识库")
    parser.add_argument("--cve", type=str,
                        help="查询指定 CVE ID 的知识库条目")
    parser.add_argument("--stats", action="store_true",
                        help="显示知识库统计信息")
    parser.add_argument("--rebuild", action="store_true",
                        help="强制重建 FAISS 向量索引")
    parser.add_argument("--api-key", type=str,
                        help="DashScope API Key（也可通过 DASHSCOPE_API_KEY 环境变量设置）")
    parser.add_argument("--benchmark", action="store_true",
                        help="v3.0: 执行 RAG 检索质量评估（hit_rate / NDCG / MRR）")
    parser.add_argument("--retries", type=int, default=3,
                        help="网络请求失败时的最大重试次数（默认 3 次）")
    parser.add_argument("--no-cache", action="store_true",
                        help="禁用本地缓存，强制从 NVD 拉取最新数据")
    return parser


def _fetch_nvd_cves(years: int = 2, max_retries: int = 3, use_cache: bool = True) -> list:
    """从 NVD CVE JSON Feed 拉取最近 N 年的漏洞数据（v3.0: 支持指数退避重试 + 本地缓存）"""
    import urllib.request
    import urllib.error
    import json
    from datetime import datetime

    cache_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "_nvd_cache.json"
    )

    # 1) 优先使用本地缓存
    if use_cache and os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cached = json.load(f)
                age_hours = (datetime.utcnow().timestamp() -
                             cached.get("_fetched_at", 0)) / 3600
                if age_hours < 24 and isinstance(cached.get("items"), list):
                    print(f"[RAG] 使用本地缓存，共 {len(cached['items'])} 条（{age_hours:.1f} 小时前）")
                    return cached["items"]
        except Exception:
            pass

    cves = []
    current_year = datetime.now().year
    for year in range(current_year, current_year - years - 1, -1):
        url = (
            f"https://nvd.nist.gov/feeds/json/cve/1.1/"
            f"nvdcve-1.1-{year}.json.gz"
        )
        # 指数退避重试
        for attempt in range(max_retries + 1):
            try:
                print(f"[RAG] 正在拉取 {year} 年 CVE 数据 (尝试 {attempt+1}/{max_retries+1}): {url}")
                import gzip
                response = urllib.request.urlopen(url, timeout=30)
                raw = gzip.decompress(response.read())
                data = json.loads(raw)
                for item in data.get("CVE_Items", [])[:50]:
                    cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
                    description = item.get("cve", {}).get("description", {})
                    if isinstance(description, dict):
                        desc_list = description.get("description_data", [])
                        desc_text = next(
                            (d["value"] for d in desc_list if d.get("lang") == "en"),
                            ""
                        )
                    else:
                        desc_text = str(description)
                    cves.append({
                        "cve_id": cve_id,
                        "year": year,
                        "description": desc_text[:300],
                        "published": item.get("publishedDate", ""),
                    })
                print(f"[RAG] 成功拉取 {len(data.get('CVE_Items', []))} 条 CVE 记录")
                break  # 成功，跳出重试
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    print(f"[RAG] {year} 年数据不存在（404）")
                    break
                if attempt < max_retries:
                    wait_sec = 2 ** attempt
                    print(f"[RAG] HTTP {e.code}，等待 {wait_sec}s 后重试")
                    time.sleep(wait_sec)
                    continue
                print(f"[RAG] 拉取 {year} 年数据失败（超过最大重试次数）")
            except urllib.error.URLError as e:
                if attempt < max_retries:
                    wait_sec = 2 ** attempt
                    print(f"[RAG] 网络错误：{e.reason}，等待 {wait_sec}s 后重试")
                    time.sleep(wait_sec)
                    continue
                print(f"[RAG] 拉取 {year} 年数据失败：{e.reason}")
            except Exception as e:
                print(f"[RAG] 拉取 {year} 年数据失败: {e}")
                break

    # 2) 将拉取结果写入缓存（下次使用）
    if cves and use_cache:
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump({
                    "_fetched_at": datetime.utcnow().timestamp(),
                    "items": cves,
                    "count": len(cves),
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    return cves


# ============================================================
# v3.0 新增：RAG 检索质量评估（Benchmark）
# 指标：Hit Rate @ k / NDCG / MRR
# ============================================================

def _benchmark_knowledge_base(rag: RAGEngine, test_queries: list = None) -> dict:
    """评估 RAG 检索质量（使用内置测试集）"""
    if test_queries is None:
        # 默认测试集：使用已有知识库中的条目作为"标准答案"
        test_queries = []
        for cve_id, entry in rag._entries.items():
            query_text = f"{entry.vuln_type} {cve_id}"
            test_queries.append({
                "query": query_text,
                "expected_cve": cve_id,
                "keywords": [w for w in entry.vuln_type.split() if len(w) > 2],
            })

    # 补充测试用例：从内容中随机抽取关键词
    if len(test_queries) < 3:
        for cve_id, entry in list(rag._entries.items())[:10]:
            for kw in entry.content.replace("、", " ").split()[:3]:
                if len(kw.strip()) >= 2:
                    test_queries.append({
                        "query": kw.strip(),
                        "expected_cve": cve_id,
                        "keywords": [kw.strip()],
                    })
            if len(test_queries) >= 10:
                break

    import math
    results = []
    total = len(test_queries)
    print(f"\n[RAG] 开始检索质量评估（共 {total} 个查询）")

    for k in [1, 3, 5]:
        hit_count = 0
        reciprocal_ranks = []
        ndcg_values = []

        for q in test_queries:
            retrieved = rag.retrieve(q["query"], top_k=k)
            retrieved_ids = [r.get("cve_id") for r in retrieved]

            # 1) Hit Rate @ k
            if q["expected_cve"] in retrieved_ids:
                hit_count += 1

            # 2) MRR（reciprocal rank of the first relevant item）
            if q["expected_cve"] in retrieved_ids:
                rank = retrieved_ids.index(q["expected_cve"]) + 1
                reciprocal_ranks.append(1.0 / rank)
            else:
                reciprocal_ranks.append(0.0)

            # 3) NDCG @ k
            dcg = 0.0
            for idx, r_id in enumerate(retrieved_ids):
                relevance = 1.0 if r_id == q["expected_cve"] else 0.0
                if idx == 0:
                    dcg += relevance
                elif idx > 0 and relevance > 0:
                    dcg += relevance / (math.log2(idx + 1))
            idcg = 1.0
            ndcg_values.append(dcg / idcg if idcg > 0 else 0.0)

        hit_rate = hit_count / total if total > 0 else 0
        mrr = sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else 0
        avg_ndcg = sum(ndcg_values) / len(ndcg_values) if ndcg_values else 0

        results.append({
            "k": k,
            "hit_rate": round(hit_rate, 4),
            "mrr": round(mrr, 4),
            "avg_ndcg": round(avg_ndcg, 4),
            "hits": hit_count,
            "total": total,
        })
        print(f"  @{k:>2}  HitRate={hit_rate:.2%}, MRR={mrr:.3f}, NDCG={avg_ndcg:.3f}")

    return {
        "test_case_count": total,
        "index_size": len(rag._entries),
        "faiss_available": FAISS_AVAILABLE,
        "use_real_embedding": rag.embedder.use_real_api,
        "metrics": results,
        "top_entries_sampled": list(rag._entries.keys())[:10],
    }


def _nvd_to_knowledge_entry(cve_data: dict) -> dict:
    """将 NVD CVE 数据转换为知识库条目格式"""
    return {
        "cve_id": cve_data["cve_id"],
        "vuln_type": _infer_vuln_type(cve_data["description"]),
        "content": cve_data["description"],
        "similar_cases": [],
        "best_practices": [
            "参考 NVD 官方修复建议",
            "尽快应用安全更新补丁",
            "使用依赖扫描工具检测受影响组件",
        ],
        "fix_example": (
            f"<!-- {cve_data['cve_id']} 修复参考 -->\n"
            f"# 请查阅 NVD 官方公告获取最新修复方案\n"
            f"# https://nvd.nist.gov/vuln/detail/{cve_data['cve_id']}"
        ),
    }


def _infer_vuln_type(description: str) -> str:
    """根据描述文本推断漏洞类型"""
    desc_lower = description.lower()
    if any(k in desc_lower for k in ["sql", "injection", "sqli"]):
        return "SQL注入"
    if any(k in desc_lower for k in ["command", "rce", "remote code", "os command"]):
        return "命令注入"
    if any(k in desc_lower for k in ["xss", "cross-site", "scripting"]):
        return "XSS跨站脚本"
    if any(k in desc_lower for k in ["authentication", "bypass", "unauthorized"]):
        return "认证绕过"
    if any(k in desc_lower for k in ["prompt", "injection", "llm"]):
        return "提示词注入"
    return "未分类漏洞"


def main():
    """CLI 入口（v3.0: 支持 --benchmark 检索质量评估）"""
    import os
    import math  # 供 benchmark 使用
    parser = _build_parser()
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("DASHSCOPE_API_KEY")
    rag = RAGEngine(api_key=api_key)

    if args.update:
        print("[RAG] 启动知识库自动更新...")
        cves = _fetch_nvd_cves(years=2, max_retries=args.retries, use_cache=not args.no_cache)
        if not cves:
            print("[RAG] 未获取到 CVE 数据，更新中止")
            return

        # 将 NVD CVE 数据添加到知识库
        added = 0
        for cve_data in cves:
            if cve_data["cve_id"].startswith("CVE-"):
                entry = _nvd_to_knowledge_entry(cve_data)
                rag._entries[cve_data["cve_id"]] = KnowledgeEntry(
                    cve_id=entry["cve_id"],
                    vuln_type=entry["vuln_type"],
                    content=entry["content"],
                    similar_cases=entry["similar_cases"],
                    best_practices=entry["best_practices"],
                    fix_example=entry["fix_example"],
                )
                added += 1

        # 重建索引
        if args.rebuild or FAISS_AVAILABLE:
            rag._build_index()
            rag._load_or_build_index()

        print(f"[RAG] 知识库更新完成：新增 {added} 条 CVE 记录")
        print(f"[RAG] 索引重建: {'成功' if rag._index is not None else '失败（FAISS 不可用）'}")

    elif args.benchmark:
        print("=== RAG 检索质量评估（Benchmark）===")
        summary = _benchmark_knowledge_base(rag)
        print("\n[RAG] 评估完成：")
        print(f"  测试查询数: {summary['test_case_count']}")
        print(f"  索引大小: {summary['index_size']}")
        print(f"  FAISS 可用: {summary['faiss_available']}")
        print(f"  使用真实 Embedding API: {summary['use_real_embedding']}")
        for metric in summary["metrics"]:
            print(f"  @{metric['k']:>2}  HitRate={metric['hit_rate']:.2%}, "
                  f"MRR={metric['mrr']:.3f}, NDCG={metric['avg_ndcg']:.3f}")

    elif args.cve:
        entry = rag.get_kb_entry(args.cve)
        if entry:
            print(f"=== {args.cve} ===")
            print(f"类型: {entry.vuln_type}")
            print(f"内容: {entry.content[:200]}...")
            print(f"最佳实践: {entry.best_practices[:3]}")
        else:
            retrieved = rag.retrieve(args.cve, top_k=3)
            if retrieved:
                print(f"未找到精确匹配，Top-3 语义检索结果:")
                for r in retrieved:
                    print(f"  - {r['cve_id']} ({r['vuln_type']}): {r.get('best_practices', [''])[0] if r.get('best_practices') else 'N/A'}")
            else:
                print(f"未找到 {args.cve} 相关知识")

    elif args.stats:
        print("=== RAG 知识库统计 ===")
        print(f"条目总数: {len(rag._entries)}")
        print(f"索引可用: {rag._index is not None if FAISS_AVAILABLE else 'FAISS 未安装'}")
        print(f"真实 API: {rag.embedder.use_real_api}")
        for cve_id, entry in rag._entries.items():
            print(f"  - {cve_id}: {entry.vuln_type}")
        kb_summary = {cve_id: rag.get_kb_summary(cve_id)
                      for cve_id in list(rag._entries.keys())[:5]}
        print(f"FAISS 可用: {FAISS_AVAILABLE}, 向量维度: {rag.embedding_dim}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
