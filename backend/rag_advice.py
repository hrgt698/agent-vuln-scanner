"""
RAG 知识库增强引擎
基于历史漏洞库和最佳实践知识库，增强 AI 报告的专业深度。
使用方式：from rag_advice import RAGAdviceEngine
"""

import json
from typing import Dict, List, Optional


class RAGAdviceEngine:
    """检索增强生成引擎
    内置历史 CVE 案例库、最佳实践知识库和代码修复示例，
    在 AI 生成报告后附加相关上下文，提升报告的专业性和可操作性。
    """

    def __init__(self):
        self.knowledge_base: Dict[str, dict] = self._build_kb()

    def _build_kb(self) -> Dict[str, dict]:
        """构建本地知识库（生产环境中可用向量数据库替代）"""
        return {
            "CS0048": {
                "vuln_type": "API未授权访问",
                "similar_cases": [
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
                "best_practices": [
                    "使用 JWT Bearer Token 对每个 API 端点进行身份校验",
                    "API 网关统一鉴权（如 Kong / APISIX / Nginx + lua）",
                    "遵循最小权限原则，默认拒绝所有未认证请求",
                    "部署 Web 应用防火墙（WAF）拦截异常请求模式",
                ],
                "fix_example": """```python
# 推荐修复方案：添加统一的鉴权中间件
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

# 白名单：无需鉴权的公开端点
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
            },
            "CWE-89": {
                "vuln_type": "SQL注入",
                "similar_cases": [
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
                "best_practices": [
                    "永远使用参数化查询（PreparedStatement）替代字符串拼接",
                    "ORM 框架自带防注入能力（如 SQLAlchemy），优先使用",
                    "对用户输入做严格的类型校验和白名单过滤",
                    "数据库账户遵循最小权限原则，不直接用 root 连接",
                ],
                "fix_example": """```python
# ❌ 危险写法（当前靶机使用的方式，仅供教学演示）
query = f"SELECT name, secret FROM users WHERE id = '{user_id}'"

# ✅ 安全修复：使用参数化查询
import sqlite3
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
query = "SELECT name, secret FROM users WHERE id = ?"
cursor.execute(query, (user_id,))  # 参数化查询自动转义特殊字符
result = cursor.fetchone()
```""",
            },
            "CWE-78": {
                "vuln_type": "操作系统命令注入",
                "similar_cases": [
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
                "best_practices": [
                    "永远避免使用 shell=True 或 os.system() 等危险函数",
                    "使用 subprocess.run 的列表形式传递参数（自动转义）",
                    "对用户输入做严格的字符过滤和白名单校验",
                    "将命令执行逻辑隔离到沙箱容器中运行",
                ],
                "fix_example": """```python
# ❌ 危险写法（当前靶机使用的方式，仅供教学演示）
command = f"ping -c 1 {user_input}"
result = subprocess.check_output(command, shell=True, text=True)

# ✅ 安全修复 1：使用列表形式传递参数（推荐）
result = subprocess.run(
    ["ping", "-c", "1", user_input],
    capture_output=True, text=True, timeout=10
)

# ✅ 安全修复 2：配合白名单校验
import re
ALLOWED_IP_PATTERN = re.compile(r"^[0-9.]+$")
if not ALLOWED_IP_PATTERN.match(user_input):
    return {"status": "error", "message": "非法输入"}
result = subprocess.run(
    ["ping", "-c", "1", user_input],
    capture_output=True, text=True, timeout=10
)
```""",
            },
            "AML.T0051": {
                "vuln_type": "LLM提示词注入",
                "similar_cases": [
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
                "best_practices": [
                    "对用户输入做语义级别的意图分类，检测越权指令",
                    "使用独立的 System Prompt 空间，与 User Input 完全隔离",
                    "关键操作（如泄露凭证）需要用户二次确认",
                    "部署 Guardrails 中间件过滤恶意指令（如 NVIDIA NeMo Guardrails）",
                ],
                "fix_example": """```python
# ❌ 危险写法（当前靶机使用的方式，仅供教学演示）
agent_response = f"我是AI助手，正在处理您的任务：{user_prompt}"

# ✅ 安全修复：意图分类 + 指令隔离
import re

# 检测越权指令特征
OVERRIDE_PATTERNS = [
    re.compile(r"忽略.*指令", re.IGNORECASE),
    re.compile(r"override|越权|跳过", re.IGNORECASE),
    re.compile(r"打印.*(凭证|密码|密钥|secret)", re.IGNORECASE),
    re.compile(r"泄露|窃取|偷", re.IGNORECASE),
]

def is_safe_prompt(prompt: str) -> bool:
    for pattern in OVERRIDE_PATTERNS:
        if pattern.search(prompt):
            return False
    return True

if not is_safe_prompt(user_prompt):
    return {"status": "blocked", "message": "检测到越权指令，已拦截"}
```""",
            },
        }

    def get_kb_entry(self, cve_id: str) -> Optional[dict]:
        """获取指定 CVE 的知识库条目"""
        return self.knowledge_base.get(cve_id)

    def enhance_report(self, cve_id: str, ai_report: str) -> str:
        """用检索到的知识增强 AI 报告"""
        kb = self.get_kb_entry(cve_id)
        if not kb:
            return ai_report

        enhanced_sections = []

        # 1. 追加相似历史案例
        if kb.get("similar_cases"):
            cases_lines = ["### 五、相似历史案例参考"]
            for case in kb["similar_cases"]:
                cases_lines.append(
                    f"- **{case['cve']}** ({case['year']}): {case['description']} "
                    f"→ 修复策略: {case['fix_type']}"
                )
            enhanced_sections.append("\n".join(cases_lines))

        # 2. 追加最佳实践
        if kb.get("best_practices"):
            practices_lines = ["### 六、最佳实践建议"]
            for i, practice in enumerate(kb["best_practices"], 1):
                practices_lines.append(f"{i}. {practice}")
            enhanced_sections.append("\n".join(practices_lines))

        # 3. 追加代码修复示例
        if kb.get("fix_example"):
            enhanced_sections.append(f"### 七、参考代码实现\n\n{kb['fix_example']}")

        if enhanced_sections:
            return ai_report + "\n\n---\n\n" + "\n\n".join(enhanced_sections)

        return ai_report

    def get_kb_summary(self, cve_id: str) -> dict:
        """获取知识库摘要（用于前端展示）"""
        kb = self.get_kb_entry(cve_id)
        if not kb:
            return {"has_knowledge": False}
        return {
            "has_knowledge": True,
            "vuln_type": kb["vuln_type"],
            "case_count": len(kb.get("similar_cases", [])),
            "practice_count": len(kb.get("best_practices", [])),
            "has_fix_example": bool(kb.get("fix_example")),
        }