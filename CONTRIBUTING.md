# 开发者贡献指南

---

## 📖 项目概览

本项目是一个基于 **AgentBench + OpenClaw** 的漏洞自动化评估平台，核心特性包括：

- **ReAct Agent** - Toolformer 风格显式工具循环（Thought → Action → Observation）
- **Q-Learning 红蓝对抗** - 攻击策略自适应，支持 SQLite 持久化
- **RAG 知识库增强** - 漏洞知识向量化检索 + NVD 数据自动同步
- **多模型集成研判** - Turbo / Plus / Max / LongContext 四模型并发对比
- **细粒度权限控制** - JWT + permission_required 装饰器
- **完整安全防护** - CSRF 中间件 / CSP 响应头 / API Key 池健康检查

技术栈：**Python 3.10** + **FastAPI** + **SQLAlchemy** + **Vue3** + **Docker**

---

## 🛠️ 本地开发环境

### 1. 克隆与依赖安装
```bash
# 在仓库根目录执行

# 创建虚拟环境（推荐 miniconda）
conda create -n assessment python=3.10
conda activate assessment

# 安装核心依赖
pip install -r backend/requirements.txt

# 可选：安装 FAISS 向量索引（提升 RAG 性能）
pip install faiss-cpu

# 安装代码风格工具
pip install ruff black mypy bandit pre-commit
pre-commit install
```

### 2. 环境变量配置
在 `backend/` 目录下创建 `.env` 文件：

```dotenv
# ====== DashScope API Key（支持多 Key，逗号分隔）======
DASHSCOPE_API_KEY_POOL=sk-your-key-1,sk-your-key-2,sk-your-key-3

# ====== 数据库配置 ======
# 可选：sqlite（默认）或 postgres
DB_ENGINE=sqlite
DB_SQLITE_PATH=./data/assessment.db

# 若使用 PostgreSQL：
# DB_ENGINE=postgres
# DB_POSTGRES_HOST=localhost
# DB_POSTGRES_PORT=5432
# DB_POSTGRES_USER=assessment
# DB_POSTGRES_PASSWORD=your_pwd
# DB_POSTGRES_DB=assessment
# DB_POOL_SIZE=10
# DB_MAX_OVERFLOW=20

# ====== 教学靶机配置 ======
TARGET_MODE=teaching
TARGET_EXPIRE_SECONDS=1800
TEACHING_ADMIN_TOKEN=assessment-teaching-admin-token-demo-only
FLAG_CS0048=__REQUIRED__
FLAG_CWE78=__REQUIRED__

# ====== 服务端口 ======
PORT=8000
```

### 3. 启动服务

```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

访问：http://127.0.0.1:8000/docs （Swagger UI）

### 4. 运行测试套件

```bash
python tests/test_e2e.py
```

预期输出：`通过 23 / 失败 0 / 跳过 0 / 总计 23`

---

## 📁 项目目录结构

```
./
│
├── backend/                      # FastAPI 后端
│   ├── main.py                   # 应用入口（路由挂载、中间件、启动校验）
│   ├── routes/                   # 7 个领域路由（judge/scan/knowledge/adversarial/tracer/history/admin）
│   ├── services/                 # 共享服务层（Key 池 / ReAct / 多模型对比 / 报告生成）
│   ├── vuln/                     # 靶机漏洞模块
│   ├── prompts/                  # Prompt 版本管理（JSON）
│   ├── tests/                    # 后端单元测试
│   ├── Dockerfile               # 后端镜像
│   ├── Dockerfile.target        # 靶机镜像（非 root 运行）
│   └── requirements.txt
│
├── frontend/                     # Vue 3 + Vite 前端
│   ├── src/                      # 入口、路由、store、API 封装
│   │   └── components/           # 页面与展示组件
│   └── package.json
│
├── agentbench_core/              # AgentBench 适配层（含上游框架副本与基准数据）
├── deploy/                       # 靶机独立部署脚本与配置模板
├── docs/                         # ADR、项目综述；补充材料在 docs/coursework/
├── scripts/                      # 统计与评分卡脚本
├── tests/
│   └── test_e2e.py               # 端到端测试（23 项，纯标准库）
├── docker-compose.yml             # backend / frontend / target 三服务编排
├── pyproject.toml                # ruff/black/mypy/pytest/bandit 配置
├── .pre-commit-config.yaml
├── CHANGELOG.md
└── CONTRIBUTING.md
```

---

## 🔌 API 使用示例

### 1. 获取 JWT Token（开发模式）
```bash
curl -X POST http://127.0.0.1:8000/api/jwt/token
```

### 2. 漏洞扫描
```bash
curl -X POST http://127.0.0.1:8000/api/scan/stream \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"target": "http://127.0.0.1:18789"}'
```

### 3. 多模型并发研判对比
```bash
curl -X POST http://127.0.0.1:8000/api/judge/compare \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "vuln_data": {
      "cve_id": "CWE-78",
      "vuln_name": "命令注入",
      "status": "success",
      "risk_level": "high",
      "execution_log": "; cat /etc/passwd"
    },
    "models": ["qwen-turbo", "qwen-plus", "qwen-max"]
  }'
```

### 4. SSE 流式多模型对比（前端推荐）
```javascript
const eventSource = new EventSource(
  "http://127.0.0.1:8000/api/judge/compare/stream",
  { withCredentials: true }
);
eventSource.onmessage = (e) => {
  const data = JSON.parse(e.data);
  if (data.type === "compare_model_done") {
    console.log(`模型 ${data.result.model} 完成，延迟 ${data.result.latency_ms}ms`);
  } else if (data.type === "compare_complete") {
    console.log(`推荐模型: ${data.recommended_model}`);
    eventSource.close();
  }
};
```

### 5. ReAct Agent 推理查询
```bash
curl -X POST "http://127.0.0.1:8000/api/react/query?user_query=请分析该目标的高危漏洞并给出修复建议" \
  -H "Authorization: Bearer <token>"
```

### 6. API Key 健康检查
```bash
curl -X POST http://127.0.0.1:8000/api/admin/api-keys/health-check \
  -H "Authorization: Bearer <token>"
```

### 7. Prompt A/B 对比测试
```bash
curl -X POST http://127.0.0.1:8000/api/admin/prompts/ab-test \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt_a": "请以安全专家身份分析该漏洞，输出风险级别和修复建议。",
    "prompt_b": "你是一名安全分析师。输出严格的结构化报告。",
    "test_query": "CWE-78 命令注入漏洞",
    "iterations": 3
  }'
```

### 8. 系统健康总览
```bash
curl -X GET http://127.0.0.1:8000/api/admin/health \
  -H "Authorization: Bearer <token>"
```

---

## 🧪 测试规范

### 测试类型
| 类型 | 位置 | 说明 |
|------|------|------|
| 端到端测试 | `tests/test_e2e.py` | 覆盖所有核心模块的集成测试，纯标准库实现，零依赖 |
| 函数测试 | 各模块内 | 单函数级别的行为测试（建议在新增模块时补充） |

### 新增测试的规范
1. **测试函数命名**: `test_<模块>_<场景>[_<条件>]`
2. **位置**: 统一追加到 `tests/test_e2e.py` 末尾
3. **必须包含**:
   - 正向用例（happy path）
   - 负向用例（空数据、超长字符串、无效参数）
   - 边界条件（0 / 1 / max / 超限）
4. **使用 TestResult 类**: 通过 `result.record_pass/record_fail/record_skip` 报告结果
5. **不引入新依赖**: 仅使用 Python 标准库

### 示例（新增一个测试函数）
```python
def test_myfeature_some_scenario(result: TestResult):
    """一句话描述：这个测试的预期行为是什么"""
    try:
        from mymodule import myfunction
        assert_true(myfunction(input) == expected_output, "失败原因描述")
        result.record_pass("MyFeature.SomeScenario")
    except Exception as e:
        result.record_fail("MyFeature.SomeScenario", str(e))
```

---

## 📐 代码风格与类型注解

### 1. Black 格式化（4 空格缩进，最大行宽 100）
```bash
cd backend
black . --line-length 100
ruff check . --fix
```

### 2. Mypy 严格类型检查
`pyproject.toml` 已配置：
```toml
[tool.mypy]
strict = true
disallow_untyped_defs = true
warn_return_any = true
warn_unused_ignores = true
```

运行检查：
```bash
cd backend
mypy . --ignore-missing-imports
```

### 3. 函数类型注解规范
```python
# 好的示例
def analyze_vulnerability(
    target_url: str,
    cve_id: str,
    risk_level: str = "medium",
    timeout: int = 30,
) -> Optional[Dict[str, Any]]:
    """分析单个漏洞的风险情况

    Args:
        target_url: 目标 URL
        cve_id: 漏洞 ID（如 CWE-78）
        risk_level: 默认风险等级
        timeout: 请求超时时间（秒）

    Returns:
        {"status": str, "description": str, "latency_ms": int} 或 None
    """
    pass
```

### 4. Git 提交信息格式
```
<类型>(<模块>): <简要描述>

<详细说明（可选）>

相关 Issue #123
```

**类型标签**:
- `feat` - 新增功能
- `fix` - 修复 Bug
- `refactor` - 代码重构（不改变行为）
- `perf` - 性能优化
- `docs` - 文档更新
- `test` - 测试相关
- `chore` - 构建/CI 配置
- `security` - 安全相关

**示例**:
```
feat(judge): 新增多模型并发对比 API

- 线程池并发调用 Turbo/Plus/Max/LongContext
- SSE 流式推送每个模型的实时结果
- 自动根据延迟与报告长度推荐最佳模型
```

---

## 🔐 安全贡献指南

### 敏感信息处理
- **不要硬编码任何 API Key/Token/Password**
- 使用 `__REQUIRED__` 作为占位符（参考 `services/` 模块 / `target_app.py`）
- 敏感值必须通过环境变量注入
- 日志中出现的敏感值需要 `_mask_*` 函数处理（参考 `database.py` 的 `_mask_db_url`）

### 输入校验
- 所有用户输入都应经过校验：长度、字符集、格式
- SQLAlchemy ORM 已经防 SQL 注入，禁止拼接 SQL 字符串
- HTML/JSON 输出使用框架自带的转义

### 输出净化
- 面向 API 响应的 `dict` 不应包含内部字段
- 错误消息不应泄露系统路径、堆栈追踪到前端（仅开发模式可见）

### 发现安全问题
请通过 **私有 Issue** 或直接联系维护者报告安全问题，**不要**在公开 Issue 中讨论未修复的漏洞。

---

## 🔀 分支与发布流程

### 分支模型
```
main          ← 生产级代码（稳定、可运行、测试全通过）
│
├── feat/react-agent-v2      ← 特性分支（短期，1-2 周合并）
├── fix/api-key-timeout      ← Bug 修复分支
└── docs/update-readme       ← 文档更新
```

### 分支命名规范
```
<类型>/<简短描述>
```

**类型**:
- `feat/` - 新功能
- `fix/` - Bug 修复
- `refactor/` - 重构
- `perf/` - 性能
- `docs/` - 文档
- `chore/` - 杂项

### PR 合并要求
- 至少 1 人 Code Review
- 所有测试（23 项）全部通过
- Ruff/Black 格式化通过
- CHANGELOG.md 新增对应条目

### 版本号规范（SemVer 2.0）
```
MAJOR.MINOR.PATCH
  │     │    └── 仅 Bug 修复（v3.0.1 → v3.0.2）
  │     └────── 兼容的功能新增（v3.0 → v3.1）
  └──────────── 不兼容的破坏性变更（v3 → v4）
```

---

## 📝 常见问题

### Q: 运行时提示 `DASHSCOPE_API_KEY` 未配置？
A: 这是正常的。平台设计为 **无 API Key 也可运行**，此时会自动降级为启发式研判逻辑。要启用完整 AI 功能，可到阿里云 DashScope 控制台申请免费 Key。

### Q: 如何添加新漏洞脚本？
A: 在 `backend/` 目录新增 `exp_<cve_id>.py`，编写 `scan()` 函数返回 `{status, leaked_data}`，然后在 `ALLOWED_SCRIPTS` 中注册。

### Q: 如何增加新的大模型对比项？
A: 在 `services/multimodel.py` 与 `ensemble_judge.py` 的模型清单中新增项，并在对应的 `_call_single_model()` 中处理 API 调用逻辑。

### Q: 数据库如何切换到 PostgreSQL？
A: 设置环境变量 `DB_ENGINE=postgres` 并提供 `DB_POSTGRES_HOST/PORT/USER/PASSWORD/DB` 即可，SQLite 文件中的历史数据可通过脚本迁移。

---

## 📚 参考资源

- **AgentBench Paper**: 评估大型语言模型作为代理的能力
- **OpenClaw**: 教学级漏洞靶场
- **FastAPI 文档**: https://fastapi.tiangolo.com/
- **SQLAlchemy ORM**: https://docs.sqlalchemy.org/
- **DashScope API**: https://help.aliyun.com/zh/model-studio/
- **RFC 7518 (JWT)**: https://www.rfc-editor.org/rfc/rfc7518

---

**感谢您对本项目的贡献！** 🚀

