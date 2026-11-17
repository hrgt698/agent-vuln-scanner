# 变更日志

---

## v3.3 (2026-06-18)

### 🌟 新功能速览

| 模块 | 功能说明 | 关键文件 |
|------|----------|----------|
| 🤖 ReAct Agent | 工具链智能回退：工具 A 失败 → 自动切换工具 B → 启发式兜底 | `backend/react_agent.py` |
| 📊 多模型对比 | 纯 JS Diff 实现差异高亮，模型结果并排对比 | `frontend/src/components/` |
| 📝 AI 报告 | 元数据水印（模型名 + 置信度 + 时间戳），可追溯可审计 | `backend/services.py` |
| 🎯 靶机日志 | 请求来源 IP / path 独立记录，便于审计回溯 | `backend/target_app.py` |
| 🎭 Demo 模式 | 报告 HTML 化，关键词红色高亮，便于教学展示 | `backend/services.py` |
| 🏗️ 代码结构 | 靶机漏洞模块化重构：`vuln/` 目录独立文件，便于扩展 | `backend/target_app.py` · `backend/vuln/` |
| 📱 UI 适配 | 全局响应式 CSS，移动端友好 | `frontend/src/App.vue` · `frontend/src/styles/` |
| 📖 前端文档 | 组件统一文档注释 + 中文文案规范 | `frontend/src/components/` |
| 🔄 CI/CD | OWASP ZAP Baseline DAST + 前端 ESLint 检查 | `.github/workflows/ci-cd.yml` |

### 🔧 详细变更

#### 1. ReAct Agent 工具链智能回退
- 当主工具（如 `scan_vulnerability`）失败时，自动尝试备选工具
- 二级备选失败后降级到启发式模式，保证至少有输出
- `reasoning_trace` 记录完整回退路径，前端可可视化展示

#### 2. 多模型差异高亮（纯 JS Diff）
- 前端自实现文本 diff 算法，无需引入外部依赖
- 对比 Turbo/Plus/Max/LongContext 四模型结果，差异字符高亮
- 支持点击切换「仅差异」与「全文」视图

#### 3. AI 报告元数据水印
- 每份报告内嵌元数据块：`model_name / confidence / timestamp`
- 可用于追溯哪次调用、哪个模型、何种置信度
- Demo 模式报告：HTML 格式 + 关键词红色高亮

#### 4. 靶机请求来源日志
- `target_security.log` 新增 `source_ip / path / method` 字段
- 便于在教学场景中分析「谁访问了哪个漏洞端点」

#### 5. 靶机漏洞模块化重构
- 原有单体 `target_app.py` 拆分为 `vuln/` 目录下独立文件
- 新增漏洞仅需在 `vuln/` 中新增文件并注册路由，无需修改主文件
- 更易维护、更易扩展

#### 6. 全局响应式 CSS
- 统一媒体查询断点：`768px / 1024px`
- 移动端：卡片堆叠、字号自适应、横向滚动容器
- 桌面端：网格布局、多列并排

#### 7. 前端组件统一文档注释 + 中文文案
- 所有 Vue 组件顶部增加 JSDoc 风格文档注释
- Props / Events / Slots 中文说明
- UI 文本统一中文，避免中英文混排不一致

#### 8. CI/CD 增强
- 新增 OWASP ZAP Baseline 动态扫描（占位步骤，需要运行中的靶机）
- 新增前端 ESLint 检查（`npm run lint`，`continue-on-error: true`）
- 两个 job 均设置 `continue-on-error: true`，避免阻塞主流水线

---

## v3.1 (2026-06-18)

### 🌟 新功能

#### 1. 多模型并发对比 & 推荐系统 (`backend/services.py`)
- 新增 `judge_multimodel_compare()` - 线程池并发调用 Turbo/Plus/Max/LongContext 四模型研判同一漏洞
- 新增 `sse_stream_multimodel()` - SSE 流式推送每个模型的结果，前端可实时渲染对比
- 新增 `_call_single_model()` - 单模型报告生成工具，内置超时控制
- 智能推荐：综合延迟 + 报告长度，自动给出 `recommended_model`

#### 2. 多模型对比 API 端点 (`backend/routes/judge.py`)
- `POST /api/judge/compare` - 漏洞数据并发对比，返回 `total_models/successful/fastest_model/slowest_model/avg_latency_ms/models_compared/recommended_model`
- `POST /api/judge/compare/stream` - SSE 流式对比事件流（`compare_start` → `compare_model_done` → `compare_complete`）
- `GET /api/models/compare` - 获取可用于对比的模型清单

#### 3. 教学模式漏洞生命周期管理 (`backend/target_app.py`)
- `_start_expiry_timer()` - 后台守护线程实现教学会话自动过期（默认 1800 秒，可通过 `TARGET_EXPIRE_SECONDS` 配置）
- `_teaching_session_expired` 全局标志 + 中间件拦截，过期后所有漏洞端点返回 HTTP 410 Gone
- `GET /api/v1/health/status` - 教学靶机状态端点，返回 mode/started_at/expires_at/seconds_remaining/vulnerabilities_enabled
- `POST /api/v1/admin/terminate-session` - 带 Bearer Token 的管理员会话强制终止（Token 来自 `TEACHING_ADMIN_TOKEN` 环境变量）
- `_log_security_event()` - 安全事件独立日志，写入 `./data/target_security.log`（JSON 行格式），记录 startup/vuln_access/expired/terminated 事件

#### 4. API Key 健康检查异步化 + 后台线程缓存 (`backend/services.py`)
- `_health_check_worker()` - 守护线程每 300 秒自动检查池内所有 Key 的健康状态
- `_per_key_health_cache` - 每个 Key 的 `status/latency_ms/http_code/checked_at` 缓存
- `health_check_all_keys()` - 优先读缓存，60 秒内有结果直接返回，否则发起真实检查
- `get_api_key_pool_status()` - 增强字段：`last_check_seconds_ago/thread_running/healthy_key_count/unhealthy_key_count`

#### 5. 数据库抽象层增强 (`backend/database.py`)
- `DATABASE_CONFIG` - 集中式配置字典，支持 `DB_ENGINE/DB_SQLITE_PATH/DB_POSTGRES_*` 环境变量
- `build_db_url()` - 根据引擎自动构造连接 URL，PostgreSQL 密码为 `__REQUIRED__` 时自动降级到 SQLite 并打印警告
- `_mask_db_url()` - 日志脱敏：隐藏连接 URL 中的密码
- `SQLAlchemyDB.ping()` - 数据库连接健康探测（执行 `SELECT 1`），返回 `{available, latency_ms, engine, error}`
- `SQLAlchemyDB.get_pool_stats()` - 连接池统计：`engine_type/pool_size/max_overflow/checked_in/checked_out/overflow_count`

### 🔧 功能增强

#### 6. 全面类型注解
- `services.py` 所有公共函数增加完整参数和返回值类型提示
- `judge.py` 路由函数增加响应结构的类型注释

#### 7. Prompt 版本管理 + A/B 测试 (`backend/routes/admin.py`)
- `GET /api/admin/prompts` - 列出所有已保存 Prompt 及其版本/更新时间
- `POST /api/admin/prompts` - 新建或更新 Prompt（同名保存自动 +1 版本号）
- `GET /api/admin/prompts/{name}` - 获取单个 Prompt 的完整内容
- `DELETE /api/admin/prompts/{name}` - 删除指定 Prompt
- `POST /api/admin/prompts/ab-test` - 两个 Prompt 的对比测试，返回各自的响应长度和平均延迟，并自动推荐更优版本
- Prompt 文件存储于 `backend/prompts/` 目录，JSON 格式
- 内置默认 Prompt：`default-vulnerability-analysis.json`、`concise-vulnerability-report.json`

### ✅ 测试覆盖

#### 8. 17 项端到端测试 (`tests/test_e2e.py`)
- **安全模块 (3)**: JWT 生成/验证闭环、错误密钥拒绝、匿名用户权限
- **对抗性学习 (2)**: Q-Learning 策略选择与更新、SQLite 持久化保存与加载
- **Prompt 管理 (1)**: CRUD 完整流程、版本号递增
- **RAG 检索评估 (1)**: Hit Rate@k / NDCG / MRR 三维指标
- **API Key 管理 (2)**: Key 池轮转、健康状态摘要
- **多模型对比 (2)**: 结果结构完整性、SSE 事件流格式
- **扫描报告 (1)**: 离线报告生成与降级
- **ReAct Agent (1)**: 初始化/调用/返回结构
- **数据库抽象层 (1)**: build_db_url / ping / pool_stats
- **负例与边界 (3)**: 空数据不崩溃、超长字符串截断、无效模型名过滤

**测试结果：17/17 全部通过 ✅**

---

## v3.0 (2026-06-18)

### 🌟 新功能

1. **ReAct Agent (`backend/react_agent.py`)**
   - Toolformer 风格的显式工具循环：Thought → Action → Observation → 循环
   - 5 个内置工具：`scan_vulnerability` / `rag_query` / `judge_analyze` / `patch_generate` / `adversarial_check`
   - 完整推理轨迹（reasoning_trace）返回，便于前端可视化
   - 无 LLM 访问时自动降级为启发式模式

2. **JWT 细粒度权限系统 (`backend/security.py`)**
   - `permission_required("react:use")` 装饰器，配合 JWT payload 中的 `permissions` 字段
   - `require_authenticated_user` 依赖：匿名用户自动拒绝
   - CSRF Protection 中间件 + Content Security Policy 响应头

3. **Prompt 版本管理 (`backend/routes/admin.py`)**
   - CRUD 端点：`GET/POST/DELETE /api/admin/prompts[/name]`
   - A/B 测试端点：`POST /api/admin/prompts/ab-test`
   - 自动版本号递增

4. **RAG 检索质量评估 (`backend/rag_engine.py`)**
   - `--benchmark` CLI 参数
   - Hit Rate @ k / MRR / NDCG 三维指标
   - k = 1, 3, 5 自动对比

5. **Q-Learning 策略持久化 (`backend/adversarial_mode.py`)**
   - `save(path)` / `load(path)` SQLite 持久化
   - `get_stats_summary()` 策略统计摘要

### 🔧 安全增强

- `__REQUIRED__` 占位符方案：敏感默认值全部移除
- 启动校验 `_validate_secrets_on_startup()`
- `TARGET_EXPIRE_SECONDS` 教学会话自动过期
- API Key 池 + 健康检查 + 动态轮换

---

## v2.4 (2026-06-18)

### 主要变更
- 新增 SSE 流式研判 `POST /api/judge/stream`
- 完善 Ensemble Judger 的 multi-agent 模式
- 前端 ThinkingLog 组件集成流式显示
- 新增 Prompt 工程（CoT System Prompt + Few-shot Examples）

---

## v2.2 (2026-06-18)

### 主要变更
- 引入 AgentBench 评估基准
- 红蓝对抗博弈系统 `adversarial_mode.py`
- 决策追踪器 `DecisionTreeTracer`
- 扫描调度器 `AdaptiveScheduler`

---

## v1.0 (2026-06-18)

### 初始版本
- 基础漏洞扫描 `scan_vulnerability_sync`
- 简易报告生成 `generate_report`
- Vue3 前端（扫描控制 + 报告展示）
- FastAPI + uvicorn 服务框架

