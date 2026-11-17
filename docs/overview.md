# 项目综述

## 项目核心定位

本项目以 **AI 安全评估** 为核心场景，将 **AgentBench**（学术界多任务智能体评估框架）与 **OpenClaw**（健壮性测试框架）进行实质性融合改造，构建了一个覆盖 **漏洞扫描 → AI研判 → 决策追踪 → 自动修复 → 红蓝对抗** 全链路的自主决策型漏洞评估平台。

## 项目背景

随着 AI 智能体（AI Agent）在各行各业的广泛应用，其安全脆弱性问题日益突出。大型语言模型（LLM）驱动的智能体在执行任务时可能面临 API 未授权访问、命令注入、SQL 注入和提示词注入等安全威胁。本项目旨在构建一个自动化评估平台，对 AI 智能体的高危脆弱性进行系统性检测与分析。

## 技术方案与创新点

1. **AgentBench 框架改造**：将原有的学术跑分框架改造为实战化漏洞扫描引擎（POST → GET、Token 鉴权 → 无认证、外网 API → 本地回环）
2. **4 类高危漏洞覆盖**：CS0048、CWE-89、CWE-78、AML.T0051
3. **Docker 靶机沙箱**：隔离可控的漏洞仿真环境（FastAPI + SQLite）
4. **DAG 任务调度**：基于拓扑排序的并发扫描调度器
5. **Payload Fuzzer**：SQL/RCE/Prompt Injection 变异生成引擎
6. **攻击图关联分析**：多漏洞链复合风险评分
7. **RAG 知识库增强**：内置历史 CVE 案例 + 最佳实践 + 代码修复示例
8. **多模型集成研判**：同时调用 4 档通义千问模型进行一致性投票
9. **CoT Chain-of-Thought 推理**：五步推理链生成专业安全报告
10. **AutoPatcher 自动补丁闭环**：生成修复代码 → Docker 热加载 → 重新验证
11. **Agent 决策树追踪**：记录每步推理轨迹，支持前端交互式可视化
12. **红蓝对抗博弈模式**：红队自适应攻击 vs 蓝队动态防御学习
13. **大屏可视化**：雷达图、决策时间线、实时日志、计分板
14. **CI/CD 与自动化测试**：51 个单元测试 + 四阶段流水线

## 架构图

```
                 ┌──────────────────────────────────────┐
                 │          前端大屏 (Vue 3)              │
                 │  ScanPage  │  DecisionTree            │
                 │  雷达图     │  AdversarialPanel        │
                 │  AIReport  │  ScoreBoard              │
                 └──────────────┬───────────────────────┘
                                │ SSE / REST
        ┌───────────────────────▼───────────────────────┐
        │          FastAPI 后端 (26 个接口)              │
        │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌────┐  │
        │  │DAG   │ │Fuzzer│ │RAG   │ │决策树│ │对抗│  │
        │  │调度器 │ │变异器│ │知识库│ │追踪器│ │博弈│  │
        │  └──────┘ └──────┘ └──────┘ └──────┘ └────┘  │
        │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐     │
        │  │攻击图│ │集成  │ │补丁  │ │通义千问   │     │
        │  │分析  │ │研判  │ │闭环  │ │API调用    │     │
        │  └──────┘ └──────┘ └──────┘ └──────────┘     │
        └───────────────────────┬───────────────────────┘
                                │ HTTP GET
        ┌───────────────────────▼───────────────────────┐
        │         Docker 漏洞靶机 (FastAPI)              │
        │  /api/v1/config (CS0048)                      │
        │  /api/v1/user (CWE-89)                        │
        │  /api/v1/ping (CWE-78)                        │
        │  /api/v1/agent/chat (AML.T0051)               │
        └───────────────────────────────────────────────┘
```

## 核心模块

### 后端模块 (backend/)
| 文件 | 功能 | 技术亮点 |
|------|------|---------|
| `main.py` | 后端主程序 26 个 API | FastAPI + SSE + Uvicorn |
| `fuzzer.py` | Payload 变异引擎 | SQL/RCE/Prompt 自动变异，URL编码变体 |
| `scheduler.py` | DAG 调度器 | 拓扑排序 + 自适应超时/重试 |
| `attack_graph.py` | 攻击图分析器 | 多漏洞链复合 CVSS 评分 |
| `rag_advice.py` | RAG 知识库引擎 | 历史 CVE 案例 + 最佳实践 + 修复代码 |
| `ensemble_judge.py` | 多模型集成研判 | 并行调用多模型，一致性投票 |
| `agent_tracer.py` | 决策树追踪器 | 每步推理记录 + 时间线格式化 |
| `auto_patcher.py` | 自动补丁闭环 | Docker 热加载 + 验证回滚 |
| `adversarial_mode.py` | 红蓝对抗模式 | 自适应策略 + 动态防御学习 |

### 前端组件 (frontend/src/components/)
| 组件 | 功能 |
|------|------|
| `ScanPage.vue` | 扫描主页面（含 ECharts 雷达图） |
| `AIReport.vue` | AI 研判报告（DOMPurify XSS 防护） |
| `DecisionTree.vue` | Agent 决策轨迹时间线可视化 |
| `AdversarialPanel.vue` | 红蓝对抗控制面板 |
| `ScoreBoard.vue` | 对抗计分板（VS 比分 + 回合记录） |
| `ThinkingLog.vue` | 思考过程动画 |
| `HistoryList.vue` | 历史记录 |
| `ControlPanel.vue` | 模型/靶机控制面板 |

## 安全设计

- CORS 白名单严格限制 `localhost:5173` 和 `127.0.0.1:5173`
- DOMPurify 前端 XSS 净化
- 漏洞脚本白名单校验
- 用户输入 HTML escape 转义（防 Prompt 二次注入）
- 靶机容器非 root 运行
- 端口仅绑定本地回环 `127.0.0.1`
- 故意保留的教学漏洞已明确标注与风险提示

## 测试覆盖

76 个单元测试覆盖全部核心模块：
- `test_fuzzer.py` — 8 个测试（变异生成、CVE 映射、URL 构造、编码变体）
- `test_scheduler.py` — 10 个测试（拓扑排序、优先级、环形依赖、自适应统计）
- `test_attack_graph.py` — 8 个测试（节点管理、风险评分、攻击链描述）
- `test_agent_tracer.py` — 9 个测试（决策记录、路径回溯、时间线格式化）
- `test_rag_advice.py` — 7 个测试（知识库查询、报告增强、摘要格式）
- `test_adversarial.py` — 9 个测试（红队策略、蓝队检测、回合判定）
- `test_database.py` — 9 个测试（扫描/补丁/对抗记录读写、历史统计、单例）
- `test_security_config.py` — 16 个测试（限流、路径净化、敏感信息哈希、配置读取与单例）

## 使用方式

```bash
# 1. 启动靶机
cd deploy && start_target.bat

# 2. 配置 AI 密钥
cd backend && cp .env.example .env  # 填入 DASHSCOPE_API_KEY

# 3. 启动后端
cd backend && pip install -r requirements.txt && python main.py

# 4. 启动前端（新终端）
cd frontend && npm install && npm run dev

# 5. 运行测试
cd backend && python -m pytest tests/ -v
```

## CI/CD 流水线

```
lint (ruff + black) → test (pytest 76 用例 + 覆盖率) → security-scan (bandit + safety) → docker build
```

## 致谢

- AgentBench 开源框架（原始基准框架提供者）
- OpenClaw 健壮性测试框架（原始框架提供者）
- 通义千问 DashScope API（AI 研判能力支持）
