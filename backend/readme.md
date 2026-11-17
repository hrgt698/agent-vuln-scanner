# 后端服务使用说明

## 当前已完成的全部工作

1. **靶机服务**：Docker 靶机运行在 `127.0.0.1:18789`，包含 4 个高危漏洞靶标
2. **FastAPI 后端**：REST/SSE 接口，覆盖扫描、研判、调度、对抗全流程
3. **通义千问 AI 研判**：CoT 五步推理链（漏洞定位→风险量化→根因追溯→分级修复），自动生成报告
4. **DAG 任务调度**：基于拓扑排序的并发扫描调度器，支持依赖感知执行
5. **Payload Fuzzer**：SQL/RCE/Prompt Injection 变异生成引擎，自动重试
6. **攻击图分析**：多漏洞关联分析 + 复合风险评分
7. **RAG 知识库**：内置 4 类漏洞的历史 CVE 案例库 + 最佳实践 + 代码修复示例
8. **多模型集成研判**：同时调用多个通义千问模型进行一致性投票
9. **AutoPatcher 自动补丁闭环**：AI 生成修复代码 → Docker 热加载 → 重新扫描验证
10. **决策树追踪**：记录 Agent 每步推理轨迹，支持前端时间线可视化
11. **红蓝对抗博弈**：红队自适应攻击策略 vs 蓝队动态防御学习

## 启动步骤

### 1. 启动靶机（必须先开）

```bash
cd deploy
start_target.bat
```

确保靶机在 `127.0.0.1:18789` 运行。

### 2. 配置大模型密钥

在 `backend/` 目录下查看 `.env.example`，新建 `.env` 文件：

```
DASHSCOPE_API_KEY=sk-你的密钥
```

### 3. 安装依赖

```bash
cd backend
pip install -r requirements.txt
```

### 4. 启动后端

```bash
cd backend
python main.py
```

看到以下信息即为成功：
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

## API 接口总览

### 扫描类
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/scan/stream` | POST | 流式扫描（SSE 实时推送 + DAG 调度 + Fuzzer 增强） |
| `/api/scan/all` | POST | 批量一键扫描（含攻击图分析） |

### 模型管理
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/models` | GET | 获取可用模型列表 |
| `/api/switch-model` | POST | 切换大模型 |
| `/api/judge/ensemble` | POST | 多模型集成研判 |
| `/api/judge/ensemble/models` | GET | 可用研判模型列表 |

### 知识库 / 攻击图
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/kb/{cve_id}` | GET | 查询 CVE 知识库 |
| `/api/kb/summary/{cve_id}` | GET | 知识库摘要 |
| `/api/attack-graph/analyze` | POST | 攻击图关联分析 |

### 调度信息
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/scheduler/order` | GET | DAG 拓扑排序 |
| `/api/scheduler/stats` | GET | 调度历史统计 |

### 决策树追踪
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/tracer/start` | POST | 开始追踪 |
| `/api/tracer/record` | POST | 记录一步决策 |
| `/api/tracer/tree` | GET | 获取完整决策树 |

### 自动补丁闭环
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/auto-patch/generate` | POST | 生成补丁 |
| `/api/auto-patch/apply` | POST | 应用补丁到靶机 |
| `/api/auto-patch/restart` | POST | 重启靶机 |
| `/api/auto-patch/verify` | POST | 验证补丁 |
| `/api/auto-patch/full-cycle` | POST | 一键闭环 |
| `/api/auto-patch/history` | GET | 补丁历史 |

### 红蓝对抗
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/adversarial/start` | POST | 初始化对抗 |
| `/api/adversarial/run` | POST | 执行推演 |
| `/api/adversarial/scoreboard` | GET | 实时计分板 |
| `/api/adversarial/status` | GET | 推演状态 |

### 系统
| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/status` | GET | 系统状态 |
| `/docs` | GET | Swagger 自动文档 |

## 后端文件结构

```
backend/
├── main.py                    # 后端主程序（REST/SSE 接口、中间件、启动校验）
├── security.py                # JWT 认证、CSRF、CSP 响应头、限流
├── database.py                 # SQLite / PostgreSQL 抽象层
├── config_loader.py            # 配置加载与默认值
├── fuzzer.py                   # Payload 变异生成引擎
├── scheduler.py               # DAG 调度器 + 自适应调度
├── attack_graph.py            # 攻击图关联分析器
├── rag_engine.py / rag_advice.py   # RAG 向量检索与知识库增强
├── ensemble_judge.py           # 多模型集成研判
├── react_agent.py             # ReAct Agent 工具循环
├── adversarial_mode.py         # 红蓝对抗模式
├── auto_patcher.py / auto_patch_generator.py  # 自动补丁闭环
├── agent_tracer.py             # Agent 决策树追踪器
├── rule_based_waf.py           # WAF 规则引擎（22 条规则）
├── target_app.py               # 教学靶机应用
├── exp_cs0048.py               # 漏洞脚本：API 未授权访问
├── exp_cwe78.py                # 漏洞脚本：命令注入
├── exp_sql_injection.py        # 漏洞脚本：SQL 注入
├── exp_prompt_injection.py     # 漏洞脚本：提示词注入
├── routes/                    # 7 个领域路由模块
├── services/                   # 共享服务层（Key 池 / ReAct / 多模型 / 演示模式）
├── vuln/                       # 靶机漏洞模块化定义
├── prompts/                   # Prompt 版本管理（JSON）
├── tests/                     # 后端单元测试（8 个文件，76 个用例）
├── config.yaml / .env.example  # 配置模板
├── Dockerfile / Dockerfile.target
└── requirements.txt
```

## 版本历史

- **v2.4.1**（2026-06-18）：修正数据库 `:memory:` 生命周期；JWT 支持 PyJWT / python-jose 双兼容并在无依赖时降级为 HMAC 签名；`services.py` 拆分模块级依赖初始化；新增 `/api/models`, `/api/switch-model`, `/api/jwt/token`, `/api/knowledge/query`, `/api/judge/evaluate` 路由；前端 `api.js` 注入 JWT Authorization 并在后端不可达时优雅降级；新增可复现评分卡 `scorecard.py`。
- **v2.4.0**：新增 22 条规则引擎 `rule_based_waf.py`（含混淆编码检测：内联注释/十六进制）；红蓝对抗 `AdversarialEvaluator` 回合制；`scoreboard/status` 接口；JWT 动态 Token。
- **v2.3.0**：DAG 任务调度器 + Payload Fuzzer + 攻击图 CVSS 分析；`EnsembleJudger` 三模型投票；CoT 系统提示；FAISS RAG（可选依赖）。
- **v2.2.0**：核心 FastAPI 框架（37 条路由）+ SQLite 持久化（scan/patch/adversarial/model_eval 四张表）。
- **v2.0 / v2.1**：初始原型，`target_app.py` 教学靶机（CWE-89 / CWE-78 / Prompt Injection）。

## 常见问题

1. **端口被占用** → 关闭旧终端重新启动
2. **大模型报告不显示** → 检查 `.env` 密钥是否正确
3. **靶机连接失败** → 确认 `start_target.bat` 已运行
4. **测试失败** → 在 `backend/` 目录执行 `python -m pytest tests/ -v`
