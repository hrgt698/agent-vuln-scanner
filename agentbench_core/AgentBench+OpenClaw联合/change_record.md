项目阶段：Phase1 靶机引擎适配收尾
修改时间：2026-05-22
提交人：zwy

1. src/client/agents/http_agent.py
- 将原有POST请求改为GET请求
- 移除请求体参数，适配当前无鉴权接口
- 保留重试、SSL忽略、异常捕获原有容错逻辑

2. src/client/agents/__init__.py
- 注释缺少依赖的fastchat客户端模块
- 仅保留业务可用的HTTPAgent代理类

3. 新增 agentbench_engine_wrapper.py
- 封装批量漏洞扫描引擎类
- 实现测试用例加载、单条执行、漏洞判定、数据统计
- 可识别接口鉴权失效安全漏洞

测试验收结果：
框架正常连通靶机 172.19.0.2:18789/api/v1/config
全部用例执行成功，漏洞研判功能正常，Phase1基础开发完成

---

项目阶段：Phase2 完整平台前端对接与算法增强
修改时间：2026-06-17
提交人：yyf / xcw / djy

一、后端新增模块
1. fuzzer.py - Payload 变异生成引擎（SQL/RCE/Prompt Injection/API Bypass 自动变异）
2. scheduler.py - DAG 任务调度器（拓扑排序 + 自适应超时/重试）
3. attack_graph.py - 攻击图关联分析器（多漏洞链复合风险评分）
4. rag_advice.py - RAG 知识库增强引擎（4 类漏洞历史 CVE 案例 + 最佳实践 + 修复代码）
5. ensemble_judge.py - 多模型集成研判（同时调用多个通义千问模型一致性投票）
6. agent_tracer.py - Agent 决策树追踪器（记录每步推理轨迹，支持前端可视化）
7. auto_patcher.py - 自动补丁闭环引擎（生成修复代码 → Docker 热加载 → 重新验证）
8. adversarial_mode.py - 红蓝对抗博弈模式（红队自适应攻击 vs 蓝队动态防御学习）
9. exp_prompt_injection.py - 新增第4类漏洞脚本（AML.T0051 提示词注入）

二、前端新增组件
1. DecisionTree.vue - Agent 决策轨迹时间线可视化
2. ScoreBoard.vue - 红蓝对抗计分板（VS 比分 + 回合记录）
3. AdversarialPanel.vue - 对抗模式控制面板（配置推演 + 实时事件流 + 博弈总结）

三、工程化增强
1. .gitlab-ci.yml - CI/CD 四阶段流水线（lint → test → sec-scan → build）
2. tests/ - 51 个单元测试用例，覆盖全部新增模块
3. .env.example - 密钥配置文件模板
4. main.py 升级至 v2.0（26 个 API 接口），DAG 调度 + Fuzzer + CoT Prompt
5. 后端监听地址改为 127.0.0.1（安全加固）

四、部署支持
1. 新增 Windows bat 一键部署脚本（start_target.bat / stop_target.bat）
2. 支持 Windows + Docker 与 Linux (Ubuntu) 双平台部署

Phase2 验证结果：
- 51/51 单元测试全部通过
- main.py 语法检查通过
- 后端 26 个 API 接口正常注册
- 前端 11 个组件正常加载
- 完整功能闭环：扫描 → 研判 → 补丁 → 验证
