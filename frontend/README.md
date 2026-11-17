# 前端 — Vue 3 + Vite 安全评估大屏

基于 Vue 3 + Vite 构建的大屏可视化安全评估平台。

## 功能列表

### 基础功能
- 一键漏洞扫描：支持 CS0048 / CWE-78 / CWE-89 / AML.T0051 四大漏洞靶标
- 通义千问 AI 研判：CoT 五步推理链自动生成漏洞概述、风险分析、修复建议报告
- 四档模型切换：turbo / plus / max / max-longcontext 动态切换
- SSE 流式日志展示：实时推送扫描进度与靶机交互日志
- ECharts 雷达图：漏洞风险多维度可视化
- 历史记录：追溯过往扫描结果
- Markdown 报告导出：一键导出专业安全评估报告

### 算法增强功能（v2.0+）
- **决策树可视化**：Agent 决策轨迹时间线展示（每步推理、工具调用、奖励信号）
- **红蓝对抗面板**：红队 vs 蓝队计分板 + 回合记录 + 实时攻击事件流
- **自动补丁展示**：一键修复循环的状态反馈（生成→应用→验证）

## 技术栈

- **框架**: Vue 3 (Composition API)
- **构建工具**: Vite
- **状态管理**: Pinia
- **图表**: ECharts（雷达图内置在 ScanPage 中）
- **Markdown 渲染**: DOMPurify（XSS 防护）
- **通信**: SSE (Server-Sent Events)

## 项目启动

```sh
npm install
npm run dev
```

前端默认运行在 `http://localhost:5173`。

## 完整部署

请运行项目根目录的 `start_all.bat` 一键启动全栈服务：

1. 靶机服务（docker-compose）：端口 18789
2. 后端服务（FastAPI + Uvicorn）：端口 8000
3. 前端服务（Vite）：端口 5173

## 项目结构

```
frontend/
├── src/
│   ├── main.js                # 应用入口
│   ├── App.vue                # 根组件（tab 切换）
│   ├── components/            # 页面与展示组件
│   ├── stores/                # Pinia 状态管理
│   ├── utils/                 # API 封装
│   ├── router/                # 路由配置
│   └── styles/                # 全局样式
├── public/                    # 静态资源
└── package.json
```
