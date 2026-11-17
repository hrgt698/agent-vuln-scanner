<!--
@file App.vue
@description 应用主入口，负责页面路由与全局样式
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="dashboard">
    <Header />
    <NavBar v-model:activeTab="activeTab" />

    <IntroPage v-if="activeTab === 'intro'" />
    <ScanPage v-else-if="activeTab === 'scan'" />
    <DemoPage v-else-if="activeTab === 'demo'" />
    <ModelComparePage v-else-if="activeTab === 'compare'" />
  </div>
</template>

<script setup>
import { ref } from 'vue'
import Header from './components/Header.vue'
import NavBar from './components/NavBar.vue'
import IntroPage from './components/IntroPage.vue'
import ScanPage from './components/ScanPage.vue'
import DemoPage from './components/DemoPage.vue'
import ModelComparePage from './components/ModelComparePage.vue'

const activeTab = ref('intro')
</script>

<style>
/* ===== 全局基础样式 ===== */
html, body, #app {
  margin: 0;
  padding: 0;
  min-height: 100vh;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC',
    'Hiragino Sans GB', 'Microsoft YaHei', Arial, sans-serif;
  color: #303133;
  background: #f0f2f5;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* ===== dashboard 容器 ===== */
.dashboard {
  padding: 20px;
  max-width: 1400px;
  margin: 0 auto;
  box-sizing: border-box;
}

/* ===== 全局字体自适应（使用 clamp 更现代化） ===== */
body {
  font-size: 14px;
  line-height: 1.6;
}

h1 { font-size: clamp(20px, 2.5vw, 28px); }
h2 { font-size: clamp(18px, 2.2vw, 24px); }
h3 { font-size: clamp(16px, 2vw, 20px); }
h4 { font-size: clamp(14px, 1.8vw, 16px); }

/* ===== 响应式：平板 (768px - 1024px) ===== */
@media (max-width: 1024px) {
  .dashboard {
    padding: 15px;
    max-width: 100%;
  }
}

/* ===== 响应式：手机 (<= 768px) ===== */
@media (max-width: 768px) {
  .dashboard {
    padding: 10px;
  }

  body {
    font-size: 13px;
  }

  /* NavBar 垂直排列 */
  .navbar {
    flex-direction: column;
    align-items: stretch;
    gap: 8px;
    padding: 10px;
  }

  .nav-btn {
    width: 100%;
    padding: 12px 20px;
    font-size: 14px;
    text-align: center;
  }

  /* 结果区切换为单列 */
  .result-area {
    flex-direction: column;
    padding: 15px !important;
  }

  /* 介绍页卡片：单列 */
  .intro-container {
    padding: 15px !important;
    grid-template-columns: 1fr !important;
  }

  /* 摘要卡片：自适应换行 */
  .summary-cards,
  .summary-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  /* 输入框栅格：手机端单列 */
  .input-grid,
  .vuln-cards,
  .result-grid {
    grid-template-columns: 1fr !important;
  }

  /* 图表高度自适应 */
  .chart-container {
    height: 260px !important;
    gap: 8px !important;
  }

  .chart-bar {
    max-width: 60px;
  }

  /* 按钮自适应 */
  .gradient-btn,
  .generate-btn,
  .scan-btn {
    padding: 12px 24px;
    font-size: 14px;
    width: 100%;
    box-sizing: border-box;
  }

  /* 头部信息缩小 */
  .header {
    padding: 20px 15px !important;
  }

  .header h1 {
    font-size: 20px;
  }

  /* 报告内容：缩小内边距与字号 */
  .report-content,
  .report-text {
    padding: 12px !important;
    font-size: 12.5px !important;
  }

  /* 历史记录缩小 */
  .history-section {
    padding: 0 10px 15px 10px !important;
  }

  .history-item {
    padding: 10px;
  }

  /* 控制面板按钮宽度 */
  .control-panel {
    padding: 15px !important;
  }

  .control-panel button {
    width: 100%;
    margin-bottom: 8px;
  }

  /* 图表容器最小宽度自适应 */
  .radar-container,
  .report-box {
    min-width: 0 !important;
  }

  /* 表格/长文本横向滚动 */
  pre {
    overflow-x: auto;
    max-width: 100%;
    box-sizing: border-box;
  }
}

/* ===== 响应式：小屏手机 (<= 480px) ===== */
@media (max-width: 480px) {
  .dashboard {
    padding: 6px;
  }

  body {
    font-size: 12px;
  }

  .header h1 {
    font-size: 18px;
  }

  .nav-btn {
    font-size: 13px;
    padding: 10px;
  }
}

/* ===== 打印样式（可选） ===== */
@media print {
  .dashboard {
    max-width: 100%;
    padding: 0;
  }
  .navbar,
  .control-panel {
    display: none;
  }
}
</style>