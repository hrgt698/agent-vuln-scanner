<!--
@file AIReport.vue
@description AI 研判报告展示
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="report-box">
    <div class="report-header">
      <h3>🤖 AI 智能研判报告</h3>
      <!-- 评分徽章 -->
      <div v-if="reportData.score" class="score-badge" :class="scoreClass">
        <span class="score-label">综合评分</span>
        <span class="score-value">{{ reportData.score }}</span>
        <span class="score-max">/110</span>
      </div>
    </div>

    <!-- 流式推理过程 -->
    <div v-if="isStreaming" class="thinking-container">
      <div
        v-for="(msg, idx) in thinkingSteps"
        :key="idx"
        class="thinking-step"
        :class="{ 'thinking-done': msg.done }"
      >
        <div class="thinking-indicator">
          <span v-if="msg.done" class="step-check">✓</span>
          <span v-else class="step-spinner">⟳</span>
        </div>
        <div class="thinking-text">{{ msg.message }}</div>
      </div>
      <div v-if="thinkingSteps.length === 0" class="streaming-placeholder">
        <span class="blink-dot">●</span> 等待 AI 推理过程...
      </div>
    </div>

    <!-- 多模型投票结果 -->
    <div v-if="reportData.model_summaries && reportData.model_summaries.length > 0" class="model-votes">
      <h4 class="section-title">🔬 多模型研判摘要</h4>
      <div class="model-vote-list">
        <div
          v-for="item in reportData.model_summaries"
          :key="item.model"
          class="model-vote-item"
        >
          <div class="model-name">{{ item.model }}</div>
          <div class="model-summary">{{ item.summary || '暂无摘要' }}</div>
        </div>
      </div>
    </div>

    <!-- 最终报告内容 -->
    <div v-if="!isStreaming && safeReport" class="report-content">
      <div class="report-meta">
        <span v-if="reportData.mode" class="meta-tag">模式：{{ reportData.mode === 'multi-agent' ? 'Multi-Agent' : 'Full' }}</span>
        <span v-if="reportData.current_model" class="meta-tag">模型：{{ reportData.current_model }}</span>
        <span v-if="reportData.models_called" class="meta-tag">调用模型数：{{ reportData.models_called.length }}</span>
      </div>
      <div v-html="safeReport" class="markdown-body"></div>
    </div>

    <!-- 错误状态 -->
    <div v-if="errorMessage" class="error-box">
      <span class="error-icon">⚠️</span>
      <span class="error-text">{{ errorMessage }}</span>
    </div>

    <!-- 空状态 -->
    <div v-if="!isStreaming && !safeReport && !errorMessage" class="placeholder-text">
      <div class="placeholder-icon">📋</div>
      <p>点击「开始漏洞扫描」按钮，AI 将开始分析...</p>
      <p class="placeholder-hint">分析完成后将在此展示详细的漏洞研判报告</p>
    </div>
  </div>
</template>

<script setup>
/**
 * @file AIReport.vue
 * @description AI 研判报告展示组件
 * - 支持 SSE 流式推理过程可视化（v2.4 新增）
 * - 支持多模型投票结果展示
 * - 使用 DOMPurify 进行 XSS 防护
 *
 * @author hrgt698
 * @version 2.4.0
 * @requires dompurify
 */
import { computed, ref, watch } from 'vue'
import DOMPurify from 'dompurify'

const props = defineProps({
  isScanning: Boolean,
  scanProgress: Number,
  scanLogs: Array,
  aiReport: String,
  // v2.4 新增：SSE 流式研判数据
  sseThinkingSteps: {
    type: Array,
    default: () => [],
  },
  sseComplete: {
    type: Boolean,
    default: false,
  },
  sseError: {
    type: String,
    default: '',
  },
})

// ========== v2.4 新增：SSE 流式数据处理 ==========
const thinkingSteps = ref([])
const isStreaming = computed(() => props.isScanning && thinkingSteps.value.length > 0)
const errorMessage = computed(() => props.sseError || '')

watch(() => props.sseThinkingSteps, (newSteps) => {
  if (newSteps && newSteps.length > 0) {
    thinkingSteps.value = newSteps.map((step, idx) => ({
      ...step,
      done: step.type === 'complete' || step.type === 'error',
    }))
  }
}, { deep: true })

watch(() => props.sseComplete, (val) => {
  if (val) {
    // 完成后清空 thinking 状态
    setTimeout(() => {
      thinkingSteps.value = []
    }, 2000)
  }
})

// ========== 报告数据整合 ==========
const reportData = computed(() => {
  if (props.aiReport && typeof props.aiReport === 'object') {
    return props.aiReport
  }
  return {}
})

// ========== 安全报告渲染（XSS 防护） ==========
const safeReport = computed(() => {
  const raw = typeof props.aiReport === 'string'
    ? props.aiReport
    : (reportData.value.analysis || '')
  if (!raw) return ''
  return DOMPurify.sanitize(raw)
})

// ========== 评分样式 ==========
const scoreClass = computed(() => {
  const s = reportData.value.score || 0
  if (s >= 90) return 'score-excellent'
  if (s >= 70) return 'score-good'
  if (s >= 50) return 'score-warning'
  return 'score-danger'
})
</script>

<style scoped>
.report-box {
  flex: 1;
  min-width: 380px;
  background: white;
  border-radius: 12px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.08);
  padding: 20px;
  max-height: 700px;
  overflow-y: auto;
}

.report-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 10px;
}

.report-header h3 {
  margin: 0;
  color: #333;
  font-size: 16px;
}

/* ===== 评分徽章 ===== */
.score-badge {
  display: flex;
  align-items: baseline;
  gap: 4px;
  padding: 6px 14px;
  border-radius: 20px;
  font-weight: 600;
  font-size: 14px;
}
.score-label {
  font-size: 12px;
  font-weight: 400;
  color: inherit;
  opacity: 0.8;
}
.score-value {
  font-size: 22px;
  font-weight: 700;
}
.score-max {
  font-size: 12px;
  opacity: 0.6;
}
.score-excellent { background: #e8f5e9; color: #2e7d32; }
.score-good { background: #e3f2fd; color: #1565c0; }
.score-warning { background: #fff8e1; color: #f57f17; }
.score-danger { background: #ffebee; color: #c62828; }

/* ===== 流式推理过程 ===== */
.thinking-container {
  background: #fafafa;
  border-radius: 8px;
  padding: 14px;
  margin-bottom: 16px;
  border: 1px solid #eee;
}
.thinking-step {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 6px 0;
  color: #666;
  font-size: 13px;
  transition: all 0.3s;
}
.thinking-step.thinking-done {
  color: #2e7d32;
}
.thinking-indicator {
  flex-shrink: 0;
  width: 18px;
  text-align: center;
}
.step-check {
  color: #2e7d32;
  font-size: 14px;
}
.step-spinner {
  display: inline-block;
  animation: spin 1s linear infinite;
  color: #667eea;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
.thinking-text {
  line-height: 1.5;
}
.streaming-placeholder {
  text-align: center;
  color: #bbb;
  padding: 10px;
  font-size: 13px;
}
.blink-dot {
  animation: blink 1.5s ease-in-out infinite;
  color: #667eea;
}
@keyframes blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

/* ===== 多模型投票 ===== */
.model-votes {
  margin-bottom: 16px;
}
.section-title {
  font-size: 13px;
  color: #555;
  margin-bottom: 10px;
  font-weight: 600;
}
.model-vote-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.model-vote-item {
  background: #f9f9f9;
  border-radius: 6px;
  padding: 10px 12px;
  border-left: 3px solid #667eea;
}
.model-name {
  font-size: 12px;
  font-weight: 600;
  color: #667eea;
  margin-bottom: 4px;
}
.model-summary {
  font-size: 12px;
  color: #666;
  line-height: 1.5;
}

/* ===== 报告内容 ===== */
.report-content {
  margin-top: 12px;
}
.report-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 14px;
}
.meta-tag {
  background: #f0f2f5;
  color: #666;
  font-size: 11px;
  padding: 3px 10px;
  border-radius: 12px;
}
.markdown-body {
  line-height: 1.7;
  color: #2c3e50;
  font-size: 14px;
}

/* ===== 错误状态 ===== */
.error-box {
  background: #fff5f5;
  border: 1px solid #ffcdd2;
  border-radius: 8px;
  padding: 12px 16px;
  color: #c62828;
  font-size: 13px;
  margin-top: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* ===== 空状态 ===== */
.placeholder-text {
  text-align: center;
  padding: 40px 20px;
  color: #909399;
}
.placeholder-icon {
  font-size: 48px;
  margin-bottom: 12px;
}
.placeholder-text p {
  margin: 6px 0;
  font-size: 14px;
}
.placeholder-hint {
  color: #bbb;
  font-size: 12px !important;
}
</style>
