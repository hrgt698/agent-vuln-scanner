<!--
@file ScanResult.vue
@description 扫描结果展示
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="result-display">
    <div class="summary-cards" v-if="results.length > 0">
      <div class="summary-card total">
        <div class="card-value">{{ total }}</div>
        <div class="card-label">总计漏洞</div>
      </div>
      <div class="summary-card success">
        <div class="card-value">{{ success }}</div>
        <div class="card-label">成功利用</div>
      </div>
      <div class="summary-card failed">
        <div class="card-value">{{ failed }}</div>
        <div class="card-label">利用失败</div>
      </div>
      <div class="summary-card rate">
        <div class="card-value">{{ successRate }}%</div>
        <div class="card-label">成功率</div>
      </div>
    </div>

    <!-- 漏洞卡片列表 -->
    <div class="vuln-cards">
      <div
        v-for="(result, idx) in results"
        :key="idx"
        class="vuln-card"
        :class="result.status === 'success' ? 'vuln-success' : 'vuln-failed'"
      >
        <div class="vuln-header">
          <span class="vuln-icon">{{ result.status === 'success' ? '✅' : '❌' }}</span>
          <strong>{{ idx + 1 }}. {{ result.vuln_name || result.cve_id }}</strong>
          <span
            class="risk-badge"
            :style="{ background: riskColor(result.risk_level) }"
          >{{ riskLabel(result.risk_level) }}</span>
        </div>
        <div class="vuln-detail" v-if="result.cve_id">
          📋 CVE/编号: {{ result.cve_id }}
        </div>
        <div class="vuln-detail" v-if="result.leaked_data">
          🔑 泄露数据:
          <code class="flag-code">{{ result.leaked_data }}</code>
        </div>
      </div>
    </div>

    <!-- AI 报告 -->
    <div class="ai-report-section" v-if="aiReportHtml" v-html="aiReportHtml" />
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  results: {
    type: Array,
    default: () => []
  },
  total: {
    type: Number,
    default: 0
  },
  success: {
    type: Number,
    default: 0
  },
  aiReportHtml: {
    type: String,
    default: ''
  }
})

const failed = computed(() => props.total - props.success)
const successRate = computed(() =>
  props.total > 0 ? ((props.success / props.total) * 100).toFixed(1) : '0.0'
)

const riskColor = (level) => {
  if (level === 'critical') return '#e6a23c'
  if (level === 'high') return '#f56c6c'
  return '#909399'
}

const riskLabel = (level) => {
  const map = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
  return map[level] || '未知'
}
</script>

<style scoped>
.result-display {
  padding: 20px 30px;
}

.summary-cards {
  display: flex;
  justify-content: space-around;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 20px;
  color: white;
}

.summary-card {
  text-align: center;
}

.card-value {
  font-size: 32px;
  font-weight: bold;
}

.card-label {
  font-size: 14px;
  opacity: 0.9;
}

.vuln-cards {
  margin-top: 15px;
}

.vuln-card {
  margin-bottom: 15px;
  padding: 15px;
  background: #fafafa;
  border-radius: 8px;
  border-left: 4px solid #909399;
}

.vuln-success {
  border-left-color: #67c23a;
}

.vuln-failed {
  border-left-color: #f56c6c;
}

.vuln-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}

.vuln-icon {
  font-size: 20px;
}

.risk-badge {
  color: white;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 12px;
}

.vuln-detail {
  font-size: 13px;
  color: #666;
  padding-left: 30px;
}

.flag-code {
  background: #e8f8e8;
  padding: 4px 8px;
  border-radius: 4px;
  color: #67c23a;
}

.ai-report-section {
  margin-top: 30px;
  border: 1px solid #e9ecef;
  border-radius: 12px;
  padding: 20px;
}
</style>
