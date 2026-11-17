<!--
@file DemoPage.vue
@description 一键演示模式页面
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="intro-container">
    <div class="intro-card">
      <h2>🎬 演示报告生成</h2>
      <p>选择一个漏洞类型，点击「一键生成演示报告」，即可快速获取专业的漏洞分析报告。</p>
    </div>

    <div class="intro-card">
      <h3>🔧 选择漏洞类型</h3>
      <div class="vuln-cards">
        <div
          v-for="v in vulns"
          :key="v.id"
          :class="['vuln-card', v.risk, { selected: selectedVuln === v.id }]"
          @click="handleSelect(v)"
        >
          <span class="cve-id">{{ v.id }}</span>
          <span class="vuln-name">{{ v.name }}</span>
          <span :class="['risk-badge', v.risk]">
            {{ v.risk === 'critical' ? '严重' : v.risk === 'high' ? '高危' : '中危' }}
          </span>
        </div>
      </div>
    </div>

    <div class="intro-card">
      <h3>⚙️ 风险等级设置</h3>
      <div class="risk-selector">
        <label>风险等级：</label>
        <select v-model="selectedRisk">
          <option value="high">高风险 (High)</option>
          <option value="medium">中风险 (Medium)</option>
          <option value="critical">严重 (Critical)</option>
        </select>
      </div>
    </div>

    <div class="intro-card action-card">
      <button
        class="generate-btn"
        :disabled="isLoading"
        @click="generateReport"
      >
        <span v-if="isLoading" class="loading-icon">⏳</span>
        {{ isLoading ? '正在生成中，请稍候...' : '🚀 一键生成演示报告' }}
      </button>
    </div>

    <div class="intro-card report-card" v-if="isLoading || report">
      <h3>📄 演示报告 <small class="report-meta">关键词红色高亮表示高风险点</small></h3>
      <div v-if="isLoading" class="loading-state">
        <div class="spinner"></div>
        <p>正在由 AI 智能生成报告，请稍候...</p>
      </div>
      <div v-else-if="report" class="report-content">
        <pre class="report-text"><template v-for="(tok, i) in highlightedReportTokens" :key="i"><span :class="tok.kind">{{ tok.text }}</span></template></pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { api } from '@/utils/api'

// ========== v3.3 新增：报告关键词高亮 ==========
// 高风险关键词列表（基于漏洞场景）
const RISK_KEYWORDS = [
  '命令注入', 'SQL注入', 'SQL 注入', '未授权', '未验证',
  '恶意', '攻击', '漏洞', '风险', '泄露', '敏感数据',
  '越权', '路径遍历', '注入', '提权', '执行', '拼接',
  'CWE-78', 'CWE-89', 'CS0048', 'AML.T0051',
  'command injection', 'sql injection', 'vulnerability',
  'exploit', 'risk', 'leak', 'unauthorized',
  'CWE-', 'CS0048',
]

const isRiskKeyword = (text) => {
  const lower = text.toLowerCase()
  return RISK_KEYWORDS.some((kw) => lower.includes(kw.toLowerCase()))
}

// 计算属性：将报告拆分为 token 流，识别风险关键词
const highlightedReportTokens = computed(() => {
  if (!report.value) return []
  const tokens = []
  report.value.split(/(\s+|[,.，。！？；:()（）])/).forEach((part) => {
    if (!part) return
    if (isRiskKeyword(part)) {
      tokens.push({ text: part, kind: 'risk-highlight' })
    } else {
      tokens.push({ text: part, kind: 'normal' })
    }
  })
  return tokens
})

const selectedVuln = ref('CWE-78')
const selectedRisk = ref('high')
const report = ref('')
const isLoading = ref(false)

const vulns = ref([
  { id: 'CWE-78', name: '命令注入', risk: 'high' },
  { id: 'CWE-89', name: 'SQL 注入', risk: 'high' },
  { id: 'CS0048', name: 'API 未授权访问', risk: 'medium' },
  { id: 'CWE-125', name: '越界读取', risk: 'medium' },
  { id: 'AML.T0051', name: '提示词注入', risk: 'critical' }
])

const handleSelect = (v) => {
  selectedVuln.value = v.id
}

const generateReport = async () => {
  isLoading.value = true
  report.value = ''
  try {
    const current = vulns.value.find((v) => v.id === selectedVuln.value)
    const res = await api.judgeDemo({
      cve_id: selectedVuln.value,
      vuln_name: current ? current.name : '',
      risk_level: selectedRisk.value
    })
    report.value = res.report
  } catch (err) {
    report.value = '[错误] 演示报告生成失败：' + (err?.message || '未知错误')
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
.intro-container {
  padding: 30px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 25px;
}

.intro-card {
  background: #f8f9fa;
  border-radius: 16px;
  padding: 25px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
}

.intro-card h2,
.intro-card h3 {
  color: #667eea;
  margin-bottom: 15px;
}

.vuln-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
}

.vuln-card {
  background: white;
  border-radius: 12px;
  padding: 18px;
  border: 2px solid #e0e0e0;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 8px;
  transition: all 0.25s ease;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
}

.vuln-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.15);
}

.vuln-card.high {
  border-color: #f56c6c;
}

.vuln-card.medium {
  border-color: #e6a23c;
}

.vuln-card.critical {
  border-color: #9c27b0;
}

.vuln-card.selected {
  border-color: #667eea;
  background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
  box-shadow: 0 4px 14px rgba(102, 126, 234, 0.35);
  transform: translateY(-2px);
}

.cve-id {
  font-family: monospace;
  background: #f0f0f0;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  color: #333;
}

.vuln-name {
  font-weight: bold;
  font-size: 15px;
  color: #333;
}

.risk-badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: bold;
  color: white;
}

.risk-badge.high {
  background: #f56c6c;
}

.risk-badge.medium {
  background: #e6a23c;
}

.risk-badge.critical {
  background: #9c27b0;
}

.risk-selector {
  display: flex;
  align-items: center;
  gap: 15px;
  flex-wrap: wrap;
}

.risk-selector label {
  font-size: 14px;
  color: #333;
}

.risk-selector select {
  padding: 8px 15px;
  border-radius: 8px;
  border: 1px solid #ddd;
  font-size: 14px;
  background: white;
  cursor: pointer;
}

.action-card {
  grid-column: 1 / -1;
  display: flex;
  justify-content: center;
  background: transparent;
  box-shadow: none;
  padding: 10px 0;
}

.generate-btn {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  padding: 16px 48px;
  border-radius: 16px;
  font-size: 17px;
  font-weight: bold;
  cursor: pointer;
  box-shadow: 0 4px 14px rgba(102, 126, 234, 0.4);
  transition: all 0.25s ease;
  display: flex;
  align-items: center;
  gap: 10px;
}

.generate-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
}

.generate-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.loading-icon {
  display: inline-block;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.report-card {
  grid-column: 1 / -1;
  background: #ffffff;
}

.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  color: #667eea;
}

.spinner {
  width: 40px;
  height: 40px;
  border: 4px solid rgba(102, 126, 234, 0.2);
  border-top-color: #667eea;
  border-radius: 50%;
  animation: spin 0.9s linear infinite;
  margin-bottom: 15px;
}

.report-content {
  background: #f5f7fa;
  border-radius: 12px;
  padding: 20px;
  border-left: 4px solid #667eea;
}

.report-text {
  margin: 0;
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 13.5px;
  line-height: 1.8;
  color: #303133;
}
/* v3.3 新增：报告关键词高亮 */
.risk-highlight {
  color: #d64545;
  background: #ffe5e5;
  padding: 0 4px;
  border-radius: 3px;
  font-weight: 600;
  border-bottom: 1px dashed #d64545;
}
.normal {
  color: #303133;
}
.report-meta {
  font-size: 12px;
  font-weight: normal;
  color: #909399;
}
</style>
