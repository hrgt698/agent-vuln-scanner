<!--
@file ModelComparePage.vue
@description 多模型并发对比页面
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="intro-container">
    <div class="intro-card">
      <h3>🔐 漏洞信息输入</h3>
      <div class="input-grid">
        <div class="input-item">
          <label>漏洞ID (CVE/CWE)</label>
          <input v-model="cveId" type="text" placeholder="例如 CWE-78" :disabled="isComparing" />
        </div>
        <div class="input-item">
          <label>漏洞名称</label>
          <input v-model="vulnName" type="text" placeholder="例如 命令注入" :disabled="isComparing" />
        </div>
        <div class="input-item">
          <label>风险等级</label>
          <select v-model="riskLevel" :disabled="isComparing">
            <option value="critical">严重 (Critical)</option>
            <option value="high">高危 (High)</option>
            <option value="medium">中危 (Medium)</option>
          </select>
        </div>
      </div>
      <div class="action-row">
        <button class="gradient-btn" @click="handleCompare" :disabled="isComparing">
          <span v-if="isComparing">⚡ 多模型并发对比中...</span>
          <span v-else>🚀 开始并发对比 + 加权综合</span>
        </button>
      </div>
    </div>

    <div class="intro-card">
      <h3>📡 实时流式日志 (SSE)</h3>
      <p class="hint">每个模型完成后，下方会立即显示其研判结果。流式处理中，无需等待全部完成。</p>

      <div v-if="modelResults.length === 0 && !isComparing" class="empty-state">
        <div class="empty-icon">🤖</div>
        <p>点击上方按钮，开始多模型并发对比实验</p>
      </div>

      <div v-if="isComparing && modelResults.length === 0" class="loading-state">
        <div class="spinner"></div>
        <p>正在并发调用多模型，请稍候...</p>
      </div>

      <div class="result-grid">
        <div v-for="(item, index) in modelResults" :key="index"
             :class="['result-card', { 'card-error': item.status === 'error', 'card-ok': item.status === 'success' }]">
          <div class="result-header">
            <div class="model-info">
              <span class="model-name">🧠 {{ item.name || item.model }}</span>
              <span :class="['status-tag', item.status]">
                {{ item.status === 'success' ? '✅ 成功' : (item.status === 'error' ? '❌ 失败' : '⏳ 进行中') }}
              </span>
            </div>
            <span class="latency">⏱ {{ item.latency_ms ? item.latency_ms + ' ms' : '---' }}</span>
          </div>
          <div class="result-body">
            <div v-if="item.status === 'error'" class="error-text">
              ⚠ {{ item.error || '模型调用失败' }}
            </div>
            <div v-else-if="item.report" class="report-preview">
              <pre>{{ truncateReport(item.report) }}</pre>
            </div>
            <div v-else class="report-preview muted">
              暂无报告数据
            </div>
          </div>
          <div v-if="weightedScores[item.name || item.model] !== undefined" class="score-footer">
            加权评分: <strong>{{ weightedScores[item.name || item.model].toFixed(3) }}</strong>
          </div>
        </div>
      </div>
    </div>

    <div class="intro-card">
      <h3>📊 加权投票综合结果</h3>

      <div v-if="Object.keys(ensembleData).length === 0 && !ensembleReport" class="empty-state">
        <div class="empty-icon">📈</div>
        <p>综合结果将在所有模型对比完成后生成</p>
      </div>

      <div v-else class="ensemble-section">
        <div class="summary-row">
          <div class="summary-item highlight">
            <div class="summary-label">🏆 推荐模型</div>
            <div class="summary-value">{{ ensembleData.top_model || 'N/A' }}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">🎯 置信度</div>
            <div class="summary-value">{{ formatPercent(ensembleData.confidence_score) }}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">🔗 Jaccard 相似度</div>
            <div class="summary-value">{{ formatPercent(ensembleData.cross_validation?.jaccard_similarity) }}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">🔁 交叉验证重叠</div>
            <div class="summary-value">{{ ensembleData.cross_validation?.overlap_words ?? 0 }}</div>
          </div>
        </div>

        <div class="chart-wrapper">
          <div class="chart-title">各模型加权评分柱状图</div>
          <div class="chart-container">
            <div v-for="(score, modelName) in weightedScores" :key="modelName" class="chart-bar-wrapper">
              <div class="chart-bar" :style="{ height: getBarHeight(score) }">
                <span class="bar-value">{{ score.toFixed(3) }}</span>
              </div>
              <div class="bar-label" :class="{ 'top-model': modelName === ensembleData.top_model }">
                {{ modelName }}
                <span v-if="modelName === ensembleData.top_model" class="crown">👑</span>
              </div>
            </div>
          </div>
        </div>

        <div v-if="ensembleReport" class="ensemble-report">
          <div class="report-title">📝 加权综合研判报告</div>
          <pre class="report-content">{{ ensembleReport }}</pre>
        </div>

        <!-- v3.3 新增：多模型报告差异高亮视图 -->
        <div v-if="modelResults.length >= 2" class="diff-section">
          <div class="report-title highlight-title">
            🔍 模型报告差异对比（<strong>{{ uniqueDifferenceWords }}</strong> 处模型间分歧点）
          </div>
          <p class="diff-hint">
            红色高亮：仅在部分模型报告中出现，其他模型未提到 —— 可能反映模型关注点不同
          </p>
          <div class="diff-content">
            <div v-for="(item, idx) in highlightedReportList" :key="idx" class="diff-card">
              <div class="diff-card-header">
                🧠 {{ item.model }}
                <span v-if="item.model === ensembleData.top_model" class="crown">👑 推荐</span>
              </div>
              <div class="diff-card-body">
                <span
                  v-for="(token, i) in item.tokens"
                  :key="i"
                  :class="token.kind"
                  :title="token.kind === 'unique' ? '此内容仅在该模型报告中出现' : ''"
                >{{ token.text }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { api } from '@/utils/api'

const cveId = ref('CWE-78')
const vulnName = ref('命令注入')
const riskLevel = ref('high')
const modelResults = ref([])
const weightedScores = ref({})
const ensembleReport = ref('')
const ensembleData = ref({})
const isComparing = ref(false)
const maxScore = ref(0)

// ========== v3.3 新增：简易差异高亮（不引入外部依赖） ==========
// 策略：将每个报告拆分为关键词，然后统计每个词的出现模型数
// 仅在 1 个模型中出现的词 → 标红（unique），其他 → 普通

const STOPWORDS = new Set([
  '的', '是', '在', '有', '和', '为', '与', '也', '但', '不', '将',
  '本', '等', '可以', '需要', '需要', '可能', '或者', '这些', '那些',
  'a', 'the', 'is', 'in', 'of', 'to', 'and', 'or', 'for', 'on', 'are',
  'was', 'were', 'this', 'that', 'it', 'by', 'an', 'be', 'as', 'at',
  '.', ',', '，', '。', '：', ':', '；', '(', ')', '（', '）', '!', '！',
  '?', '？', '"', "'", '/', '\\', '|', '-', '+', '=',
])

function tokenize(text) {
  // 按空格和标点切分，保留换行
  const tokens = []
  text.split(/(\s+|[,.，。！？；:()（）])/).forEach((part) => {
    if (part) tokens.push(part)
  })
  return tokens
}

function wordSignature(word) {
  // 归一化，去除多余空白并变小写
  return word.trim().toLowerCase().replace(/[^a-z0-9\u4e00-\u9fa5]/g, '')
}

// computed：所有模型的报告中，每个词在几个模型报告里出现
const wordModelCoverage = computed(() => {
  const coverage = {}
  modelResults.value.forEach((m) => {
    const reportText = (m.report || '').toString()
    const uniqueWords = new Set()
    reportText.split(/\s+|[,.，。！？；:()（）]/).forEach((w) => {
      const sig = wordSignature(w)
      if (sig && sig.length >= 2 && !STOPWORDS.has(sig)) {
        uniqueWords.add(sig)
      }
    })
    uniqueWords.forEach((sig) => {
      coverage[sig] = (coverage[sig] || 0) + 1
    })
  })
  return coverage
})

const uniqueDifferenceWords = computed(() => {
  let count = 0
  for (const sig in wordModelCoverage.value) {
    if (wordModelCoverage.value[sig] === 1) count++
  }
  return count
})

const highlightedReportList = computed(() => {
  return modelResults.value.map((m) => {
    const text = (m.report || '').toString()
    const tokens = []
    text.split(/(\s+|[,.，。！？；:()（）])/).forEach((part) => {
      if (!part) return
      const sig = wordSignature(part)
      if (sig && sig.length >= 2 && !STOPWORDS.has(sig) && wordModelCoverage.value[sig] === 1) {
        tokens.push({ text: part, kind: 'unique-word' })
      } else {
        tokens.push({ text: part, kind: 'normal-text' })
      }
    })
    return {
      model: m.name || m.model,
      tokens,
    }
  })
})

const parseSSEEvent = (line) => {
  if (!line || !line.startsWith('data:')) return null
  const dataStr = line.substring(5).trim()
  if (!dataStr || dataStr === '[DONE]') return null
  try {
    return JSON.parse(dataStr)
  } catch {
    return { raw: dataStr }
  }
}

const handleCompare = async () => {
  isComparing.value = true
  modelResults.value = []
  weightedScores.value = {}
  ensembleReport.value = ''
  ensembleData.value = {}
  maxScore.value = 0

  const vulnData = {
    cve_id: cveId.value,
    vuln_name: vulnName.value,
    risk_level: riskLevel.value,
    status: 'success',
  }

  try {
    const response = await api.judgeCompareStream({ vuln_data: vulnData })

    if (!response || !response.ok) {
      throw new Error('流式对比请求失败')
    }

    const reader = response.body?.getReader()
    if (!reader) {
      throw new Error('无法读取 SSE 响应流')
    }

    const decoder = new TextDecoder('utf-8')
    let buffer = ''

    while (true) {
      const { value, done } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split(/\r?\n/)
      buffer = lines.pop() || ''

      for (const line of lines) {
        const trimmed = line.trim()
        if (!trimmed) continue
        const evt = parseSSEEvent(trimmed)
        if (!evt) continue

        if (evt.event === 'compare_model_done' || evt.type === 'compare_model_done' || evt.status === 'success' || evt.status === 'error') {
          const modelInfo = {
            model: evt.model || evt.model_id || 'unknown',
            name: evt.name || evt.model_name || evt.model || evt.model_id || 'unknown',
            status: evt.status || (evt.error ? 'error' : 'success'),
            latency_ms: evt.latency_ms || evt.latency || 0,
            report: evt.report || evt.summary || '',
            error: evt.error || null,
          }
          modelResults.value.push(modelInfo)
        } else if (evt.model && (evt.latency_ms !== undefined || evt.report !== undefined)) {
          const modelInfo = {
            model: evt.model,
            name: evt.name || evt.model,
            status: evt.error ? 'error' : 'success',
            latency_ms: evt.latency_ms || 0,
            report: evt.report || '',
            error: evt.error || null,
          }
          modelResults.value.push(modelInfo)
        }
      }
    }
  } catch (error) {
    console.warn('[多模型对比] 流式调用失败:', error)
    modelResults.value.push({
      model: 'stream_error',
      name: '⚠ 流式调用异常',
      status: 'error',
      latency_ms: 0,
      report: '',
      error: error.message || '网络或后端不可用',
    })
  }

  try {
    const result = await api.judgeWeightedEnsemble({ vuln_data: vulnData, models: [] })

    ensembleReport.value = result.ensemble_report || ''
    ensembleData.value = {
      confidence_score: result.confidence_score ?? 0,
      top_model: result.top_model || 'N/A',
      cross_validation: result.cross_validation || { overlap_words: 0, jaccard_similarity: 0 },
    }

    const scores = result.weighted_scores || {}
    let localMax = 0
    const computedScores = {}

    if (modelResults.value.length > 0 && Object.keys(scores).length === 0) {
      const latencies = modelResults.value
        .map((m) => (m.status === 'success' ? Number(m.latency_ms) || 0 : 0))
        .filter((v) => v > 0)
      const maxLatency = latencies.length > 0 ? Math.max(...latencies) : 1
      const minLatency = latencies.length > 0 ? Math.min(...latencies) : 0

      for (const m of modelResults.value) {
        const key = m.name || m.model
        const lat = Number(m.latency_ms) || 0
        if (m.status === 'success' && lat > 0) {
          const normalized = maxLatency !== minLatency
            ? 1 - (lat - minLatency) / (maxLatency - minLatency)
            : 1.0
          computedScores[key] = Math.max(0.01, normalized)
        } else {
          computedScores[key] = 0.05
        }
        if (computedScores[key] > localMax) localMax = computedScores[key]
      }
    } else {
      for (const key in scores) {
        computedScores[key] = Number(scores[key]) || 0
        if (computedScores[key] > localMax) localMax = computedScores[key]
      }
      for (const m of modelResults.value) {
        const key = m.name || m.model
        if (computedScores[key] === undefined) {
          computedScores[key] = 0.05
        }
      }
    }

    weightedScores.value = computedScores
    maxScore.value = localMax > 0 ? localMax : 1
  } catch (error) {
    console.warn('[加权综合] API 调用失败，降级到启发式结果:', error)
    ensembleReport.value =
      '[离线模式] 加权综合研判模块不可用，已降级为启发式引擎。\n\n' +
      '系统基于延迟、成功率等维度给出基础评分，仍可用于模型对比参考。'
    ensembleData.value = {
      confidence_score: 0.0,
      top_model: 'heuristic_fallback',
      cross_validation: { overlap_words: 0, jaccard_similarity: 0.0 },
    }

    const latencies = modelResults.value.map((m) => Number(m.latency_ms) || 0)
    const maxLatency = Math.max(...latencies, 1)
    const heuristic = {}
    let localMax = 0
    for (const m of modelResults.value) {
      const key = m.name || m.model
      const lat = Number(m.latency_ms) || 0
      heuristic[key] = m.status === 'success' ? Math.max(0.1, 1 - lat / maxLatency) : 0.05
      if (heuristic[key] > localMax) localMax = heuristic[key]
    }
    weightedScores.value = heuristic
    maxScore.value = localMax > 0 ? localMax : 1
  } finally {
    isComparing.value = false
  }
}

const truncateReport = (report) => {
  if (!report) return ''
  const str = String(report)
  return str.length > 300 ? str.substring(0, 300) + '...' : str
}

const formatPercent = (value) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return '0%'
  const num = Number(value)
  if (num <= 1.0) return (num * 100).toFixed(1) + '%'
  return num.toFixed(1) + '%'
}

const getBarHeight = (score) => {
  const max = maxScore.value > 0 ? maxScore.value : 1
  const ratio = Math.min(1, score / max)
  const height = Math.max(8, ratio * 300)
  return height + 'px'
}
</script>

<style scoped>
/* ========== v3.3 新增：差异高亮相关样式 ========== */
.diff-section {
  margin-top: 30px;
  padding: 20px;
  background: #fff7f7;
  border-radius: 16px;
  border: 1px solid #ffdede;
}
.highlight-title {
  color: #d64545;
}
.diff-hint {
  font-size: 13px;
  color: #8a6d6d;
  margin-bottom: 15px;
}
.diff-content {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 15px;
}
.diff-card {
  background: white;
  border-radius: 12px;
  border: 1px solid #f0dede;
  overflow: hidden;
}
.diff-card-header {
  padding: 10px 15px;
  background: linear-gradient(135deg, #f8f9fa 0%, #fff0f0 100%);
  font-weight: bold;
  font-size: 14px;
  color: #555;
  border-bottom: 1px solid #f0dede;
}
.diff-card-body {
  padding: 15px;
  font-size: 13px;
  line-height: 1.8;
  white-space: pre-wrap;
  word-break: break-word;
}
.unique-word {
  color: #d64545;
  background: #ffe5e5;
  padding: 1px 4px;
  border-radius: 3px;
  font-weight: 600;
  border-bottom: 1px dashed #d64545;
}
.normal-text {
  color: #333;
}
.crown {
  color: #e8a530;
  font-size: 12px;
}
/* 原有其他样式保持不变 */
.intro-container {
  padding: 30px;
  display: flex;
  flex-direction: column;
  gap: 25px;
}

.intro-card {
  background: #f8f9fa;
  border-radius: 16px;
  padding: 25px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
}

.intro-card h3 {
  color: #667eea;
  margin-bottom: 15px;
}

.hint {
  font-size: 13px;
  color: #909399;
  margin-bottom: 15px;
}

.input-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 15px;
  margin-bottom: 20px;
}

.input-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.input-item label {
  font-size: 13px;
  color: #606266;
  font-weight: 500;
}

.input-item input,
.input-item select {
  padding: 10px 14px;
  border: 1px solid #dcdfe6;
  border-radius: 10px;
  font-size: 14px;
  background: white;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.input-item input:focus,
.input-item select:focus {
  border-color: #667eea;
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.15);
}

.input-item input:disabled,
.input-item select:disabled {
  background: #f4f4f5;
  cursor: not-allowed;
}

.action-row {
  display: flex;
  justify-content: center;
  margin-top: 10px;
}

.gradient-btn {
  padding: 14px 36px;
  border: none;
  border-radius: 16px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
  box-shadow: 0 4px 14px rgba(102, 126, 234, 0.35);
  transition: transform 0.2s, box-shadow 0.2s, opacity 0.2s;
}

.gradient-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(102, 126, 234, 0.45);
}

.gradient-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.empty-state {
  padding: 40px 20px;
  text-align: center;
  color: #909399;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 10px;
}

.loading-state {
  padding: 40px 20px;
  text-align: center;
  color: #667eea;
}

.spinner {
  width: 36px;
  height: 36px;
  border: 4px solid rgba(102, 126, 234, 0.2);
  border-top-color: #667eea;
  border-radius: 50%;
  margin: 0 auto 15px;
  animation: spin 0.9s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.result-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 15px;
  margin-top: 10px;
}

.result-card {
  background: white;
  border-radius: 16px;
  padding: 18px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
  border-left: 4px solid #667eea;
  transition: transform 0.2s, box-shadow 0.2s;
}

.result-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.08);
}

.result-card.card-ok {
  border-left-color: #67c23a;
}

.result-card.card-error {
  border-left-color: #f56c6c;
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
  gap: 8px;
}

.model-info {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.model-name {
  font-weight: 600;
  color: #303133;
  font-size: 14px;
}

.status-tag {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
}

.status-tag.success {
  background: #f0f9eb;
  color: #67c23a;
}

.status-tag.error {
  background: #fef0f0;
  color: #f56c6c;
}

.latency {
  font-size: 12px;
  color: #909399;
  font-family: monospace;
}

.result-body {
  min-height: 60px;
}

.report-preview pre {
  background: #f8f9fa;
  border-radius: 10px;
  padding: 12px;
  font-size: 12px;
  color: #606266;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.6;
  font-family: 'SF Mono', Consolas, Monaco, monospace;
}

.report-preview.muted {
  color: #c0c4cc;
  font-size: 12px;
  font-style: italic;
}

.error-text {
  color: #f56c6c;
  font-size: 13px;
  padding: 10px;
  background: #fef0f0;
  border-radius: 8px;
}

.score-footer {
  margin-top: 10px;
  padding-top: 10px;
  border-top: 1px dashed #e4e7ed;
  font-size: 12px;
  color: #606266;
}

.score-footer strong {
  color: #667eea;
}

.ensemble-section {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.summary-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
}

.summary-item {
  background: white;
  border-radius: 12px;
  padding: 16px;
  text-align: center;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
}

.summary-item.highlight {
  background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
  border: 2px solid #667eea;
}

.summary-label {
  font-size: 12px;
  color: #909399;
  margin-bottom: 6px;
}

.summary-value {
  font-size: 16px;
  font-weight: 700;
  color: #667eea;
  word-break: break-word;
}

.chart-wrapper {
  background: white;
  border-radius: 12px;
  padding: 20px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
}

.chart-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 20px;
}

.chart-container {
  display: flex;
  align-items: flex-end;
  justify-content: space-around;
  height: 340px;
  padding: 20px 10px 0;
  gap: 14px;
  border-bottom: 2px solid #e4e7ed;
}

.chart-bar-wrapper {
  display: flex;
  flex-direction: column;
  align-items: center;
  flex: 1;
  min-width: 50px;
  height: 100%;
  justify-content: flex-end;
}

.chart-bar {
  width: 100%;
  max-width: 80px;
  background: linear-gradient(180deg, #764ba2 0%, #667eea 100%);
  border-radius: 10px 10px 4px 4px;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 8px;
  transition: height 0.8s cubic-bezier(0.2, 0.9, 0.3, 1);
  position: relative;
  box-shadow: 0 4px 14px rgba(102, 126, 234, 0.35);
}

.bar-value {
  color: white;
  font-size: 12px;
  font-weight: 700;
  font-family: monospace;
}

.bar-label {
  margin-top: 10px;
  font-size: 11px;
  color: #606266;
  text-align: center;
  font-weight: 500;
  word-break: break-word;
  line-height: 1.4;
  min-height: 32px;
}

.bar-label.top-model {
  color: #e6a23c;
  font-weight: 700;
  font-size: 12px;
}

.crown {
  margin-left: 4px;
}

.ensemble-report {
  background: white;
  border-radius: 12px;
  padding: 20px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
}

.report-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 12px;
}

.report-content {
  background: #f8f9fa;
  border-radius: 10px;
  padding: 16px;
  font-size: 12.5px;
  color: #606266;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  line-height: 1.7;
  font-family: 'SF Mono', Consolas, Monaco, monospace;
  max-height: 450px;
  overflow-y: auto;
}
</style>
