<!--
@file ScanPage.vue
@description 漏洞扫描主页面
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="scan-container">
    <!-- 模型选择栏 -->
    <ScanForm
      :availableModels="availableModels"
      :selectedModel="selectedModel"
      @model-changed="selectedModel = $event"
    />

    <!-- 控制面板 -->
    <ControlPanel
      :isScanning="isScanning"
      :scanProgress="scanProgress"
      :historyList="historyList"
      :aiReport="aiReport"
      @startScan="startScan"
      @clearHistory="clearHistory"
      @exportReport="exportReport"
    />

    <!-- 扫描进度 -->
    <ScanProgress
      :isVisible="isScanning || scanProgress > 0"
      :progress="scanProgress"
      :statusText="scanStatusText"
    />

    <!-- 结果展示 -->
    <div class="result-area">
      <RadarChart ref="radarChartRef" />
      <AIReport
        :isScanning="isScanning"
        :scanProgress="scanProgress"
        :scanLogs="scanLogs"
        :aiReport="aiReport"
      />
    </div>

    <!-- 详细结果卡片（v2.4 新增） -->
    <ScanResult
      v-if="collectedResults.length > 0"
      :results="collectedResults"
      :total="collectedResults.length"
      :success="successCount"
      :aiReportHtml="formattedFinalReport"
    />

    <!-- 历史记录 -->
    <HistoryList :historyList="historyList" />
  </div>
</template>

<script setup>
/**
 * @file ScanPage.vue
 * @description 漏洞扫描页面主组件
 * - 协调 ScanForm、ControlPanel、ScanProgress、RadarChart、AIReport、ScanResult、HistoryList 等子组件
 * - 通过 Pinia store (useScanStore) 管理全局状态
 * - 支持 SSE 流式接收扫描结果并实时更新进度
 *
 * @author hrgt698
 * @version 2.4.0
 * @since 2024.03
 *
 * @requires pinia
 * @requires @/stores/scanStore
 * @requires @/utils/api
 * @requires dompurify (用于 XSS 防护)
 */
import { ref, computed, onUnmounted } from 'vue'
import { storeToRefs } from 'pinia'
import { useScanStore } from '@/stores/scanStore'
import { api } from '@/utils/api'
import ControlPanel from './ControlPanel.vue'
import RadarChart from './RadarChart.vue'
import AIReport from './AIReport.vue'
import HistoryList from './HistoryList.vue'
import ScanForm from './ScanForm.vue'
import ScanProgress from './ScanProgress.vue'
import ScanResult from './ScanResult.vue'

const scanStore = useScanStore()
const {
  isScanning, scanProgress, scanStatusText, aiReport, scanLogs,
  historyList, availableModels, selectedModel, backendStatus, targetStatus, apiConfigured
} = storeToRefs(scanStore)

const radarChartRef = ref(null)
const localSelectedModel = ref(selectedModel.value)
let currentStreamReader = null
let completedCount = 0
let totalVulns = 0
const collectedResults = ref([])
const successCount = ref(0)

// SSE 流式扫描
const startScan = async () => {
  if (isScanning.value) return

  isScanning.value = true
  scanProgress.value = 0
  scanStatusText.value = '正在扫描...'
  scanStore.clearLogs()
  aiReport.value = ''
  collectedResults.value = []
  successCount.value = 0
  completedCount = 0

  scanStore.addLog('🚀 初始化扫描引擎...')
  scanStore.addLog('📡 连接后端服务...')

  if (currentStreamReader) {
    try { await currentStreamReader.cancel() } catch (e) {}
    currentStreamReader = null
  }

  try {
    const response = await api.scanStream()
    const reader = response.body.getReader()
    currentStreamReader = reader
    const decoder = new TextDecoder()
    let buffer = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() || ''

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.slice(6))
            await handleSSEData(data)
          } catch (e) {
            console.error('解析SSE失败:', e)
          }
        }
      }
    }
  } catch (error) {
    console.error('扫描出错:', error)
    scanStore.addLog(`❌ 扫描失败: ${error.message}`)
    scanStatusText.value = '扫描失败'
  } finally {
    setTimeout(() => {
      if (!aiReport.value) {
        aiReport.value = '<div style="color: #f56c6c; padding: 20px;"><h4>❌ 扫描失败</h4><p>请检查后端服务是否正常运行</p></div>'
      }
      isScanning.value = false
      scanStatusText.value = '准备就绪'
    }, 500)
  }
}

/**
 * 处理 SSE 流式数据
 * @param {Object} data - SSE 事件数据
 * @param {string} data.type - 事件类型 (start/progress/log/result/complete)
 * @returns {Promise<void>}
 */
const handleSSEData = async (data) => {
  switch (data.type) {
    case 'start':
      totalVulns = data.total
      scanStore.addLog(`🔍 开始扫描 (${data.index}/${data.total}): ${data.name}`)
      scanProgress.value = Math.floor((data.index - 1) / totalVulns * 100)
      break
    case 'progress':
      scanStore.addLog(data.message)
      break
    case 'log':
      let logMsg = data.message
      logMsg = logMsg.replace(/\[[*]\]/g, '📌').replace(/\[\+\]/g, '✅').replace(/\[\-\]/g, '❌')
      scanStore.addLog(logMsg)
      break
    case 'result':
      completedCount++
      scanProgress.value = Math.floor(completedCount / totalVulns * 100)
      scanStore.addLog(`${data.status_text} - ${data.name}`)
      if (data.leaked_data) {
        scanStore.addLog(`🔑 获取到敏感数据: ${data.leaked_data}`)
      }
      if (data.full_result) {
        collectedResults.value.push(data.full_result)
        if (data.status === 'success') successCount.value++
      }
      break
    case 'complete':
      scanStore.addLog('✅ 扫描完成，正在生成 AI 分析报告...')
      currentStreamReader = null

      if (radarChartRef.value) {
        radarChartRef.value.updateRadarChart(collectedResults.value)
      }
      scanStore.saveToHistory(collectedResults.value, collectedResults.value.length, successCount.value)
      aiReport.value = buildFinalReport()
      scanStore.clearLogs()  // v2.4: 使用 store 方法而非直接赋值
      scanStatusText.value = '扫描完成'
      break
  }
}

// 构建最终报告 HTML
const buildFinalReport = () => {
  if (!collectedResults.value.length) return ''
  let html = '<div style="color: #333;">'

  // 汇总卡片
  html += `<div style="display: flex; justify-content: space-around; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 12px; margin-bottom: 20px;">`
  html += `<div><div style="font-size: 32px;">${collectedResults.value.length}</div><div>总计漏洞</div></div>`
  html += `<div><div style="font-size: 32px; color: #67c23a;">${successCount.value}</div><div>成功利用</div></div>`
  html += `<div><div style="font-size: 32px; color: #f56c6c;">${collectedResults.value.length - successCount.value}</div><div>利用失败</div></div>`
  html += `<div><div style="font-size: 32px;">${((successCount.value / collectedResults.value.length) * 100).toFixed(1)}%</div><div>成功率</div></div>`
  html += `</div>`

  // AI 研判报告
  for (const result of collectedResults.value) {
    if (result.analysis_report && !result.analysis_report.includes('未配置')) {
      html += `<div style="margin-bottom: 30px; border: 1px solid #e9ecef; border-radius: 12px; padding: 20px;">`
      html += `<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px; border-radius: 8px; margin-bottom: 20px;">`
      html += `🔍 ${result.vuln_name || result.cve_id}`
      html += `<span style="float: right;">${result.status === 'success' ? '✅ 利用成功' : '❌ 利用失败'}</span>`
      html += `</div>${formatAIReport(result.analysis_report)}</div>`
    }
  }
  return html
}

const formatAIReport = (text) => {
  if (!text) return ''
  let html = text
    .replace(/^### (.+)$/gm, '<h4 style="color: #667eea; margin: 20px 0 10px 0;">📌 $1</h4>')
    .replace(/^## (.+)$/gm, '<h3 style="color: #409eff; margin: 25px 0 15px 0; border-left: 4px solid #409eff; padding-left: 12px;">$1</h3>')
    .replace(/^---$/gm, '<hr>')
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`(.+?)`/g, '<code>$1</code>')
    .replace(/^(?!<[hH]|<li|<hr|<code|\\s*$)(.+)$/gm, '<p>$1</p>')
  html = html.replace(/(<li.+?<\/li>\n?)+/g, (match) => `<ul>${match}</ul>`)
  return html
}

/**
 * 导出当前扫描报告为 Markdown 文件
 * @returns {void}
 */
const exportReport = () => {
  if (!aiReport.value || aiReport.value === '点击"开始漏洞扫描"，AI分析报告将显示在这里...') {
    alert('暂无扫描报告，请先执行漏洞扫描')
    return
  }
  const now = new Date()
  const ts = `${now.getFullYear()}-${(now.getMonth()+1).toString().padStart(2,'0')}-${now.getDate().toString().padStart(2,'0')}_${now.getHours().toString().padStart(2,'0')}-${now.getMinutes().toString().padStart(2,'0')}`
  const reportElement = document.querySelector('.report-content')
  if (!reportElement) { alert('无法获取报告内容'); return }
  const blob = new Blob([reportElement.innerText], { type: 'text/markdown;charset=utf-8' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = `security_report_${ts}.md`
  link.click()
  URL.revokeObjectURL(link.href)
}

const clearHistory = () => scanStore.clearHistory()

// 状态检测
let statusTimer = null

/**
 * 检测后端和靶机服务状态
 * @async
 * @returns {Promise<void>}
 */
const checkStatus = async () => {
  try {
    const resp = await api.getStatus()
    if (resp.data?.status === 'running') {
      backendStatus.value = true
      apiConfigured.value = resp.data.api_configured || false
    }
  } catch { backendStatus.value = false }

  try {
    const resp = await api.checkTarget()
    targetStatus.value = resp.status === 200
  } catch { targetStatus.value = false }
}

watch(selectedModel, (newVal) => { localSelectedModel.value = newVal })

onMounted(async () => {
  try {
    const resp = await api.getModels()
    availableModels.value = resp.data.models
    selectedModel.value = resp.data.current
    localSelectedModel.value = resp.data.current
  } catch {
    availableModels.value = {
      'qwen-turbo': '通义千问-Turbo（轻量快速）',
      'qwen-plus': '通义千问-Plus（均衡性能）',
      'qwen-max': '通义千问-Max（最强能力）'
    }
  }
  await checkStatus()
  statusTimer = setInterval(checkStatus, 5000)
})

onUnmounted(() => {
  if (statusTimer) clearInterval(statusTimer)
})
</script>

<style scoped>
.result-area {
  display: flex;
  gap: 30px;
  padding: 30px;
  flex-wrap: wrap;
}
</style>
