/**
 * @file scanStore.js
 * @description Pinia 状态管理 Store - 扫描全局状态管理
 * - 管理扫描进度、日志、AI 报告、历史记录
 * - 支持 SSE 流式数据接收和实时状态更新
 *
 * @author hrgt698
 * @version 2.4.0
 * @since 2024.03
 *
 * @requires pinia
 */
import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useScanStore = defineStore('scan', () => {
  // 扫描状态
  const isScanning = ref(false)
  const scanProgress = ref(0)
  const scanStatusText = ref('准备就绪')
  const aiReport = ref('')
  const scanLogs = ref([])
  const historyList = ref([])
  const selectedHistory = ref(null)
  
  // 模型相关
  const availableModels = ref({})
  const selectedModel = ref('qwen-turbo')
  const isModelSwitching = ref(false)
  const backendStatus = ref(false)
  const targetStatus = ref(false)
  const apiConfigured = ref(false)
  
  let currentStreamReader = null
  
  // 获取当前时间
  const getCurrentTime = () => {
    const now = new Date()
    return `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`
  }
  
  // 添加日志
  const addLog = (message) => {
    scanLogs.value.push({
      time: getCurrentTime(),
      message: message
    })
  }
  
  // 清空日志
  const clearLogs = () => {
    scanLogs.value = []
  }
  
  // 保存到历史记录
  const saveToHistory = (results, total, success) => {
    const now = new Date()
    const timeStr = `${now.getMonth()+1}/${now.getDate()} ${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}`
    historyList.value.unshift({
      time: timeStr,
      totalCount: total,
      successCount: success,
      results: results
    })
    if (historyList.value.length > 10) historyList.value.pop()
    localStorage.setItem('scanHistory', JSON.stringify(historyList.value))
  }
  
  // 加载历史记录
  const loadHistory = () => {
    const saved = localStorage.getItem('scanHistory')
    if (saved) historyList.value = JSON.parse(saved)
  }
  
  // 清空历史
  const clearHistory = () => {
    if (confirm('确定要清空所有历史记录吗？')) {
      historyList.value = []
      localStorage.removeItem('scanHistory')
      selectedHistory.value = null
    }
  }
  
  // 查看历史详情
  const viewHistoryDetail = (record) => {
    const idx = historyList.value.indexOf(record)
    selectedHistory.value = selectedHistory.value === idx ? null : idx
  }
  
  return {
    // 状态
    isScanning, scanProgress, scanStatusText, aiReport, scanLogs,
    historyList, selectedHistory, selectedHistory: selectedHistory,
    availableModels, selectedModel, isModelSwitching,
    backendStatus, targetStatus, apiConfigured,
    currentStreamReader,
    // 方法
    addLog, clearLogs, saveToHistory, loadHistory, clearHistory, viewHistoryDetail,
    getCurrentTime
  }
})