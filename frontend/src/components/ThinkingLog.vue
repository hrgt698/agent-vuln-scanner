<!--
@file ThinkingLog.vue
@description ReAct Agent 推理轨迹日志
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div v-if="isScanning && scanLogs.length > 0" class="thinking-container">
    <div class="thinking-header">
      <span class="thinking-icon">🤔</span>
      <span>AI 正在扫描分析中...</span>
      <span class="progress-badge">{{ scanProgress }}%</span>
    </div>
    <div class="thinking-content">
      <div v-for="(log, index) in scanLogs" :key="index" class="thinking-line">
        <span class="thinking-marker">●</span>
        <span>{{ log.message }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  isScanning: Boolean,
  scanProgress: Number,
  scanLogs: Array
})
</script>

<style scoped>
.thinking-container {
  background: #f8f9fa;
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 10px;
}
.thinking-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid #e9ecef;
}
.thinking-icon {
  font-size: 18px;
}
.progress-badge {
  margin-left: auto;
  background: #409eff;
  color: white;
  padding: 2px 8px;
  border-radius: 20px;
  font-size: 11px;
}
.thinking-content {
  font-size: 13px;
  color: #555;
  line-height: 1.6;
}
.thinking-line {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-bottom: 6px;
  padding: 4px 0;
}
.thinking-marker {
  color: #409eff;
  font-size: 10px;
  flex-shrink: 0;
}
</style>