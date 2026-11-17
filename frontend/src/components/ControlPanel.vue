<!--
@file ControlPanel.vue
@description 控制面板（开始/清除/导出按钮）
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="control-panel">
    <button @click="$emit('startScan')" :disabled="isScanning" class="scan-btn">
      <span v-if="!isScanning">🚀 开始漏洞扫描</span>
      <span v-else>
        <span class="spinner"></span>
        扫描中... {{ scanProgress }}%
      </span>
    </button>
    <button @click="$emit('clearHistory')" class="clear-btn" v-if="historyList.length > 0">
      🗑️ 清空历史
    </button>
    <button @click="$emit('exportReport')" class="export-btn" v-if="aiReport && !isScanning && aiReport !== '点击&quot;开始漏洞扫描&quot;，AI分析报告将显示在这里...'">
      📄 一键导出报告
    </button>
  </div>
</template>

<script setup>
defineProps({
  isScanning: Boolean,
  scanProgress: Number,
  historyList: Array,
  aiReport: String
})
defineEmits(['startScan', 'clearHistory', 'exportReport'])
</script>

<style scoped>
.control-panel {
  padding: 30px;
  text-align: center;
  background: #f8f9fa;
}
</style>