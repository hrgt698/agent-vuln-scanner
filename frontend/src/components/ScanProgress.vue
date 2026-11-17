<!--
@file ScanProgress.vue
@description 扫描进度与状态
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="progress-section" v-if="isVisible">
    <div class="progress-bar-container">
      <div class="progress-bar" :style="{ width: progress + '%' }">
        <span class="progress-text">{{ progress }}%</span>
      </div>
    </div>
    <div class="progress-status">{{ statusText }}</div>
  </div>
</template>

<script setup>
defineProps({
  isVisible: {
    type: Boolean,
    default: false
  },
  progress: {
    type: Number,
    default: 0
  },
  statusText: {
    type: String,
    default: ''
  }
})
</script>

<style scoped>
.progress-section {
  padding: 0 30px 20px 30px;
  background: #f8f9fa;
}
.progress-bar-container {
  background: #e9ecef;
  border-radius: 10px;
  height: 30px;
}
.progress-bar {
  background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
  height: 100%;
  transition: width 0.3s;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  padding-right: 10px;
  border-radius: 10px;
}
.progress-text {
  color: white;
  font-size: 12px;
}
.progress-status {
  text-align: center;
  margin-top: 8px;
  font-size: 12px;
  color: #666;
}
</style>
