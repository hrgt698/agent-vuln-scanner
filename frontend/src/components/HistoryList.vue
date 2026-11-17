<!--
@file HistoryList.vue
@description 历史记录列表
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="history-section" v-if="historyList.length > 0">
    <h3>
      📜 历史扫描记录
      <span class="history-count">共 {{ historyList.length }} 次</span>
    </h3>
    <div class="history-list">
      <div v-for="(record, index) in historyList" :key="index" class="history-item">
        <div class="history-header">
          <span class="history-time">🕐 {{ record.time }}</span>
          <span class="history-result" :class="record.successCount > 0 ? 'success' : 'failed'">
            {{ record.successCount }}/{{ record.totalCount }} 漏洞利用成功
          </span>
          <button @click="viewHistoryDetail(record)" class="view-detail-btn">查看详情</button>
        </div>
        <div class="history-summary" v-if="selectedHistory === index">
          <div class="history-detail">
            <div v-for="(result, idx) in record.results" :key="idx" class="history-vuln">
              <span>{{ result.status === 'success' ? '✅' : '❌' }}</span>
              <strong>{{ result.vuln_name || result.cve_id }}</strong>
              <span v-if="result.leaked_data" class="flag-preview">
                FLAG: {{ result.leaked_data }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const props = defineProps({
  historyList: Array
})

const selectedHistory = ref(null)

const viewHistoryDetail = (record) => {
  const idx = props.historyList.indexOf(record)
  selectedHistory.value = selectedHistory.value === idx ? null : idx
}
</script>

<style scoped>
.history-section {
  padding: 0 30px 30px 30px;
  background: #f8f9fa;
  border-top: 1px solid #e9ecef;
}
.history-section h3 {
  margin-bottom: 15px;
  color: #333;
  font-size: 18px;
}
.history-count {
  font-size: 12px;
  color: #909399;
  margin-left: 10px;
  font-weight: normal;
}
.history-list {
  max-height: 300px;
  overflow-y: auto;
}
.history-item {
  background: white;
  border: 1px solid #e9ecef;
  border-radius: 8px;
  padding: 12px 15px;
  margin-bottom: 10px;
}
.history-header {
  display: flex;
  align-items: center;
  gap: 15px;
  flex-wrap: wrap;
}
.history-time {
  font-size: 13px;
  color: #909399;
}
.view-detail-btn {
  background: #409eff;
  border: none;
  color: white;
  padding: 4px 12px;
  border-radius: 4px;
  cursor: pointer;
}
.history-summary {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px dashed #e9ecef;
}
.history-detail {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.history-vuln {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
  flex-wrap: wrap;
}
.flag-preview {
  font-size: 11px;
  color: #e6a23c;
  background: #fdf6ec;
  padding: 2px 6px;
  border-radius: 4px;
}
.history-result.success {
  color: #67c23a;
  background: #e8f8e8;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 12px;
}
.history-result.failed {
  color: #f56c6c;
  background: #fef0f0;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 12px;
}
</style>