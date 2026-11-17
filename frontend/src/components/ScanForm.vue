<!--
@file ScanForm.vue
@description 扫描表单（漏洞选择/模型选择）
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="model-bar">
    <span class="model-label">🤖 AI 研判模型：</span>
    <select
      v-model="localSelectedModel"
      @change="handleSwitchModel"
      :disabled="isModelSwitching"
      class="model-select"
    >
      <option v-for="(name, key) in availableModels" :key="key" :value="key">
        {{ name }}
      </option>
    </select>
    <span v-if="isModelSwitching" class="switching-tag">切换中...</span>
    <span class="model-hint">💡 不同模型影响报告质量</span>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useScanStore } from '@/stores/scanStore'
import { api } from '@/utils/api'

const props = defineProps({
  availableModels: {
    type: Object,
    default: () => ({})
  },
  selectedModel: {
    type: String,
    default: 'qwen-turbo'
  }
})

const emit = defineEmits(['model-changed'])

const scanStore = useScanStore()
const { isModelSwitching } = storeToRefs(scanStore)

const localSelectedModel = ref(props.selectedModel)

const handleSwitchModel = async () => {
  scanStore.isModelSwitching = true
  try {
    await api.switchModel(localSelectedModel.value)
    emit('model-changed', localSelectedModel.value)
    scanStore.addLog(`已切换到模型: ${localSelectedModel.value}`)
  } catch (error) {
    console.error('切换模型失败:', error)
  } finally {
    scanStore.isModelSwitching = false
  }
}

watch(() => props.selectedModel, (newVal) => {
  localSelectedModel.value = newVal
})
</script>

<style scoped>
.model-bar {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 15px;
  padding: 15px 30px;
  background: #f8f9fa;
  border-bottom: 1px solid #e9ecef;
}
.model-select {
  padding: 6px 12px;
  border-radius: 6px;
  border: 1px solid #ddd;
}
.switching-tag {
  color: #e6a23c;
  font-size: 12px;
}
.model-hint {
  font-size: 12px;
  color: #909399;
}
</style>
