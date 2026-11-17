<!--
@file IntroPage.vue
@description 平台介绍页（含模型切换与系统状态）
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="intro-container">
    <div class="intro-card">
      <h2>🛡️ 平台简介</h2>
      <p>本平台是一个基于 AgentBench 框架的自主决策型智能体安全评估平台，专注于对 AI Agent 应用进行自动化漏洞扫描与风险评估。</p>
    </div>

    <div class="intro-card">
      <h3>🎯 核心功能</h3>
      <ul>
        <li>✅ <strong>自动化漏洞扫描</strong> - 一键扫描多个高危漏洞</li>
        <li>✅ <strong>AI 智能研判</strong> - 基于大模型生成专业的安全分析报告</li>
        <li>✅ <strong>可视化雷达图</strong> - 直观展示漏洞风险分布</li>
        <li>✅ <strong>实时扫描日志</strong> - 边扫描边输出详细过程</li>
        <li>✅ <strong>历史记录管理</strong> - 保存扫描历史，支持查看详情</li>
        <li>✅ <strong>报告导出</strong> - 一键导出 Markdown 格式的安全评估报告</li>
        <li>✅ <strong>多模型并发对比</strong> - Turbo/Plus/Max/LongContext 并行研判，可视化评分</li>
        <li>✅ <strong>加权投票综合研判</strong> - 基于模型权重 + 延迟 + 报告长度的智能综合</li>
        <li>✅ <strong>一键演示模式</strong> - 无需 API Key 也可体验完整功能</li>
        <li>✅ <strong>三级智能回退</strong> - 主模型失败自动切换备用模型，最终降级到启发式</li>
      </ul>
    </div>

    <div class="intro-card">
      <h3>🔍 支持的漏洞类型</h3>
      <div class="vuln-list">
        <div class="vuln-item">
          <span class="badge high">高危</span>
          <strong>API未授权访问</strong>
          <span class="cve">CS0048</span>
          <p>未授权的API接口可被直接访问，泄露敏感配置信息</p>
        </div>
        <div class="vuln-item">
          <span class="badge critical">严重</span>
          <strong>系统命令注入</strong>
          <span class="cve">CWE-78</span>
          <p>用户输入未过滤，可执行任意系统命令</p>
        </div>
        <div class="vuln-item">
          <span class="badge high">高危</span>
          <strong>SQL注入</strong>
          <span class="cve">CWE-89</span>
          <p>SQL语句拼接，可绕过认证获取敏感数据</p>
        </div>
      </div>
    </div>

    <div class="intro-card">
      <h3>🤖 AI 模型选择</h3>
      <div class="model-selector">
        <label>当前使用的模型：</label>
        <select v-model="localSelectedModel" @change="handleSwitchModel" :disabled="isModelSwitching">
          <option v-for="(name, key) in availableModels" :key="key" :value="key">
            {{ name }}
          </option>
        </select>
        <span v-if="isModelSwitching" class="switching">切换中...</span>
      </div>
      <p class="model-desc">💡 不同模型的效果和速度不同，Turbo最快，Max最智能但稍慢</p>
    </div>

    <div class="intro-card">
      <h3>📊 系统状态</h3>
      <div class="status-info">
        <div class="status-item">
          <span class="status-label">后端状态：</span>
          <span :class="backendStatus ? 'status-ok' : 'status-error'">
            {{ backendStatus ? '✅ 已连接' : '❌ 未连接' }}
          </span>
        </div>
        <div class="status-item">
          <span class="status-label">靶机状态：</span>
          <span :class="targetStatus ? 'status-ok' : 'status-error'">
            {{ targetStatus ? '✅ 已启动' : '❌ 未启动' }}
          </span>
        </div>
        <div class="status-item">
          <span class="status-label">AI配置：</span>
          <span :class="apiConfigured ? 'status-ok' : 'status-warning'">
            {{ apiConfigured ? '✅ 已配置' : '⚠️ 未配置' }}
          </span>
        </div>
      </div>
    </div>

    <div class="intro-card">
      <h3>🚀 快速开始</h3>
      <ol>
        <li>确保靶机、后端服务均已启动</li>
        <li>点击上方「开始扫描」进入扫描页面</li>
        <li>点击「开始漏洞扫描」按钮</li>
        <li>观察实时日志，查看扫描过程</li>
        <li>等待扫描完成，查看 AI 智能研判报告</li>
        <li>点击「一键导出报告」保存评估结果</li>
      </ol>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useScanStore } from '@/stores/scanStore'
import { api } from '@/utils/api'

const scanStore = useScanStore()
const { availableModels, selectedModel, isModelSwitching, backendStatus, targetStatus, apiConfigured } = storeToRefs(scanStore)

const localSelectedModel = ref(selectedModel.value)

watch(selectedModel, (newVal) => {
  localSelectedModel.value = newVal
})

const handleSwitchModel = async () => {
  scanStore.isModelSwitching = true
  try {
    await api.switchModel(localSelectedModel.value)
    selectedModel.value = localSelectedModel.value
    scanStore.addLog(`已切换到模型: ${localSelectedModel.value}`)
  } catch (error) {
    console.error('切换模型失败:', error)
  } finally {
    scanStore.isModelSwitching = false
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
  box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}
.intro-card h2, .intro-card h3 {
  color: #667eea;
  margin-bottom: 15px;
}
.intro-card ul, .intro-card ol {
  margin-left: 20px;
  line-height: 1.8;
}
.vuln-list {
  display: flex;
  flex-direction: column;
  gap: 15px;
}
.vuln-item {
  background: white;
  border-radius: 12px;
  padding: 15px;
  border-left: 4px solid #667eea;
}
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: bold;
  margin-right: 10px;
}
.badge.high {
  background: #f56c6c;
  color: white;
}
.badge.critical {
  background: #e6a23c;
  color: white;
}
.cve {
  font-family: monospace;
  background: #f0f0f0;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 12px;
  margin-left: 10px;
}
.vuln-item p {
  margin-top: 8px;
  font-size: 13px;
  color: #666;
}
.model-selector {
  display: flex;
  align-items: center;
  gap: 15px;
  flex-wrap: wrap;
  margin-bottom: 15px;
}
.model-selector select {
  padding: 8px 15px;
  border-radius: 8px;
  border: 1px solid #ddd;
  font-size: 14px;
}
.model-desc {
  font-size: 12px;
  color: #909399;
}
.switching {
  color: #e6a23c;
  font-size: 12px;
}
</style>