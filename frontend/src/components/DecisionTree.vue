<!--
@file DecisionTree.vue
@description Agent 决策轨迹时间线
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="decision-tree-container">
    <div class="tree-header">
      <span class="tree-icon">🧠</span>
      <span>Agent 决策轨迹</span>
      <span class="badge">{{ totalSteps }} 步决策</span>
      <span class="badge reward" v-if="totalReward !== 0">{{ totalReward.toFixed(1) }} 总奖励</span>
    </div>

    <div v-if="!treeData" class="empty-state">
      <div class="empty-icon">🤖</div>
      <div class="empty-text">暂无决策数据，请先执行扫描</div>
    </div>

    <!-- 时间线模式展示 -->
    <div v-else class="timeline">
      <div v-for="node in treeNodes" :key="node.node_id"
           class="timeline-node"
           :class="{'failed': node.error, 'success': node.reward > 0}">
        <div class="tl-marker">
          <div class="tl-dot"></div>
          <div class="tl-line"></div>
        </div>
        <div class="tl-content">
          <div class="tl-step">Step {{ node.step }}</div>
          <div class="tl-action">{{ node.action }}</div>
          <div class="tl-thought" v-if="node.thought">💭 {{ node.thought }}</div>
          <div class="tl-tools" v-if="node.tools && node.tools.length">
            <span v-for="t in node.tools" :key="t" class="tool-tag">🔧 {{ t }}</span>
          </div>
          <div class="tl-stats">
            <span class="tl-reward">奖励: {{ node.reward.toFixed(2) }}</span>
            <span class="tl-confidence" v-if="node.confidence">置信度: {{ (node.confidence * 100).toFixed(0) }}%</span>
          </div>
          <div class="tl-error" v-if="node.error">❌ {{ node.error }}</div>
        </div>
      </div>
    </div>

    <!-- 统计摘要 -->
    <div v-if="treeData" class="tree-summary">
      <div class="summary-item">
        <span class="summary-label">总步数</span>
        <span class="summary-value">{{ treeData.total_steps }}</span>
      </div>
      <div class="summary-item">
        <span class="summary-label">总奖励</span>
        <span class="summary-value" :style="{color: treeData.total_reward >= 0 ? '#4caf50' : '#f44336'}">
          {{ treeData.total_reward.toFixed(1) }}
        </span>
      </div>
      <div class="summary-item">
        <span class="summary-label">成功</span>
        <span class="summary-value success">{{ treeData.successful_actions }}</span>
      </div>
      <div class="summary-item">
        <span class="summary-label">失败</span>
        <span class="summary-value failed">{{ treeData.failed_actions }}</span>
      </div>
      <div class="summary-item">
        <span class="summary-label">耗时</span>
        <span class="summary-value">{{ treeData.duration_seconds?.toFixed(1) }}s</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  treeData: { type: Object, default: null }
})

const treeNodes = computed(() => {
  if (!props.treeData?.nodes) return []
  return [...props.treeData.nodes].sort((a, b) => a.step - b.step).filter(n => n.step > 0)
})

const totalSteps = computed(() => props.treeData?.total_steps || 0)
const totalReward = computed(() => props.treeData?.total_reward || 0)
</script>

<style scoped>
.decision-tree-container { background: #1a1a2e; border-radius: 12px; padding: 20px; color: #e0e0e0; margin-bottom: 16px; }
.tree-header { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
.tree-icon { font-size: 22px; }
.badge { background: #16213e; border: 1px solid #333; padding: 2px 10px; border-radius: 20px; font-size: 11px; color: #aaa; }
.badge.reward { background: #0f3460; border-color: #1a5276; color: #90caf9; }
.empty-state { text-align: center; padding: 30px; color: #666; }
.empty-icon { font-size: 40px; margin-bottom: 10px; }
.empty-text { font-size: 13px; }
.timeline { position: relative; padding-left: 28px; }
.timeline-node { display: flex; gap: 12px; margin-bottom: 14px; cursor: default; }
.tl-marker { display: flex; flex-direction: column; align-items: center; width: 16px; }
.tl-dot { width: 10px; height: 10px; border-radius: 50%; background: #4a4a8a; flex-shrink: 0; margin-top: 4px; }
.success .tl-dot { background: #4caf50; box-shadow: 0 0 6px rgba(76,175,80,0.5); }
.failed .tl-dot { background: #f44336; box-shadow: 0 0 6px rgba(244,67,54,0.5); }
.tl-line { width: 2px; flex: 1; background: #2a2a4a; min-height: 10px; }
.timeline-node:last-child .tl-line { display: none; }
.tl-content { background: #16213e; border-radius: 8px; padding: 10px 14px; flex: 1; border: 1px solid #2a2a4a; }
.tl-step { font-size: 10px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
.tl-action { font-size: 14px; font-weight: 600; margin: 4px 0; color: #4fc3f7; word-break: break-all; }
.tl-thought { font-size: 12px; color: #888; margin: 4px 0; font-style: italic; }
.tool-tag { display: inline-block; background: #0f3460; border-radius: 4px; padding: 1px 6px; font-size: 10px; margin: 2px 4px 2px 0; color: #90caf9; }
.tl-stats { display: flex; gap: 16px; margin-top: 6px; font-size: 11px; color: #666; }
.tl-error { font-size: 11px; color: #f44336; margin-top: 4px; }
.tree-summary { display: flex; gap: 16px; margin-top: 16px; padding-top: 12px; border-top: 1px solid #2a2a4a; flex-wrap: wrap; }
.summary-item { display: flex; flex-direction: column; align-items: center; min-width: 50px; }
.summary-label { font-size: 10px; color: #666; }
.summary-value { font-size: 16px; font-weight: 700; color: #e0e0e0; }
.summary-value.success { color: #4caf50; }
.summary-value.failed { color: #f44336; }
</style>