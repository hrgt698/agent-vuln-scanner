<!--
@file AdversarialPanel.vue
@description 红蓝对抗控制面板
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="adversarial-panel">
    <div class="panel-header">
      <span class="panel-icon">⚔️</span>
      <span>红蓝对抗模式</span>
      <span class="panel-badge">NEW</span>
    </div>

    <div class="panel-description">
      红队 Agent 自适应调整攻击策略，蓝队 Agent 动态学习防御规则。每轮自动评分。
    </div>

    <!-- 控制按钮 -->
    <div class="control-row">
      <button class="btn-start" @click="$emit('startGame')"
              :disabled="isRunning">
        {{ isRunning ? '⏳ 推演中...' : '🚀 开始对抗推演' }}
      </button>
      <div class="config-row">
        <label>
          <span class="config-label">回合数</span>
          <select v-model="localRounds" @change="$emit('update:rounds', Number(localRounds))">
            <option :value="3">3 回合</option>
            <option :value="5">5 回合</option>
            <option :value="10">10 回合</option>
          </select>
        </label>
        <label>
          <span class="config-label">每轮攻击</span>
          <select v-model="localAttempts" @change="$emit('update:attempts', Number(localAttempts))">
            <option :value="3">3 次</option>
            <option :value="5">5 次</option>
            <option :value="7">7 次</option>
          </select>
        </label>
      </div>
    </div>

    <ScoreBoard
      :redScore="redScore"
      :blueScore="blueScore"
      :roundsCompleted="roundsCompleted"
      :winner="winner"
      :rounds="roundRecords"
    />

    <!-- 实时事件流 -->
    <div class="event-stream" v-if="events.length">
      <div class="event-title">📡 实时攻击记录</div>
      <div v-for="(evt, idx) in visibleEvents" :key="idx" class="event-row">
        <span class="evt-icon">{{ evt.red_won ? '⚔️' : '🛡️' }}</span>
        <span class="evt-cve">{{ evt.cve }}</span>
        <span class="evt-strategy" :title="evt.payload_preview">{{ evt.strategy }}</span>
        <span class="evt-result" :class="evt.red_won ? 'red-win' : 'blue-win'">
          {{ evt.red_won ? '红队突破' : '蓝队拦截' }}
        </span>
      </div>
    </div>

    <!-- 对抗总结 -->
    <div v-if="summary" class="summary-box">
      <div class="summary-title">📊 博弈总结</div>
      <pre class="summary-text">{{ summary }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import ScoreBoard from './ScoreBoard.vue'

const props = defineProps({
  isRunning: Boolean,
  redScore: { type: Number, default: 0 },
  blueScore: { type: Number, default: 0 },
  roundsCompleted: { type: Number, default: 0 },
  winner: { type: String, default: '' },
  roundRecords: { type: Array, default: () => [] },
  events: { type: Array, default: () => [] },
  summary: { type: String, default: '' },
  rounds: { type: Number, default: 5 },
  attempts: { type: Number, default: 5 }
})

defineEmits(['startGame', 'update:rounds', 'update:attempts'])

const localRounds = ref(props.rounds)
const localAttempts = ref(props.attempts)
const maxVisibleEvents = 20

const visibleEvents = computed(() => props.events.slice(-maxVisibleEvents))
</script>

<style scoped>
.adversarial-panel { background: #0a0a1a; border: 1px solid #2a2a4a; border-radius: 12px; padding: 20px; color: #e0e0e0; margin-bottom: 16px; }
.panel-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.panel-icon { font-size: 22px; }
.panel-badge { background: linear-gradient(135deg, #667eea, #764ba2); padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; color: white; margin-left: auto; }
.panel-description { font-size: 12px; color: #888; margin-bottom: 16px; }
.control-row { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
.btn-start { background: linear-gradient(135deg, #667eea, #764ba2); border: none; padding: 10px 20px; border-radius: 8px; color: white; font-size: 14px; cursor: pointer; transition: opacity 0.2s; }
.btn-start:disabled { opacity: 0.5; cursor: not-allowed; }
.config-row { display: flex; gap: 12px; margin-left: auto; }
.config-label { display: block; font-size: 10px; color: #666; margin-bottom: 2px; }
.config-row select { background: #16213e; border: 1px solid #333; color: #ccc; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
.event-stream { margin-top: 12px; padding: 12px; background: #111; border-radius: 8px; max-height: 300px; overflow-y: auto; }
.event-title { font-size: 12px; color: #888; margin-bottom: 8px; }
.event-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 12px; border-bottom: 1px solid #1a1a2e; }
.evt-icon { font-size: 14px; }
.evt-cve { background: #16213e; padding: 1px 6px; border-radius: 4px; font-size: 10px; color: #90caf9; min-width: 60px; }
.evt-strategy { flex: 1; color: #aaa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.evt-result { font-size: 11px; padding: 2px 8px; border-radius: 4px; white-space: nowrap; }
.evt-result.red-win { background: rgba(244,67,54,0.2); color: #f44336; }
.evt-result.blue-win { background: rgba(33,150,243,0.2); color: #2196f3; }
.summary-box { margin-top: 12px; padding: 12px; background: #16213e; border-radius: 8px; }
.summary-title { font-size: 12px; color: #888; margin-bottom: 8px; }
.summary-text { font-size: 12px; color: #ccc; line-height: 1.6; white-space: pre-wrap; font-family: inherit; margin: 0; }
</style>