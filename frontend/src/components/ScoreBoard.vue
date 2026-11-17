<!--
@file ScoreBoard.vue
@description 评估得分面板
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="scoreboard-container">
    <div class="sb-header">
      <span class="sb-icon">🏆</span>
      <span>红蓝对抗计分板</span>
      <span v-if="winner" class="sb-winner-badge" :class="winner">
        {{ winner === 'red' ? '🔴 红队胜' : winner === 'blue' ? '🔵 蓝队胜' : '🤝 平局' }}
      </span>
    </div>

    <div class="scoreboard">
      <div class="team red">
        <div class="team-icon">🔴</div>
        <div class="team-name">红队 (攻击)</div>
        <div class="score">{{ redScore }}</div>
        <div class="score-label">攻击成功次数</div>
      </div>
      <div class="vs-divider">
        <div class="vs-text">VS</div>
        <div class="round-info" v-if="roundsCompleted">第 {{ roundsCompleted }} 回合</div>
      </div>
      <div class="team blue">
        <div class="team-icon">🔵</div>
        <div class="team-name">蓝队 (防御)</div>
        <div class="score">{{ blueScore }}</div>
        <div class="score-label">防御成功次数</div>
      </div>
    </div>

    <!-- 回合记录 -->
    <div class="rounds-list" v-if="rounds.length">
      <div class="rounds-title">📋 回合记录</div>
      <div v-for="r in rounds" :key="r.round" class="round-row">
        <div class="round-header">
          <span class="round-num">第 {{ r.round }} 回合</span>
          <span class="round-winner" :class="r.winner_this_round">
            {{ r.winner_this_round === 'red' ? '🔴 红队' : r.winner_this_round === 'blue' ? '🔵 蓝队' : '🤝 平局' }}
          </span>
        </div>
        <div class="round-score">
          <span class="rs-red">红 {{ r.red_score_this_round }}</span>
          <span class="rs-sep">:</span>
          <span class="rs-blue">蓝 {{ r.blue_score_this_round }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  redScore: { type: Number, default: 0 },
  blueScore: { type: Number, default: 0 },
  roundsCompleted: { type: Number, default: 0 },
  winner: { type: String, default: '' },
  rounds: { type: Array, default: () => [] }
})
</script>

<style scoped>
.scoreboard-container { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-radius: 12px; padding: 20px; color: #e0e0e0; margin-bottom: 16px; }
.sb-header { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; }
.sb-icon { font-size: 22px; }
.sb-winner-badge { margin-left: auto; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
.sb-winner-badge.red { background: rgba(244,67,54,0.2); color: #f44336; border: 1px solid #f44336; }
.sb-winner-badge.blue { background: rgba(33,150,243,0.2); color: #2196f3; border: 1px solid #2196f3; }
.sb-winner-badge.draw { background: rgba(255,193,7,0.2); color: #ffc107; border: 1px solid #ffc107; }
.scoreboard { display: flex; align-items: center; justify-content: center; gap: 30px; padding: 20px 0; }
.team { text-align: center; flex: 1; }
.team-icon { font-size: 36px; margin-bottom: 8px; }
.team-name { font-size: 13px; color: #888; margin-bottom: 8px; }
.score { font-size: 48px; font-weight: 800; }
.team.red .score { color: #f44336; }
.team.blue .score { color: #2196f3; }
.score-label { font-size: 11px; color: #555; margin-top: 4px; }
.vs-divider { display: flex; flex-direction: column; align-items: center; gap: 8px; }
.vs-text { font-size: 20px; font-weight: 800; color: #666; }
.round-info { font-size: 11px; color: #555; }
.rounds-list { margin-top: 16px; padding-top: 12px; border-top: 1px solid #2a2a4a; }
.rounds-title { font-size: 12px; color: #888; margin-bottom: 10px; }
.round-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #16213e; border-radius: 6px; margin-bottom: 6px; }
.round-header { display: flex; align-items: center; gap: 10px; }
.round-num { font-size: 13px; color: #ccc; }
.round-winner { font-size: 11px; }
.round-winner.red { color: #f44336; }
.round-winner.blue { color: #2196f3; }
.round-score { font-size: 14px; font-weight: 600; }
.rs-red { color: #f44336; }
.rs-blue { color: #2196f3; }
.rs-sep { color: #555; margin: 0 4px; }
</style>