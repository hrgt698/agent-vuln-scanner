<!--
@file NavBar.vue
@description 4 Tab 导航栏（介绍/扫描/演示/对比）
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="navbar">
    <button 
      @click="$emit('update:activeTab', 'intro')" 
      :class="{ active: activeTab === 'intro' }" 
      class="nav-btn">
      📖 平台介绍
    </button>
    <button 
      @click="$emit('update:activeTab', 'scan')" 
      :class="{ active: activeTab === 'scan' }" 
      class="nav-btn">
      🚀 漏洞扫描
    </button>
    <button 
      @click="$emit('update:activeTab', 'demo')" 
      :class="{ active: activeTab === 'demo' }" 
      class="nav-btn">
      🎭 一键演示
    </button>
    <button 
      @click="$emit('update:activeTab', 'compare')" 
      :class="{ active: activeTab === 'compare' }" 
      class="nav-btn">
      📊 模型对比
    </button>
  </div>
</template>

<script setup>
defineProps({
  activeTab: {
    type: String,
    default: 'intro'
  }
})
defineEmits(['update:activeTab'])
</script>

<style scoped>
.navbar {
  display: flex;
  justify-content: center;
  gap: 20px;
  padding: 15px;
  background: #f8f9fa;
  border-bottom: 1px solid #e9ecef;
  flex-wrap: wrap;
}
.nav-btn {
  padding: 10px 30px;
  font-size: 16px;
  border: none;
  background: transparent;
  cursor: pointer;
  border-radius: 25px;
  transition: all 0.3s;
}
.nav-btn.active {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
}
.nav-btn:hover:not(.active) {
  background: #e9ecef;
}
</style>