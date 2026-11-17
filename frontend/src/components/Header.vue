<!--
@file Header.vue
@description 顶部标题栏组件
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="header">
    <h1>
      <span class="icon">🛡️</span>
      自主决策型智能体安全评估平台
    </h1>
    <div class="subtitle">基于 AgentBench 的自动化漏洞扫描与智能研判系统</div>
  </div>
</template>

<style scoped>
.header {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 30px;
  text-align: center;
}
.header h1 {
  font-size: 28px;
  margin-bottom: 10px;
}
.icon {
  margin-right: 10px;
}
.subtitle {
  opacity: 0.9;
  font-size: 14px;
}
</style>