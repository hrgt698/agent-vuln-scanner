<!--
@file RadarChart.vue
@description 风险雷达图可视化
@author hrgt698
@version 3.3.0
@since 2026-06-18
-->
<template>
  <div class="radar-container" ref="containerRef">
    <h4 class="radar-title">🛡️ 漏洞风险雷达图</h4>
    <div ref="chartRef" class="chart-wrapper" />
    <div v-if="!hasData" class="empty-hint">暂无扫描数据</div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import * as echarts from 'echarts'

const chartRef = ref(null)
const containerRef = ref(null)
const hasData = ref(false)
let chartInstance = null

const updateRadarChart = (results = []) => {
  hasData.value = results.length > 0
  if (!chartInstance || !hasData.value) return

  // 构建雷达图指标数据
  const indicators = buildIndicators(results)
  const seriesData = buildSeriesData(results, indicators)

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: 'rgba(50, 50, 50, 0.9)',
      borderColor: '#667eea',
      textStyle: { color: '#fff' }
    },
    legend: {
      data: ['风险分布', '攻击面'],
      bottom: 0,
      textStyle: { color: '#666' }
    },
    radar: {
      indicator: indicators,
      shape: 'polygon',
      splitNumber: 4,
      axisName: {
        color: '#667eea',
        fontSize: 12
      },
      splitLine: {
        lineStyle: { color: 'rgba(102, 126, 234, 0.2)' }
      },
      splitArea: {
        areaStyle: { color: ['rgba(102,126,234,0.05)', 'rgba(102,126,234,0.1)'] }
      },
      axisLine: { lineStyle: { color: 'rgba(102, 126, 234, 0.3)' } }
    },
    series: [{
      type: 'radar',
      data: seriesData,
      emphasis: {
        lineStyle: { width: 4 },
        areaStyle: { opacity: 0.4 }
      }
    }]
  }

  chartInstance.setOption(option, true)
}

const buildIndicators = (results) => {
  const cveMap = {}
  for (const r of results) {
    const cve = r.cve_id || '未知'
    if (!cveMap[cve]) cveMap[cve] = { count: 0, success: 0 }
    cveMap[cve].count++
    if (r.status === 'success') cveMap[cve].success++
  }

  const names = {
    'CS0048': 'API未授权',
    'CWE-89': 'SQL注入',
    'CWE-78': '命令注入',
    'AML.T0051': '提示词注入'
  }

  return Object.entries(cveMap).map(([cve, data]) => ({
    name: names[cve] || cve,
    max: Math.max(data.count * 2, 5)
  }))
}

const buildSeriesData = (results, indicators) => {
  const successByType = {}
  const totalByType = {}
  const names = {
    'CS0048': 'API未授权',
    'CWE-89': 'SQL注入',
    'CWE-78': '命令注入',
    'AML.T0051': '提示词注入'
  }

  for (const r of results) {
    const cve = r.cve_id || '未知'
    const name = names[cve] || cve
    totalByType[name] = (totalByType[name] || 0) + 1
    if (r.status === 'success') successByType[name] = (successByType[name] || 0) + 1
  }

  const riskData = indicators.map(ind => {
    const total = totalByType[ind.name] || 0
    const success = successByType[ind.name] || 0
    // 风险得分：利用成功率 × 权重
    return total > 0 ? Math.round((success / total) * ind.max * 0.8 + total * 0.5) : 0
  })

  const attackData = indicators.map(ind => {
    return totalByType[ind.name] || 0
  })

  return [
    {
      value: riskData,
      name: '风险分布',
      lineStyle: { color: '#f56c6c' },
      areaStyle: { color: 'rgba(245, 108, 108, 0.3)' },
      itemStyle: { color: '#f56c6c' }
    },
    {
      value: attackData,
      name: '攻击面',
      lineStyle: { color: '#67c23a' },
      areaStyle: { color: 'rgba(103, 194, 58, 0.3)' },
      itemStyle: { color: '#67c23a' }
    }
  ]
}

const initChart = () => {
  if (!chartRef.value) return
  chartInstance = echarts.init(chartRef.value, null, { renderer: 'canvas' })

  // 默认空图表
  const emptyOption = {
    backgroundColor: 'transparent',
    title: {
      text: '等待扫描数据...',
      left: 'center',
      top: 'center',
      textStyle: { color: '#ccc', fontSize: 14 }
    },
    radar: {
      indicator: [
        { name: 'API未授权', max: 5 },
        { name: 'SQL注入', max: 5 },
        { name: '命令注入', max: 5 },
        { name: '提示词注入', max: 5 }
      ]
    },
    series: [{
      type: 'radar',
      data: []
    }]
  }
  chartInstance.setOption(emptyOption)
}

const handleResize = () => {
  chartInstance?.resize()
}

onMounted(async () => {
  await nextTick()
  initChart()
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
  chartInstance?.dispose()
  chartInstance = null
})

defineExpose({ updateRadarChart })
</script>

<style scoped>
.radar-container {
  background: white;
  border-radius: 12px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.08);
  padding: 20px;
  min-width: 380px;
  min-height: 400px;
  position: relative;
}
.radar-title {
  margin-bottom: 15px;
  color: #333;
  font-size: 16px;
  text-align: center;
}
.chart-wrapper {
  width: 100%;
  height: 340px;
}
.empty-hint {
  position: absolute;
  top: 60px;
  left: 0;
  right: 0;
  text-align: center;
  color: #ccc;
  font-size: 14px;
  pointer-events: none;
}
</style>
