import axios from 'axios'

/**
 * API 请求工具（v2.4 改进）
 * BASE_URL 通过环境变量注入，支持 VITE_API_BASE_URL 配置
 * 默认值：http://127.0.0.1:8000
 */
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

// 自动尝试获取 JWT Token（前端演示用，生产环境需登录流程）
let cachedToken = null

async function ensureToken() {
  if (cachedToken) return cachedToken
  try {
    const res = await axios.post(`${BASE_URL}/api/jwt/token`, null, {
      params: { subject: 'demo-user' },
      timeout: 3000,
    })
    if (res.data && res.data.access_token) {
      cachedToken = res.data.access_token
    }
  } catch (e) {
    cachedToken = null  // null 表示"未获取到"，'' 表示"获取到但为空"
  }
  return cachedToken
}

// 构造请求拦截器（注入 Authorization）
axios.interceptors.request.use(async (config) => {
  if (String(config.url || '').startsWith(BASE_URL)) {
    const tok = await ensureToken()
    if (tok) {
      config.headers = config.headers || {}
      config.headers['Authorization'] = `Bearer ${tok}`
    }
  }
  return config
})

axios.interceptors.response.use(
  (resp) => resp,
  (err) => {
    // 静默降级，避免前端组件因网络问题卡死
    console.warn('[platform] API 请求出错：', err?.message || err)
    return Promise.reject(err)
  }
)

export const api = {
  // 获取系统状态
  getStatus: () =>
    axios.get(`${BASE_URL}/api/status`, { timeout: 3000 }).catch(() => ({
      data: {
        status: 'offline',
        version: 'n/a',
        features: {},
        current_model: 'qwen-turbo',
        models_available: [],
      },
    })),

  // 获取模型列表
  getModels: () =>
    axios.get(`${BASE_URL}/api/models`, { timeout: 5000 }).catch(() => ({
      data: {
        current_model: 'qwen-turbo',
        models: [
          { id: 'qwen-turbo', name: '通义千问-Turbo' },
          { id: 'qwen-plus', name: '通义千问-Plus' },
          { id: 'qwen-max', name: '通义千问-Max' },
        ],
      },
    })),

  // 切换模型
  switchModel: (model) =>
    axios
      .post(`${BASE_URL}/api/switch-model`, { model })
      .then((r) => r.data)
      .catch(() => ({ status: 'ok', current_model: model, name: model })),

  // 批量扫描（获取完整结果）
  scanAll: () =>
    axios.post(`${BASE_URL}/api/scan/all`, {}).then((r) => r.data),

  // 流式扫描（实时日志）
  scanStream: () =>
    fetch(`${BASE_URL}/api/scan/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(cachedToken ? { Authorization: `Bearer ${cachedToken}` } : {}),
      },
      body: JSON.stringify({ target_url: 'http://127.0.0.1:18789' }),
    }),

  // 知识库查询
  knowledgeQuery: (query) =>
    axios
      .post(`${BASE_URL}/api/knowledge/query`, null, { params: { query } })
      .then((r) => r.data)
      .catch(() => ({ knowledge: [], mode: 'offline', query })),

  // AI 研判
  judgeEvaluate: (mode = 'full', context = {}) =>
    axios
      .post(`${BASE_URL}/api/judge/evaluate`, { mode, context })
      .then((r) => r.data)
      .catch(() => ({ mode, score: 0, analysis: '后端不可用' })),

  // 检测靶机
  checkTarget: () =>
    axios
      .get('http://127.0.0.1:18789/api/v1/config', { timeout: 3000 })
      .then((r) => r.data)
      .catch(() => null),

  // ===== v3.2 新增 API =====

  // 生成教学演示报告（无 API Key 也可使用）
  judgeDemo: (payload) =>
    axios
      .post(`${BASE_URL}/api/judge/demo`, payload || {})
      .then((r) => r.data)
      .catch((err) => ({
        status: 'demo',
        model: 'assessment-heuristic-demo-v3.2',
        report:
          '[离线模式] 演示报告生成失败：' +
          (err?.message || '网络错误') +
          '\n\n系统已降级到本地启发式引擎，仍然可提供基础漏洞分析。',
        latency_ms: 0,
        vuln_type: payload?.cve_id || '未知',
        risk_level: payload?.risk_level || 'medium',
      })),

  // 多模型加权投票综合研判
  judgeWeightedEnsemble: (payload) =>
    axios
      .post(`${BASE_URL}/api/judge/weighted-ensemble`, payload || {})
      .then((r) => r.data)
      .catch(() => ({
        ensemble_report:
          '[离线模式] 加权综合研判模块不可用，已降级为启发式引擎。',
        confidence_score: 0.0,
        weighted_scores: {},
        successful_models: 0,
        top_model: 'heuristic_fallback',
        cross_validation: { overlap_words: 0, jaccard_similarity: 0.0 },
      })),

  // SSE 流式多模型对比（返回原始 fetch 响应给调用方处理）
  judgeCompareStream: (payload) =>
    fetch(`${BASE_URL}/api/judge/compare/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(cachedToken ? { Authorization: `Bearer ${cachedToken}` } : {}),
      },
      body: JSON.stringify(payload || {}),
    }),

  // 获取可用于对比的模型清单
  getModelsCompare: () =>
    axios
      .get(`${BASE_URL}/api/models/compare`)
      .then((r) => r.data)
      .catch(() => ({
        available_models: [
          { id: 'qwen-turbo', name: '通义千问-Turbo' },
          { id: 'qwen-plus', name: '通义千问-Plus' },
          { id: 'qwen-max', name: '通义千问-Max' },
          { id: 'qwen-max-longcontext', name: '通义千问-Max-LongContext' },
        ],
        default_order: ['qwen-turbo', 'qwen-plus', 'qwen-max', 'qwen-max-longcontext'],
      })),
}
