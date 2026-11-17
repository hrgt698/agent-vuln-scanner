import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'dashboard',
      component: () => import('@/components/IntroPage.vue'),
      meta: { title: '首页' },
    },
    {
      path: '/scan',
      name: 'scan',
      component: () => import('@/components/ScanPage.vue'),
      meta: { title: '漏洞扫描' },
    },
    {
      path: '/demo',
      name: 'demo',
      component: () => import('@/components/DemoPage.vue'),
      meta: { title: 'Demo 演示' },
    },
    {
      path: '/compare',
      name: 'compare',
      component: () => import('@/components/ModelComparePage.vue'),
      meta: { title: '多模型对比' },
    },
  ],
})

router.beforeEach((to, _from, next) => {
  document.title = to.meta.title || '自主决策型智能体安全评估平台'
  next()
})

export default router