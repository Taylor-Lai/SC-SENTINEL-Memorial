import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
      meta: { title: 'SC-SENTINEL｜安全登录', public: true, hideNavbar: true }
    },
    {
      path: '/',
      name: 'home',
      component: () => import('@/views/HomeView.vue'),
      meta: { title: 'SC-SENTINEL｜软件供应链审计平台' }
    },
    {
      path: '/submit',
      name: 'submit',
      component: () => import('@/views/SubmitView.vue'),
      meta: { title: 'SC-SENTINEL｜新建审计' }
    },
    {
      path: '/tasks/:id/monitor',
      name: 'monitor',
      component: () => import('@/views/MonitorView.vue'),
      meta: { title: 'SC-SENTINEL｜实时监控' }
    },
    {
      path: '/tasks/:id/report',
      name: 'report',
      component: () => import('@/views/ReportView.vue'),
      meta: { title: 'SC-SENTINEL｜审计报告' }
    },
    {
      path: '/history',
      name: 'history',
      component: () => import('@/views/HistoryView.vue'),
      meta: { title: 'SC-SENTINEL｜任务中心' }
    },
    // 404 回退
    {
      path: '/:pathMatch(.*)*',
      redirect: '/'
    }
  ],
  scrollBehavior(_to, _from, savedPosition) {
    if (savedPosition) return savedPosition
    return { top: 0, behavior: 'smooth' }
  }
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.isAuthenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  if (to.name === 'login' && auth.isAuthenticated) {
    return { path: typeof to.query.redirect === 'string' ? to.query.redirect : '/' }
  }
  return true
})

router.afterEach((to) => {
  if (to.meta.title) {
    document.title = to.meta.title as string
  }
})

export default router
