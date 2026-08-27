import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

const SESSION_KEY = 'sc-sentinel-demo-session'
const DEMO_USERNAME = import.meta.env.VITE_DEMO_LOGIN_USERNAME || 'sentinel-demo'
const DEMO_PASSWORD = import.meta.env.VITE_DEMO_LOGIN_PASSWORD || 'sentinel2026'

interface DemoSession {
  username: string
  loggedInAt: string
}

function loadSession(): DemoSession | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY)
    return raw ? JSON.parse(raw) as DemoSession : null
  } catch {
    return null
  }
}

export const useAuthStore = defineStore('auth', () => {
  const session = ref<DemoSession | null>(loadSession())
  const isAuthenticated = computed(() => session.value !== null)
  const displayName = computed(() => session.value?.username || '')

  function login(username: string, password: string) {
    if (username.trim() !== DEMO_USERNAME || password !== DEMO_PASSWORD) {
      return { ok: false, message: '账号或密码不正确，请使用默认演示账号。' }
    }
    session.value = { username: username.trim(), loggedInAt: new Date().toISOString() }
    localStorage.setItem(SESSION_KEY, JSON.stringify(session.value))
    return { ok: true }
  }

  function logout() {
    session.value = null
    localStorage.removeItem(SESSION_KEY)
  }

  return { isAuthenticated, displayName, login, logout }
})
