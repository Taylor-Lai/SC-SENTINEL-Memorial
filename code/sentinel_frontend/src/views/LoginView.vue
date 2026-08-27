<template>
  <div class="login-page">
    <div class="login-orb orb-one" /><div class="login-orb orb-two" />
    <section class="login-shell">
      <div class="brand-panel">
        <RouterLink to="/" class="brand"><span class="brand-mark"><svg width="24" height="24" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 1.5L14 5V11L8 14.5L2 11V5L8 1.5Z" stroke="white" stroke-width="1.1" /><path d="M8 4.5L11.5 6.5V10.5L8 12.5L4.5 10.5V6.5L8 4.5Z" fill="white" opacity=".5" /><circle cx="8" cy="8.5" r="1.8" fill="white" /></svg></span><span>SC-SENTINEL</span></RouterLink>
        <div class="brand-copy"><div class="eyebrow"><span class="pulse-dot" />安全审计工作台</div><h1>让每一个<br /><em>漏洞结论</em>都有证据。</h1><p>面向 C/C++ 开源软件供应链的多智能体二进制漏洞检测与动态验证系统。</p></div>
        <div class="stage-list"><span><b>01—04</b> 依赖情报 · 语义切片 · 假设 · 约束审计</span><span><b>05—07</b> Harness · 动态证据 · 风险裁决</span></div>
      </div>
      <div class="login-card-wrap">
        <form class="login-card" @submit.prevent="submit">
          <div class="form-head"><div class="form-kicker">安全访问</div><h2>进入审计控制台</h2><p>登录后可提交项目、查看实时验证进度及导出报告。</p></div>
          <label class="field"><span>演示账号</span><input v-model.trim="username" autocomplete="username" placeholder="请输入账号" autofocus /></label>
          <label class="field"><span>访问密码</span><div class="password-box"><input v-model="password" :type="showPassword ? 'text' : 'password'" autocomplete="current-password" placeholder="请输入密码" /><button type="button" class="show-pass" @click="showPassword = !showPassword">{{ showPassword ? '隐藏' : '显示' }}</button></div></label>
          <p v-if="errorMessage" class="login-error">{{ errorMessage }}</p>
          <button class="login-button" type="submit" :disabled="submitting">{{ submitting ? '正在验证…' : '安全登录 →' }}</button>
          <button type="button" class="demo-fill" @click="fillDemo">填入默认演示账号</button>
          <p class="login-note">本地演示访问控制 · 登录态仅保存在当前浏览器</p>
        </form>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const username = ref('')
const password = ref('')
const showPassword = ref(false)
const submitting = ref(false)
const errorMessage = ref('')

function fillDemo() {
  username.value = import.meta.env.VITE_DEMO_LOGIN_USERNAME || 'sentinel-demo'
  password.value = import.meta.env.VITE_DEMO_LOGIN_PASSWORD || 'sentinel2026'
  errorMessage.value = ''
}
function submit() {
  if (submitting.value) return
  submitting.value = true
  const result = auth.login(username.value, password.value)
  submitting.value = false
  if (!result.ok) { errorMessage.value = result.message || '登录失败，请稍后重试。'; return }
  const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
  router.replace(redirect.startsWith('/') ? redirect : '/')
}
</script>

<style scoped>
.login-page { min-height: 100vh; display: grid; place-items: center; position: relative; overflow: hidden; padding: 28px; background: var(--eg); }
.login-orb { position: absolute; width: 480px; height: 480px; border-radius: 50%; pointer-events: none; filter: blur(84px); opacity: .22; }.orb-one { background: #ff843f; top: -220px; left: -160px; }.orb-two { background: #f2b45a; right: -180px; bottom: -220px; }
.login-shell { width: min(100%, 1050px); min-height: 610px; display: grid; grid-template-columns: 1.12fr .88fr; position: relative; z-index: 1; overflow: hidden; border: 1px solid var(--ch); border-radius: 24px; background: #fff; box-shadow: 0 28px 80px rgba(50, 30, 16, .14), var(--sf); }
.brand-panel { padding: 54px; display: flex; flex-direction: column; color: #fff; background: linear-gradient(145deg, #18120f 0%, #342015 100%); position: relative; overflow: hidden; }.brand-panel::after { content: ''; position: absolute; width: 340px; height: 340px; right: -150px; bottom: -170px; border: 1px solid rgba(255,255,255,.12); border-radius: 50%; box-shadow: 0 0 0 38px rgba(255,255,255,.025), 0 0 0 76px rgba(255,255,255,.02); }
.brand { display: inline-flex; align-items: center; gap: 10px; color: #fff; font-family: var(--fd); font-size: 21px; }.brand-mark { width: 35px; height: 35px; display: grid; place-items: center; border-radius: 9px; background: linear-gradient(135deg, var(--w1), var(--amber)); }.brand-copy { margin: auto 0 44px; position: relative; z-index: 1; }.eyebrow, .form-kicker { color: #f9b06e; font-size: 11px; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; }.pulse-dot { width: 6px; height: 6px; display: inline-block; vertical-align: middle; margin: -2px 7px 0 0; border-radius: 50%; background: #ff8c42; box-shadow: 0 0 0 4px rgba(255,140,66,.12); }h1 { margin: 18px 0; font-family: var(--fd); font-size: clamp(40px, 4.1vw, 55px); font-weight: 400; line-height: 1.04; letter-spacing: -1px; }h1 em { font-style: italic; color: #ffad67; }.brand-copy p { max-width: 405px; color: rgba(255,255,255,.6); line-height: 1.75; font-size: 14px; }.stage-list { display: grid; gap: 10px; position: relative; z-index: 1; color: rgba(255,255,255,.56); font-size: 11px; }.stage-list b { color: #ffb579; font-family: var(--fm); font-weight: 500; }
.login-card-wrap { display: grid; place-items: center; padding: 42px; background: linear-gradient(180deg, #fff 0%, var(--w5) 100%); }.login-card { width: min(100%, 320px); }.form-head { margin-bottom: 30px; }.form-kicker { color: var(--w1); margin-bottom: 10px; }h2 { font-family: var(--fd); font-weight: 400; font-size: 31px; line-height: 1.1; margin-bottom: 10px; }.form-head p { font-size: 12.5px; color: var(--grv); line-height: 1.65; }.field { display: block; margin-bottom: 18px; }.field > span { display: block; font-size: 12px; font-weight: 600; margin-bottom: 7px; }input { width: 100%; height: 43px; padding: 0 13px; color: var(--obs); font: 13px var(--fb); outline: none; border: 1px solid var(--ch); border-radius: 9px; background: rgba(255,255,255,.85); transition: border-color .15s, box-shadow .15s; }input:focus { border-color: var(--w1); box-shadow: 0 0 0 3px rgba(255,107,53,.12); }.password-box { position: relative; }.password-box input { padding-right: 52px; }.show-pass { position: absolute; right: 7px; top: 7px; padding: 5px 7px; border: 0; border-radius: 5px; color: var(--grv); cursor: pointer; background: transparent; font: 11px var(--fb); }.show-pass:hover { color: var(--w1); background: var(--w4); }.login-error { margin: -4px 0 13px; padding: 8px 10px; border-radius: 7px; color: var(--rc); background: var(--rbg); font-size: 12px; }.login-button { width: 100%; height: 45px; border: 0; border-radius: 9px; color: #fff; cursor: pointer; font: 600 13px var(--fb); background: linear-gradient(135deg, var(--w1), var(--amber)); box-shadow: 0 7px 18px rgba(255,107,53,.28); transition: transform .15s, box-shadow .15s; }.login-button:hover:not(:disabled) { transform: translateY(-1px); }.login-button:disabled { opacity: .65; cursor: wait; }.demo-fill { width: 100%; margin-top: 12px; padding: 7px; border: 0; color: var(--grv); cursor: pointer; background: transparent; font: 12px var(--fb); }.demo-fill:hover { color: var(--w1); }.login-note { margin-top: 13px; color: var(--fog); text-align: center; font-size: 10.5px; }
@media (max-width: 760px) { .login-page { padding: 0; align-items: stretch; }.login-shell { min-height: 100vh; border: 0; border-radius: 0; grid-template-columns: 1fr; }.brand-panel { min-height: 240px; padding: 30px; }.brand-copy { margin: auto 0 0; }.brand-copy p, .stage-list { display: none; }.login-card-wrap { padding: 42px 28px; }.login-card { width: min(100%, 380px); } }
</style>
