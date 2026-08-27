<template>
  <nav class="nav">
    <RouterLink to="/" class="nlogo">
      <span class="nlmark">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <path d="M8 1.5L14 5V11L8 14.5L2 11V5L8 1.5Z" stroke="white" stroke-width="1.1" fill="none" />
          <path d="M8 4.5L11.5 6.5V10.5L8 12.5L4.5 10.5V6.5L8 4.5Z" fill="white" opacity="0.5" />
          <circle cx="8" cy="8.5" r="1.8" fill="white" />
        </svg>
      </span>
      SC-SENTINEL
    </RouterLink>

    <div class="nright">
      <RouterLink to="/" class="home-link">产品总览</RouterLink>
      <div class="user-menu">
        <span class="user-avatar">{{ initials }}</span>
        <span class="user-name">{{ auth.displayName }}</span>
        <button class="logout" type="button" title="退出登录" @click="logout">退出</button>
      </div>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'

const router = useRouter()
const auth = useAuthStore()
const initials = computed(() => auth.displayName.slice(0, 2).toUpperCase())

function logout() {
  auth.logout()
  router.replace({ name: 'login' })
}
</script>

<style scoped>
.nav {
  position: sticky; top: 0; z-index: 200; height: 58px; padding: 0 44px;
  display: flex; align-items: center; justify-content: space-between;
  background: rgba(253, 252, 252, 0.9); backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--ch);
}
.nlogo { display: flex; align-items: center; gap: 9px; font-family: var(--fd); font-size: 19px; cursor: pointer; color: inherit; white-space: nowrap; flex-shrink: 0; }
.nlmark {
  width: 30px; height: 30px; border-radius: 7px; background: var(--obs);
  display: flex; align-items: center; justify-content: center; position: relative; overflow: hidden;
}
.nlmark::before { content: ''; position: absolute; inset: 0; background: linear-gradient(135deg, rgba(255, 107, 53, 0.55), transparent 60%); }
.nlmark svg { position: relative; z-index: 1; }

.nright { display: flex; align-items: center; gap: 8px; }
.home-link { color: var(--grv); font-size: 12px; font-weight: 600; padding: 7px 10px; border-radius: 6px; }
.home-link:hover { color: var(--obs); background: var(--pw); }
.user-menu { display: flex; align-items: center; gap: 7px; margin-left: 4px; padding-left: 10px; border-left: 1px solid var(--ch); }
.user-avatar { width: 25px; height: 25px; display: grid; place-items: center; border-radius: 50%; color: #fff; background: linear-gradient(135deg, var(--w1), var(--amber)); font: 700 9px var(--fm); }
.user-name { max-width: 86px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; font-weight: 600; }
.logout { border: 0; padding: 4px 5px; border-radius: 5px; color: var(--grv); cursor: pointer; background: transparent; font: 11px var(--fb); }
.logout:hover { color: var(--w1); background: var(--w4); }

@media (max-width: 860px) {
  .nav { padding: 0 18px; }
}
@media (max-width: 560px) {
  .nav { padding: 0 12px; }
  .nlogo { font-size: 16px; gap: 7px; }
  .nlmark { width: 28px; height: 28px; }
  .home-link { display: none; }
  .user-name, .logout { display: none; }
  .user-menu { padding-left: 6px; }
}
</style>
