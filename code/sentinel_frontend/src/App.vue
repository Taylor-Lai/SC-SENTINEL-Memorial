<template>
  <div id="app-wrapper">
    <AppNavbar v-if="!route.meta.hideNavbar" />
    <main class="main-content">
      <RouterView v-slot="{ Component }">
        <Transition name="page" mode="out-in">
          <component :is="Component" />
        </Transition>
      </RouterView>
    </main>
  </div>
</template>

<script setup lang="ts">
import { useRoute } from 'vue-router'
import AppNavbar from '@/components/layout/AppNavbar.vue'

const route = useRoute()
</script>

<style scoped>
#app-wrapper { min-height: 100vh; display: flex; flex-direction: column; }
.main-content { flex: 1; }
</style>
