import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('/node_modules/zrender/')) return 'charts-renderer'
          if (id.includes('/node_modules/echarts/')) return 'charts-core'
          if (id.includes('/node_modules/vue-echarts/')) return 'charts-vue'
        }
      }
    }
  },
  server: {
    port: 5400,
    host: true,
    proxy: {
      // 所有 /api 请求代理到后端（含 WebSocket：/api/v1/ws/...）
      '/api': {
        target: 'http://127.0.0.1:18000',
        changeOrigin: true,
        ws: true
      }
    }
  }
})
