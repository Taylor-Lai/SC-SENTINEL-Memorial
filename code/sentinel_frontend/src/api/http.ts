import axios from 'axios'

const http = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' }
})

// ── 请求拦截器 ──────────────────────────────────────────────────
http.interceptors.request.use(
  (config) => config,
  (error) => Promise.reject(error)
)

// ── 响应拦截器（全局异常处理，不依赖 UI 库） ────────────────────
// 后端全局响应包装：{ code: 200, message: 'success', data: {...} }
// 注意：文件下载（blob）等非包装响应不在此判断。
http.interceptors.response.use(
  (response) => {
    const data = response.data
    // 仅对带 code 字段的 JSON 业务响应做判断；二进制流（blob）直接放行
    if (data && typeof data === 'object' && typeof data.code === 'number') {
      if (data.code !== 200) {
        const msg = data.message || '操作失败，请稍后重试'
        console.error('[SENTINEL API]', msg)
        return Promise.reject(new Error(msg))
      }
    }
    return response
  },
  (error) => {
    // HTTP 层错误
    if (error.response) {
      const status = error.response.status
      const msgMap: Record<number, string> = {
        400: '请求参数错误',
        404: '请求的资源不存在',
        422: '数据格式校验失败',
        500: '服务器内部错误，请联系管理员',
        503: '服务暂时不可用，请稍后重试'
      }
      const msg = error.response.data?.message || msgMap[status] || `请求失败 (${status})`
      console.error('[SENTINEL API]', msg)
      return Promise.reject(new Error(msg))
    } else if (error.code === 'ECONNABORTED') {
      const msg = '请求超时，请检查服务状态或稍后重试'
      console.error('[SENTINEL API]', msg)
      return Promise.reject(new Error(msg))
    } else {
      const msg = '网络异常，无法连接到后端服务'
      console.error('[SENTINEL API]', msg)
      return Promise.reject(new Error(msg))
    }
  }
)

export default http
