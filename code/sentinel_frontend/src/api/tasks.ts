import http from './http'
import type {
  ApiResponse,
  TaskCreateResult,
  TaskListData,
  TaskSummary,
  AuditReport,
  DashboardStats
} from '@/types/api'

/** 提交审计任务（multipart/form-data），返回新建任务的基础信息 */
export function submitTask(formData: FormData) {
  return http.post<ApiResponse<TaskCreateResult>>('/tasks', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 120000 // 文件上传允许更长超时
  })
}

/**
 * 获取任务列表（分页）
 * 后端参数：page（从 1 起）、size（每页条数，最大 100）、可选 project_name / status
 */
export function getTaskList(params: {
  page?: number
  size?: number
  status?: string
  project_name?: string
}) {
  return http.get<ApiResponse<TaskListData>>('/tasks', { params })
}

/** 获取全局聚合统计（History 仪表盘用，避免 N+1 报告查询） */
export function getDashboardStats() {
  return http.get<ApiResponse<DashboardStats>>('/tasks/stats')
}

/** 获取单个任务状态（轮询用） */
export function getTask(taskId: string) {
  return http.get<ApiResponse<TaskSummary>>(`/tasks/${taskId}`)
}

/** 获取完整审计报告（summary + components + vulnerabilities） */
export function getTaskReport(taskId: string) {
  return http.get<ApiResponse<AuditReport>>(`/tasks/${taskId}/report`)
}

/** 强制终止任务 */
export function cancelTask(taskId: string) {
  return http.post<ApiResponse<null>>(`/tasks/${taskId}/cancel`)
}

/** 导出 PDF 审计报告（返回 Blob） */
export function exportPdf(taskId: string) {
  return http.get(`/tasks/${taskId}/export-pdf`, {
    responseType: 'blob',
    timeout: 120000 // PDF 生成可能需要更多时间
  })
}
