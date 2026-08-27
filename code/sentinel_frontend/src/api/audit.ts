import http from './http'
import type { ApiResponse, AuditSubmitResult, AuditStatus } from '@/types/api'

/**
 * 触发审计 Pipeline（SBOM → LLM → 可选 Fuzzing）
 * 必须先通过 POST /tasks 创建任务拿到 task_id 后再调用。
 */
export function submitAudit(taskId: string) {
  return http.post<ApiResponse<AuditSubmitResult>>('/audit/submit', {
    task_id: taskId
  })
}

/**
 * 查询审计进度（轻量级降级轮询）
 * WebSocket 断开时由前端每 3 秒静默调用，返回阶段/进度百分比/状态描述。
 */
export function getAuditStatus(taskId: string) {
  return http.get<ApiResponse<AuditStatus>>(`/audit/status/${taskId}`)
}
