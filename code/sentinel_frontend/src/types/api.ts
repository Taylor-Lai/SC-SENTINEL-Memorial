/**
 * 后端 API 返回数据类型定义
 * 与 app/schemas/task.py / app/api/v1/audit.py 严格一一对应
 */

// ── 通用响应包装（后端 app/schemas/common.py: {code, message, data}）──
export interface ApiResponse<T = unknown> {
  code: number
  message: string
  data: T
}

// ── 任务状态枚举（与后端 TaskStatus 一致）──────────────────────────
export type TaskStatus =
  | 'pending'
  | 'analyzing_deps'
  | 'llm_auditing'
  | 'fuzzing'
  | 'completed'
  | 'failed'

export type SourceType = 'zip' | 'github'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

// 后端 vuln_type 是自由字符串，常见标准缩写见对接规范
export type VulnType =
  | 'UAF'
  | 'double_free'
  | 'heap_overflow'
  | 'stack_overflow'
  | string

// 后端 EbpfEventType
export type EbpfEventType =
  | 'double_free'
  | 'heap_overflow'
  | 'use_after_free'
  | 'null_deref'
  | 'stack_overflow'
  | 'out_of_bounds'
  | 'format_string'
  | 'other'

// 后端 VerifyStatus
export type VerifyStatus = 'unverified' | 'confirmed' | 'not_reproduced' | 'false_positive'

// ── 任务摘要（对应后端 TaskListItem / TaskStatusOut）────────────────
export interface TaskSummary {
  id: string
  project_name: string
  status: TaskStatus
  source_type: SourceType
  is_dynamic: boolean
  vuln_count: number
  error_message: string | null
  created_at: string
  completed_at: string | null
}

// ── 任务分页列表（对应后端 TaskListOut）────────────────────────────
export interface TaskListData {
  total: number
  items: TaskSummary[]
}

// ── 仪表盘聚合统计（对应后端 DashboardStats）────────────────────────
export interface LibRiskCount {
  library_name: string
  critical: number
  high: number
  other: number
}

export interface DashboardStats {
  total_audits: number
  completed: number
  running: number
  failed: number
  total_vulns: number
  confirmed_vulns: number
  not_reproduced_vulns: number
  pending_verification: number
  cve_risks: number
  confirm_rate: number
  verification_coverage: number
  avg_scan_seconds: number
  vuln_type_dist: Record<string, number>
  top_libs: LibRiskCount[]
}

// ── 创建任务响应（对应后端 TaskCreateOut）──────────────────────────
export interface TaskCreateResult {
  id: string
  project_name: string
  status: TaskStatus
  created_at: string
}

// ── 触发审计 Pipeline 响应（对应后端 /audit/submit data）───────────
export interface AuditSubmitResult {
  task_id: string
  status: TaskStatus
  ws_url: string
  message?: string
}

// ── 审计进度（对应后端 /audit/status/{id} data）────────────────────
export interface AuditStatus {
  task_id: string
  project_name: string
  status: TaskStatus
  status_label: string
  progress_percent: number
  ws_url: string
  error_message: string | null
}

// ── 组件风险（对应后端 ComponentOut）───────────────────────────────
export interface ComponentRisk {
  library_name: string
  version: string | null
  cve_id: string | null
  cvss_score: number | null
  severity: Severity
  description: string | null
  nvd_url: string | null
}

// ── eBPF 事件（对应后端 EbpfLogOut，内嵌在漏洞中）──────────────────
export interface EbpfLog {
  timestamp: number // 纳秒级 Unix 时间戳
  event_type: EbpfEventType
  memory_addr: string | null
  function_name: string | null
}

// ── 漏洞详情（对应后端 VulnerabilityOut）───────────────────────────
export interface Vulnerability {
  id: string
  vuln_type: VulnType
  file_path: string | null
  line_number: number | null
  code_context: string | null
  description: string | null
  trigger_condition: string | null
  fix_suggestion: string | null
  verify_status: VerifyStatus
  crash_output: string | null
  ebpf_logs: EbpfLog[]
  llm_original_type?: string // LLM初始分类(如被eBPF纠正)
  ebpf_corrected?: boolean    // 是否被eBPF纠正
  cwe_id: string
  severity: Severity
  evidence_sources: Array<'static' | 'asan' | 'afl' | 'ebpf' | string>
  evidence_grade: 'corroborated' | 'runtime_confirmed' | 'partial_evidence' | 'candidate' | 'not_reproduced' | 'dismissed' | string
}

// ── 报告摘要（对应后端 ReportSummary）──────────────────────────────
export interface ReportSummary {
  project_name: string
  total_time_seconds: number | null
  is_dynamic: boolean
  risk_score: number
  risk_level: 'critical' | 'high' | 'medium' | 'low' | string
  confirmed_count: number
  candidate_count: number
  not_reproduced_count: number
}

// ── 完整审计报告（对应后端 ReportOut）──────────────────────────────
export interface AuditReport {
  summary: ReportSummary
  components: ComponentRisk[]
  vulnerabilities: Vulnerability[]
  candidate_vulnerabilities?: Vulnerability[]
}

// ── 提交任务的表单（前端内部使用）──────────────────────────────────
export interface SubmitTaskForm {
  project_name: string
  source_type: SourceType
  source_path?: string // GitHub URL
  is_dynamic: boolean
  target_vulns?: string // JSON string of vuln types
}

// ── WebSocket 进度推送（与后端 WsProgressMessage 一致）──────────────
export interface WsProgressMessage {
  stage: string
  percent: number
  message: string
  log_stream: string
  timestamp?: string // 前端本地追加，方便展示时间
}
