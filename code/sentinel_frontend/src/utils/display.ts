/** 统一管理后端枚举到中文展示文案的映射，避免各页面口径漂移。 */
const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  unknown: '未知'
}

const vulnerabilityLabels: Record<string, string> = {
  use_after_free: '释放后使用',
  uaf: '释放后使用',
  double_free: '重复释放',
  buffer_overflow: '缓冲区溢出',
  heap_overflow: '堆缓冲区溢出',
  stack_overflow: '栈缓冲区溢出',
  format_string: '格式化字符串漏洞',
  format_string_vulnerability: '格式化字符串漏洞'
}

const taskStatusLabels: Record<string, string> = {
  pending: '排队中',
  analyzing_deps: '依赖分析中',
  llm_auditing: '语义审计中',
  fuzzing: '动态验证中',
  completed: '已完成',
  failed: '已失败',
  cancelled: '已取消'
}

export function severityLabel(value?: string | null) {
  return severityLabels[(value || 'unknown').toLowerCase()] || value || '未知'
}

export function vulnerabilityLabel(value?: string | null) {
  const source = value?.trim() || ''
  const normalized = source.toLowerCase().replace(/[\s-]+/g, '_')
  return vulnerabilityLabels[normalized] || source || '未知漏洞类型'
}

export function taskStatusLabel(value?: string | null) {
  return taskStatusLabels[value || ''] || value || '未知状态'
}

export function displayUnknown(value?: string | null) {
  const normalized = value?.trim()
  return !normalized || normalized.toLowerCase() === 'unknown' ? '未知' : normalized
}
