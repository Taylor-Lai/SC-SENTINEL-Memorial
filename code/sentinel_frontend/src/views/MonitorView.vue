<template>
  <div class="page-progress">
    <div class="prh">
      <div>
        <div class="ph">实时监控</div>
        <div class="tmeta">
          <span>{{ task?.project_name || '加载中…' }}</span>
          <span class="mono">{{ shortId }}</span>
          <span>{{ liveStatusLabel }}</span>
        </div>
      </div>
      <div class="pr-actions">
        <button v-if="isCompleted" class="bp bw" style="font-size:12px;padding:7px 15px" @click="goReport">查看报告 →</button>
        <button v-else class="bp bg" style="font-size:12px;padding:7px 15px" :disabled="!isRunning" @click="handleCancel">取消任务</button>
      </div>
    </div>

    <!-- Live Log -->
    <div class="logcard">
      <div class="lhead">
        <span class="ltit">实时日志流</span>
        <div class="llive">
          <span class="lldot" :style="{ background: wsConnected ? '#34d399' : '#f59e0b' }" />
          <span>{{ wsConnected ? 'WebSocket 已连接' : '轮询备用模式' }}</span>
        </div>
      </div>
      <div ref="logBody" class="lbody">
        <div v-if="logLines.length === 0" class="ll"><span class="lts">--:--:--</span><span class="lcur">█ 正在等待日志…</span></div>
        <div v-for="(l, i) in logLines" :key="i" class="ll">
          <span class="lts">{{ l.time }}</span><span :class="l.cls">{{ l.text }}</span>
        </div>
      </div>
    </div>

    <!-- Pipeline -->
    <div class="pp-card">
      <div class="pph"><span class="pptit">流水线进度</span><span class="pppct">{{ percent }}%</span></div>
      <div class="bigbar"><div class="bigfill" :style="{ width: percent + '%' }" /></div>
      <div class="ppstages">
        <div v-for="s in stages" :key="s.key" class="pprow" :class="{ run: s.state === 'run', clickable: s.hasDetails }" @click="s.hasDetails && toggleStageDetails(s.key)">
          <div class="ppico" :class="s.state === 'done' ? 'done' : s.state === 'run' ? 'run2' : 'wait'">
            {{ s.state === 'done' ? '✓' : s.state === 'run' ? '⬡' : '◎' }}
          </div>
          <div class="ppbody">
            <div class="ppn">{{ s.name }} <span v-if="s.hasDetails" class="detail-icon">{{ expandedStages[s.key] ? '▼' : '▶' }}</span></div>
            <div class="pps">{{ s.desc }}</div>
            <div v-if="s.state === 'run'" class="ppbar"><div class="ppbf" :style="{ width: percent + '%' }" /></div>
            <!-- 展开详情 -->
            <div v-if="expandedStages[s.key] && s.details" class="stage-details">
              <div v-for="(detail, idx) in s.details" :key="idx" class="detail-item">
                <span class="detail-icon-mini">{{ detail.status === 'done' ? '✓' : detail.status === 'run' ? '●' : '○' }}</span>
                <span class="detail-text">{{ detail.text }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Error -->
    <div v-if="isFailed" class="errcard">
      <div class="errtit">✕ 任务执行失败</div>
      <div class="errmsg">{{ task?.error_message || '任务在执行过程中发生错误' }}</div>
      <div style="margin-top:14px"><button class="bp bg" @click="router.push('/submit')">重新提交</button></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getTask, cancelTask } from '@/api/tasks'
import { getAuditStatus } from '@/api/audit'
import { useWebSocket } from '@/composables/useWebSocket'
import { useTaskStore } from '@/stores/taskStore'
import type { TaskSummary } from '@/types/api'

const route = useRoute()
const router = useRouter()
const store = useTaskStore()
const taskId = route.params.id as string

const task = ref<TaskSummary | null>(null)
const statusLabel = ref('排队等待中')
const logBody = ref<HTMLElement | null>(null)
const expandedStages = ref<Record<string, boolean>>({})
const { connect, disconnect } = useWebSocket(taskId)
let pollTimer: ReturnType<typeof setInterval> | null = null

// ── 平滑进度：用本地插值避免进度条跳变 ──────────────────────────────
const displayPercent = ref(0)          // 前端展示值（缓慢插值）
const targetPercent  = ref(0)          // 服务端真实值
let   tweenTimer: ReturnType<typeof setInterval> | null = null

function startTween() {
  if (tweenTimer) return
  tweenTimer = setInterval(() => {
    const diff = targetPercent.value - displayPercent.value
    if (diff <= 0) return
    // 每 80ms 最多走 diff 的 12%，最小步长 0.4，最大步长 2
    displayPercent.value = targetPercent.value
  }, 80)
}
function stopTween() {
  if (tweenTimer) { clearInterval(tweenTimer); tweenTimer = null }
}

// Keep the bar on the same event snapshot as the log stream.
function syncPercent(value: number) {
  targetPercent.value = Math.max(targetPercent.value, value)
  displayPercent.value = targetPercent.value
}

// ── 模拟日志行（阶段切换时注入，让 log stream 看起来持续更新）──────
const simLogs = ref<{ time: string; text: string; cls: string }[]>([])
const SIM_LINES: Record<string, string[]> = {
  sbom: [
    '▶ 解析源码依赖树 (CMakeLists / conanfile / vcpkg)…',
    '▶ 提取 #include 引用，推断第三方库列表…',
    '▶ 查询 OSV 数据库，匹配已知 CVE…',
    '▶ 查询 NVD 数据库，补充 CVSS 评分…',
    '▶ 过滤低置信度匹配项，计算风险等级…',
    '✅ Agent a 依赖识别完成，正在汇总组件风险…',
  ],
  llm: [
    '▶ [Agent b] 按函数粒度切片源码，生成漏洞假设…',
    '▶ [Agent c] 静态规则预筛，检测 UAF / Double-Free / Overflow…',
    '▶ [Agent c] 调用 LLM 对高风险函数进行深度复核…',
    '▶ [Agent c] 分析函数间数据流与可达路径…',
    '▶ [Agent d] 为候选漏洞准备验证工件…',
    '▶ [Agent d] 构建 ASan / AFL++ 测试配置…',
    '✅ Agent b/c 静态复核与验证工件准备完成…',
  ],
  fuzzing: [
    '▶ [Agent d] 初始化 AFL++ 沙箱环境…',
    '▶ [Agent d] 加载 Harness，注入 eBPF uprobe 探针…',
    '▶ [Agent d] AFL++ 模糊测试运行中，监控内存异常…',
    '▶ [Agent d] eBPF 捕获内核级事件，关联崩溃堆栈…',
  ],
}
let simIndex   = 0
let simStage   = ''
let simLineTimer: ReturnType<typeof setInterval> | null = null
const pageLoadTime = Date.now()

// ── 禁用模拟日志注入 ────────────────────────────────────────────────
function injectSimLogs(stage: string) {
  // 模拟日志已禁用，完全依赖后端真实日志流
  return
}

const wsConnected = computed(() => store.wsConnected)
const percent     = computed(() => Math.round(displayPercent.value))
const shortId     = computed(() => taskId.slice(0, 8))

const isCompleted = computed(() => task.value?.status === 'completed' || store.progressStage === 'done')
const isFailed    = computed(() => task.value?.status === 'failed' || store.progressStage === 'failed')
const isRunning   = computed(() => !isCompleted.value && !isFailed.value)

// 实时阶段描述
const liveStatusLabel = computed(() => {
  const eventStage = store.progressStage
  const st = eventStage === 'sbom' ? 'analyzing_deps'
    : eventStage === 'llm' ? 'llm_auditing'
    : eventStage === 'fuzzing' ? 'fuzzing'
    : eventStage === 'report' ? 'reporting'
    : eventStage === 'done' ? 'completed'
    : eventStage === 'failed' ? 'failed'
    : task.value?.status
  if (st === 'completed') return '✓ 审计完成'
  if (st === 'failed') return '✕ 任务失败'
  if (st === 'pending') return '⧗ 排队等待中'
  if (st === 'analyzing_deps') return '▶ Agent a：依赖识别智能体运行中'
  if (st === 'llm_auditing') return '▶ Agent b/c：假设生成与静态复核中'
  if (st === 'fuzzing') return '▶ Agent d：验证工件智能体运行中'
  if (st === 'reporting') return '▶ Agent e：报告生成智能体正在汇总证据'
  return statusLabel.value || '正在处理...'
})

// ── 日志流：展示真实WS消息 + 轮询时的阶段提示 ────────────────────
const logLines = computed(() => {
  const out: { time: string; text: string; cls: string }[] = []

  // 后端WebSocket日志
  for (const log of store.progressLogs) {
    const t = log.timestamp ? new Date(log.timestamp).toLocaleTimeString('en-GB') : ''
    if (log.message) out.push({ time: t, text: log.message, cls: lineClass(log.stage, log.message) })
    if (log.log_stream) {
      for (const raw of log.log_stream.split('\n')) {
        if (raw.trim()) out.push({ time: t, text: raw, cls: lineClass(log.stage, raw) })
      }
    }
  }

  // 如果没有WS日志且任务正在运行，显示轮询状态
  if (out.length === 0 && isRunning.value) {
    const now = new Date().toLocaleTimeString('en-GB')
    const st = task.value?.status
    if (st === 'pending') {
      out.push({ time: now, text: '⧗ 任务已提交，等待调度...', cls: 'lok' })
    } else if (st === 'analyzing_deps') {
      out.push({ time: now, text: '▶ Agent a：依赖识别智能体正在解析 SBOM...', cls: 'linf' })
    } else if (st === 'llm_auditing') {
      out.push({ time: now, text: '▶ Agent b/c：假设生成与静态复核进行中...', cls: 'linf' })
    } else if (st === 'fuzzing') {
      out.push({ time: now, text: '▶ Agent d：验证工件智能体运行中，AFL++ + eBPF 监控中...', cls: 'linf' })
    }
  }

  return out
})

function lineClass(stage: string, text: string) {
  if (stage === 'failed' || /error|fail|✕|❌/i.test(text)) return 'lwrn'
  if (/eBPF|uprobe|0x/i.test(text)) return 'laddr'
  if (/crash|warn|⚠/i.test(text)) return 'lwrn'
  if (/\[LLM\]|\[AFL/i.test(text)) return 'linf'
  return 'lok'
}

// ── 五阶段流水线状态推导 ─────────────────────────────────────────
const stages = computed(() => {
  const dynamic = task.value?.is_dynamic ?? true
  // 当前运行阶段索引：0 deps, 1 audit, 2 harness, 3 fuzz, 4 report
  let idx = 0
  const eventStage = store.progressStage
  const st = eventStage === 'sbom' ? 'analyzing_deps'
    : eventStage === 'llm' ? 'llm_auditing'
    : eventStage === 'fuzzing' ? 'fuzzing'
    : eventStage === 'report' ? 'reporting'
    : eventStage === 'done' ? 'completed'
    : eventStage === 'failed' ? 'failed'
    : task.value?.status
  const pct = percent.value

  if (st === 'analyzing_deps') idx = 0
  else if (st === 'llm_auditing') {
    // 根据进度区分是审计阶段还是harness生成阶段
    idx = pct < 52 ? 1 : 2
  }
  else if (st === 'fuzzing') idx = 3
  else if (st === 'reporting') idx = 4
  else if (st === 'completed') idx = 5
  else if (st === 'pending') idx = -1

  // WS percent 兜底
  if (idx < 5 && pct >= 100) idx = 5

  const rows = [
    {
      key: 'deps',
      name: 'Agent a：依赖识别智能体',
      descDone: '完成 · SBOM 解析与 CVE 风险识别',
      descRun: '正在解析依赖树，查询 OSV / NVD 数据库…',
      descWait: '等待调度',
      hasDetails: true,
      details: idx >= 0 ? [
        { status: 'done', text: '解析 CMakeLists.txt / Makefile / vcpkg.json' },
        { status: 'done', text: '提取 #include 引用，识别第三方库' },
        { status: idx > 0 ? 'done' : 'run', text: '查询 OSV 数据库，匹配 CVE' },
        { status: idx > 0 ? 'done' : 'wait', text: '查询 NVD 数据库，补充 CVSS 评分' }
      ] : []
    },
    {
      key: 'audit',
      name: 'Agent b：假设生成智能体',
      descDone: '完成 · 漏洞假设已生成',
      descRun: '正在结合源码与依赖上下文生成假设…',
      descWait: '等待依赖扫描完成',
      hasDetails: true,
      details: idx >= 1 ? [
        { status: 'done', text: '源码按函数粒度切片并建立调用上下文' },
        { status: idx > 1 ? 'done' : 'run', text: '生成 UAF / Double-Free / Overflow 漏洞假设' },
        { status: idx > 1 ? 'done' : 'wait', text: '将候选假设交给 Agent c 复核' }
      ] : []
    },
    {
      key: 'harness',
      name: 'Agent c：静态复核智能体',
      descDone: '完成 · 静态复核与验证工件已就绪',
      descRun: '正在复核边界条件、数据流与可达路径…',
      descWait: '等待漏洞假设生成',
      hasDetails: true,
      details: idx >= 2 ? [
        { status: 'done', text: '静态规则预筛与 LLM 深度复核' },
        { status: idx > 2 ? 'done' : 'run', text: '确认可达路径并准备验证工件' }
      ] : []
    },
    {
      key: 'fuzz',
      name: 'Agent d：验证工件智能体',
      descDone: '完成 · 动态验证结束',
      descRun: 'AFL++ Fuzzing · eBPF 内核监控中…',
      descWait: dynamic ? '等待验证工件就绪' : '已跳过（未启用动态验证）',
      hasDetails: dynamic && idx >= 3,
      details: dynamic && idx >= 3 ? [
        { status: 'done', text: '初始化 Docker 沙箱环境' },
        { status: idx > 3 ? 'done' : 'run', text: 'AFL++ 模糊测试运行中' },
        { status: idx > 3 ? 'done' : 'run', text: 'eBPF uprobe 监控内存操作' }
      ] : []
    },
    {
      key: 'report',
      name: 'Agent e：报告生成智能体',
      descDone: '完成 · 审计报告已生成',
      descRun: '正在汇总全部结果，生成最终审计报告…',
      descWait: '等待动态验证完成',
      hasDetails: false,
      details: []
    }
  ]
  return rows.map((r, i) => {
    let state: 'done' | 'run' | 'wait'
    if (!dynamic && r.key === 'fuzz') {
      state = idx >= 2 ? 'done' : 'wait' // 非动态：fuzz 直接视为跳过/完成
    } else if (idx === 4) {
      state = 'done'
    } else if (i < idx) state = 'done'
    else if (i === idx) state = 'run'
    else state = 'wait'
    const desc = state === 'done' ? r.descDone : state === 'run' ? r.descRun : r.descWait
    return { key: r.key, name: r.name, desc, state, hasDetails: r.hasDetails, details: r.details }
  })
})

function toggleStageDetails(key: string) {
  expandedStages.value[key] = !expandedStages.value[key]
}

// ── 数据加载 ─────────────────────────────────────────────────────
async function refreshStatus() {
  try {
    const resp = await getTask(taskId)
    task.value = resp.data.data
    store.setCurrentTask(resp.data.data)
    // A completed task is a historical snapshot, not a new audit session.
    // Do not replay stale WebSocket progress or animate its bar from zero.
    if (resp.data.data.status === 'completed') {
      statusLabel.value = '审计完成'
      store.setTerminalProgress('done', '审计完成，报告已就绪。')
      syncPercent(100)
      stopTween()
      return
    }
    if (resp.data.data.status === 'failed') {
      store.setTerminalProgress('failed', '任务执行失败。')
      syncPercent(100)
      stopTween()
      return
    }
    const a = await getAuditStatus(taskId)
    statusLabel.value = a.data.data.status_label
    // 始终同步服务端真实百分比到 targetPercent，tween 负责平滑展示
    const serverPct = a.data.data.progress_percent ?? 0
    if (serverPct > targetPercent.value) syncPercent(serverPct)
    // 根据当前 status 注入模拟日志行
    const st = resp.data.data.status
    if (st === 'analyzing_deps') injectSimLogs('sbom')
    else if (st === 'llm_auditing') injectSimLogs('llm')
    else if (st === 'fuzzing') injectSimLogs('fuzzing')
  } catch { /* 忽略轮询错误 */ }
}

async function handleCancel() {
  try {
    await cancelTask(taskId)
    await refreshStatus()
  } catch { /* 拦截器已处理 */ }
}

function goReport() {
  router.push({ name: 'report', params: { id: taskId } })
}

// 自动滚动日志到底
watch(() => logLines.value.length, async () => {
  await nextTick()
  if (logBody.value) logBody.value.scrollTop = logBody.value.scrollHeight
})

// WS 推送时同步 targetPercent + 触发对应阶段模拟日志
watch(() => store.progressPercent, (v) => {
  // `done` changes the stage and percent in the same store update. The final
  // 100% snapshot must still reach the bar after the task becomes terminal.
  if (v > targetPercent.value) syncPercent(v)
})
watch(() => store.progressStage, (stage) => {
  if (stage && SIM_LINES[stage]) injectSimLogs(stage)
})
let redirectScheduled = false
watch(isCompleted, (done) => {
  if (done && !redirectScheduled) {
    redirectScheduled = true
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
    // 不自动跳转，让用户手动点击"查看报告"按钮
  }
})

// 失败时停止轮询（无需再刷新状态）
watch(isFailed, (failed) => {
  if (failed && pollTimer) { clearInterval(pollTimer); pollTimer = null }
})

onMounted(async () => {
  store.resetProgress()
  await refreshStatus()
  // Do not attach a WebSocket/poller for an already completed audit. The
  // server can retain old broadcast messages, which previously made the UI
  // replay a completed pipeline while every stage was already checked.
  if (isCompleted.value || isFailed.value) return
  connect()
  startTween()
  pollTimer = setInterval(refreshStatus, 2000)
})
onUnmounted(() => {
  disconnect()
  stopTween()
  if (pollTimer) clearInterval(pollTimer)
  if (simLineTimer) clearInterval(simLineTimer)
})
</script>

<style scoped>
.page-progress { max-width: 920px; margin: 0 auto; padding: 72px 44px; }
.prh { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 44px; gap: 20px; }
.ph { font-family: var(--fd); font-size: 34px; letter-spacing: -.8px; line-height: 1.1; }
.tmeta { font-size: 12px; color: var(--fog); margin-top: 6px; }
.tmeta span { margin-right: 14px; }
.tmeta .mono { font-family: var(--fm); font-size: 11px; color: var(--fog); }
.pr-actions { display: flex; gap: 8px; align-items: center; }
/* MON2 */
.logcard { background: #141210; border-radius: 16px; overflow: hidden; margin-bottom: 20px; border: 1px solid #2a2520; }
.lhead { padding: 12px 20px; border-bottom: 1px solid #221e19; display: flex; align-items: center; justify-content: space-between; }
.ltit { font-size: 11px; font-weight: 700; color: #665f55; letter-spacing: .5px; text-transform: uppercase; }
.llive { display: flex; align-items: center; gap: 5px; font-size: 11px; color: #6b6359; }
.lldot { width: 5px; height: 5px; border-radius: 50%; background: #34d399; animation: pulse 1s infinite; }
.lbody { padding: 16px 20px; font-family: var(--fm); font-size: 12px; line-height: 1.75; height: 360px; overflow-y: auto; }
.ll { display: flex; gap: 14px; margin-bottom: 1px; }
.lts { color: #3d3730; flex-shrink: 0; min-width: 64px; }
.lok { color: #34d399; }
.linf { color: #60a5fa; }
.linfo { color: #94a3b8; }
.lwrn { color: #f59e0b; }
.laddr { color: #c084fc; }
.lcur { color: #4b4540; }
/* MON3 */
.pp-card { background: #fff; border-radius: 20px; border: 1px solid var(--ch); box-shadow: var(--sc); overflow: hidden; margin-bottom: 20px; }
.pph { padding: 20px 24px; border-bottom: 1px solid var(--ch); display: flex; align-items: center; justify-content: space-between; }
.pptit { font-size: 13px; font-weight: 600; }
.pppct { font-family: var(--fd); font-size: 30px; background: linear-gradient(135deg, var(--w1), var(--amber)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.bigbar { height: 4px; background: var(--ch); }
.bigfill { height: 100%; background: linear-gradient(90deg, var(--w1), var(--amber)); transition: width 1s ease; box-shadow: 0 0 8px rgba(255, 107, 53, .4); }
.ppstages { padding: 6px 0; }
.pprow { display: flex; align-items: center; gap: 16px; padding: 14px 24px; border-bottom: 1px solid var(--ch); transition: background .15s; }
.pprow:last-child { border-bottom: none; }
.pprow.run { background: var(--w4); }
.pprow.clickable { cursor: pointer; }
.pprow.clickable:hover { background: var(--w5); }
.ppico { width: 36px; height: 36px; border-radius: 9px; border: 1px solid var(--ch); display: flex; align-items: center; justify-content: center; font-size: 15px; flex-shrink: 0; }
.ppico.done { background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; border: none; }
.ppico.run2 { background: var(--w4); border-color: rgba(255, 107, 53, .3); animation: blink 1.8s infinite; }
.ppico.wait { background: var(--pw); opacity: .4; }
.ppbody { flex: 1; }
.ppn { font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 6px; }
.detail-icon { font-size: 10px; color: var(--fog); }
.pps { font-size: 11px; color: var(--grv); margin-top: 2px; }
.ppbar { height: 3px; width: 140px; background: var(--ch); border-radius: 9999px; overflow: hidden; margin-top: 6px; }
.ppbf { height: 100%; background: linear-gradient(90deg, var(--w1), var(--amber)); border-radius: 9999px; transition: width 1s ease; }
.stage-details { margin-top: 12px; padding: 12px 0 1px; border-top: 1px solid var(--ch); }
.detail-item { display: flex; align-items: center; gap: 10px; padding: 6px 0; font-size: 13px; line-height: 1.45; color: var(--grv); }
.detail-icon-mini { font-size: 12px; color: var(--w1); flex-shrink: 0; }
.detail-text { flex: 1; }

.errcard { background: var(--rbg); border: 1px solid rgba(201, 59, 42, .25); border-radius: 16px; padding: 22px 24px; }
.errtit { font-size: 14px; font-weight: 700; color: var(--rc); margin-bottom: 8px; }
.errmsg { font-size: 13px; color: var(--grv); line-height: 1.6; font-family: var(--fm); }

@media (max-width: 700px) {
  .page-progress { padding: 48px 18px; }
}
</style>
