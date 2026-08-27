<template>
  <div class="page-history">
    <div class="dash-hero">
      <RouterLink to="/" class="back-home">← 返回产品总览</RouterLink>
      <div class="eyebrow">安全态势看板</div>
      <h1 class="dash-title">全局安全态势<span class="accent">分析</span></h1>
      <p class="dash-sub">累计 {{ tasks.length }} 次审计任务的聚合洞察</p>
    </div>

    <!-- KPI -->
    <div class="dash-stats">
      <div class="dstat"><div class="dstat-v">{{ kpi.total }}</div><div class="dstat-l">审计任务总数</div><div class="dstat-s">完成 {{ kpi.completed }} · 进行中 {{ kpi.running }}</div></div>
      <div class="dstat"><div class="dstat-v" style="color:var(--rc)">{{ kpi.vulns }}</div><div class="dstat-l">漏洞发现总数</div><div class="dstat-s">跨所有项目</div></div>
      <div class="dstat"><div class="dstat-v" style="color:var(--ok)">{{ kpi.confirmRate }}<span style="font-size:20px">%</span></div><div class="dstat-l">动态复现率</div><div class="dstat-s">已验证样本复现率 · 覆盖 {{ kpi.coverage }}%</div></div>
      <div class="dstat"><div class="dstat-v" style="color:var(--hi)">{{ kpi.cves }}</div><div class="dstat-l">CVE 风险数</div><div class="dstat-s">组件供应链风险</div></div>
      <div class="dstat"><div class="dstat-v">{{ kpi.avgTime }}<span style="font-size:20px">秒</span></div><div class="dstat-l">平均审计耗时</div><div class="dstat-s">端到端平均耗时</div></div>
    </div>

    <!-- Charts -->
    <div class="charts-grid">
      <div class="chart-card">
        <div class="chart-title">漏洞类型分布</div>
        <div class="chart-sub">按类型统计</div>
        <VChart v-if="hasVulnData" :option="donutOption" autoresize style="height:200px" />
        <div v-else class="chart-empty">暂无漏洞数据</div>
      </div>
      <div class="chart-card wide">
        <div class="chart-title">高频漏洞组件排行</div>
        <div class="chart-sub">各库累计 CVE 数量及严重等级</div>
        <VChart v-if="hasCompData" :option="barOption" autoresize style="height:200px" />
        <div v-else class="chart-empty">暂无组件数据</div>
      </div>
    </div>

    <!-- Task table -->
    <div class="table-head">
      <div class="th-title">任务明细</div>
      <RouterLink to="/submit" class="bp bw" style="font-size:12px;padding:7px 16px">+ 新建审计</RouterLink>
    </div>
    <div class="twrap">
      <table class="ttable">
        <thead><tr><th>项目</th><th>状态</th><th>漏洞数</th><th>动态验证</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-if="!loading && tasks.length === 0"><td colspan="6" style="color:var(--fog);text-align:center;padding:40px">暂无审计任务，<RouterLink to="/submit" style="color:var(--w1)">立即创建 →</RouterLink></td></tr>
          <tr v-for="t in tasks" :key="t.id" @click="openTask(t)">
            <td><div class="tnam">{{ t.project_name }}</div><div class="tid">{{ t.id.slice(0, 8) }}-…</div></td>
            <td><span class="sp" :class="statusCls(t.status)">● {{ statusText(t.status) }}</span></td>
            <td><span :style="{ fontWeight: 700, color: t.vuln_count ? 'var(--rc)' : 'var(--fog)' }">{{ t.vuln_count || '—' }}</span></td>
            <td>{{ t.is_dynamic ? '✓' : '—' }}</td>
            <td style="color:var(--grv)">{{ fmtDate(t.created_at) }}</td>
            <td>
              <button v-if="isRunning(t.status)" class="rowbtn danger" @click.stop="onCancel(t)">取消</button>
              <span v-else-if="t.status === 'completed'" class="rowbtn">查看 →</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="total > size" class="pager">
      <button class="bp bg" :disabled="page <= 1" @click="changePage(page - 1)">← 上一页</button>
      <span class="pinfo">{{ page }} / {{ totalPages }}</span>
      <button class="bp bg" :disabled="page >= totalPages" @click="changePage(page + 1)">下一页 →</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart } from 'echarts/charts'
import { TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
import VChart from 'vue-echarts'
import { getTaskList, getDashboardStats, cancelTask } from '@/api/tasks'
import { useTaskStore } from '@/stores/taskStore'
import type { TaskSummary, DashboardStats } from '@/types/api'
import { taskStatusLabel, vulnerabilityLabel } from '@/utils/display'

use([CanvasRenderer, PieChart, BarChart, TooltipComponent, LegendComponent, GridComponent])

const router = useRouter()
const store = useTaskStore()

const tasks = ref<TaskSummary[]>([])
const total = ref(0)
const page = ref(1)
const size = 10
const loading = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null

// 全局聚合统计（来自后端 /tasks/stats，避免 N+1 报告查询）
const stats = ref<DashboardStats | null>(null)

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / size)))

const kpi = computed(() => ({
  total: stats.value?.total_audits ?? total.value,
  completed: stats.value?.completed ?? 0,
  running: stats.value?.running ?? 0,
  vulns: stats.value?.total_vulns ?? 0,
  cves: stats.value?.cve_risks ?? 0,
  confirmRate: stats.value?.confirm_rate ?? 0,
  coverage: stats.value?.verification_coverage ?? 0,
  avgTime: stats.value?.avg_scan_seconds ?? 0
}))

const hasVulnData = computed(() => Object.keys(stats.value?.vuln_type_dist ?? {}).length > 0)
const hasCompData = computed(() => (stats.value?.top_libs ?? []).length > 0)

const warm = ['#ff6b35', '#f7a650', '#e8813a', '#ffd4a8', '#c93b2a', '#cf7d1e']

const donutOption = computed(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: { orient: 'vertical', right: 0, top: 'center', textStyle: { color: '#7a7168', fontSize: 12 } },
  series: [{
    type: 'pie', radius: ['55%', '78%'], center: ['32%', '50%'],
    data: Object.entries(stats.value?.vuln_type_dist ?? {}).map(([name, value]) => ({ name: vulnerabilityLabel(name), value })),
    itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
    label: { show: false }, color: warm
  }]
}))

const barOption = computed(() => {
  const libs = stats.value?.top_libs ?? []
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { bottom: 0, textStyle: { color: '#7a7168', fontSize: 12 }, itemWidth: 10, itemHeight: 10 },
    grid: { left: 8, right: 12, top: 12, bottom: 28, containLabel: true },
    xAxis: { type: 'category', data: libs.map((l) => l.library_name), axisLabel: { color: '#b5b0a8', fontSize: 11 }, axisLine: { lineStyle: { color: '#e8e4de' } } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: 'rgba(0,0,0,0.05)' } }, axisLabel: { color: '#b5b0a8' } },
    series: [
      { name: '严重', type: 'bar', stack: 'x', data: libs.map((l) => l.critical), itemStyle: { color: '#c93b2a' } },
      { name: '高危', type: 'bar', stack: 'x', data: libs.map((l) => l.high), itemStyle: { color: '#f7a650' } },
      { name: '其他', type: 'bar', stack: 'x', data: libs.map((l) => l.other), itemStyle: { color: '#ffd4a8', borderRadius: [4, 4, 0, 0] } }
    ]
  }
})

async function fetchTasks() {
  loading.value = true
  try {
    const [listResp, statsResp] = await Promise.all([
      getTaskList({ page: page.value, size }),
      getDashboardStats()
    ])
    tasks.value = listResp.data.data.items
    total.value = listResp.data.data.total
    store.setTaskList(listResp.data.data.items, listResp.data.data.total)
    stats.value = statsResp.data.data
  } catch { /* 拦截器已处理 */ } finally {
    loading.value = false
  }
}

function isRunning(s: string) {
  return ['pending', 'analyzing_deps', 'llm_auditing', 'fuzzing'].includes(s)
}
function statusCls(s: string) {
  if (s === 'completed') return 'done'
  if (s === 'failed') return 'fail'
  if (s === 'pending') return 'pend'
  return 'run'
}
function statusText(s: string) {
  return taskStatusLabel(s)
}
function fmtDate(d: string) {
  return new Date(d).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function openTask(t: TaskSummary) {
  store.setCurrentTask(t)
  if (t.status === 'completed') router.push({ name: 'report', params: { id: t.id } })
  else if (isRunning(t.status)) router.push({ name: 'monitor', params: { id: t.id } })
}

async function onCancel(t: TaskSummary) {
  try { await cancelTask(t.id); await fetchTasks() } catch { /* ignore */ }
}

function changePage(p: number) {
  page.value = p
  fetchTasks()
}

onMounted(() => {
  fetchTasks()
  pollTimer = setInterval(() => {
    if (tasks.value.some((t) => isRunning(t.status))) fetchTasks()
  }, 5000)
})
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.page-history { max-width: 1200px; margin: 0 auto; padding: 72px 44px; }
.dash-hero { margin-bottom: 40px; }
.eyebrow { font-size: 11px; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; color: var(--w1); margin-bottom: 14px; }
.dash-title { font-family: var(--fd); font-size: 44px; letter-spacing: -.88px; line-height: 1.1; margin-bottom: 8px; }
.accent { background: linear-gradient(135deg, var(--w1), var(--amber)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.dash-sub { font-size: 15px; color: var(--grv); }
.dash-stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 40px; }
.dstat { background: #fff; border-radius: 16px; border: 1px solid var(--ch); box-shadow: var(--sc); padding: 20px 22px; position: relative; overflow: hidden; }
.dstat::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--w1), var(--amber)); }
.dstat-v { font-family: var(--fd); font-size: 36px; letter-spacing: -.7px; line-height: 1; margin-bottom: 6px; }
.dstat-l { font-size: 11px; color: var(--fog); font-weight: 600; letter-spacing: .3px; }
.dstat-s { font-size: 11px; color: var(--grv); margin-top: 4px; }
/* HIS2 */
.charts-grid { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin-bottom: 40px; }
.chart-card { background: #fff; border-radius: 18px; border: 1px solid var(--ch); box-shadow: var(--sc); padding: 24px; overflow: hidden; }
.chart-title { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.chart-sub { font-size: 12px; color: var(--grv); margin-bottom: 20px; }
.chart-empty { height: 200px; display: flex; align-items: center; justify-content: center; color: var(--fog); font-size: 13px; }

.table-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.th-title { font-size: 16px; font-weight: 600; }
.twrap { background: #fff; border-radius: 18px; border: 1px solid var(--ch); box-shadow: var(--sc); overflow: hidden; }
.ttable { width: 100%; border-collapse: collapse; }
.ttable th { text-align: left; padding: 12px 20px; font-size: 11px; font-weight: 700; color: var(--fog); letter-spacing: .4px; background: var(--pw); border-bottom: 1px solid var(--ch); }
.ttable td { padding: 14px 20px; border-bottom: 1px solid var(--ch); font-size: 13px; }
.ttable tr:last-child td { border-bottom: none; }
.ttable tbody tr:hover td { background: var(--w4); cursor: pointer; }
.tnam { font-weight: 600; }
.tid { font-family: var(--fm); font-size: 11px; color: var(--fog); margin-top: 2px; }
.rowbtn { font-size: 12px; font-weight: 600; color: var(--grv); }
.rowbtn.danger { color: var(--rc); background: var(--rbg); border: none; padding: 4px 10px; border-radius: 9999px; cursor: pointer; font-family: var(--fb); }
/* HIS3 */
.pager { display: flex; align-items: center; justify-content: center; gap: 16px; margin-top: 28px; }
.pager .bp { font-size: 12px; padding: 7px 16px; }
.pinfo { font-size: 12px; color: var(--grv); font-family: var(--fm); }

@media (max-width: 980px) {
  .page-history { padding: 48px 18px; }
  .dash-stats { grid-template-columns: repeat(2, 1fr); }
  .charts-grid { grid-template-columns: 1fr; }
  .dash-title { font-size: 32px; }
}
</style>
