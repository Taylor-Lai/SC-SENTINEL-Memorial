<template>
  <div class="page-report">
    <!-- Loading -->
    <div v-if="loading" class="rload">正在加载审计报告…</div>

    <!-- Not ready (still running) -->
    <div v-else-if="notReady" class="rload">
      <div style="font-size:15px;color:var(--obs);margin-bottom:8px">任务尚未完成</div>
      <div style="font-size:13px;color:var(--grv);margin-bottom:16px">报告将在审计流水线结束后生成</div>
      <button class="bp bw" @click="goMonitor">前往实时监控 →</button>
    </div>

    <!-- Report body -->
    <template v-else-if="report">
      <div class="rhdr">
        <div>
          <div class="reyebrow">审计报告</div>
          <div class="ph">{{ report.summary.project_name }}</div>
          <div class="rmeta">
            审计耗时 {{ durationText }} ·
            {{ report.summary.is_dynamic ? 'ASan / AFL++ / eBPF 联合验证' : '仅静态审计' }}
          </div>
        </div>
        <div class="racts">
          <button class="bp bg" :disabled="pdfExporting" @click="handleExportPdf">{{ pdfExporting ? '导出中…' : '↓ 导出 PDF' }}</button>
        </div>
      </div>

      <!-- Summary cards -->
      <div class="smgrid">
        <div class="smcard"><div class="smlbl">动态验证覆盖率</div><div class="smval">{{ verificationCoverage }}<span>%</span></div><div class="smsub">已完成运行时验证的发现占全部发现的比例</div></div>
        <div class="smcard"><div class="smlbl">运行时已复现</div><div class="smval" style="color:var(--rc)">{{ confirmedCount }}</div><div class="smsub">已由运行时强证据复现</div></div>
        <div class="smcard"><div class="smlbl">需要复核</div><div class="smval" style="color:var(--hi)">{{ reviewCount }}</div><div class="smsub">静态候选，等待进一步验证</div></div>
        <div class="smcard"><div class="smlbl">当前未复现</div><div class="smval" style="color:var(--blue)">{{ notReproducedCount }}</div><div class="smsub">限定测试预算内未触发，不等于误报</div></div>
      </div>

      <div class="method-note">
        <strong>裁决口径</strong><span>静态分析负责提出候选；ASan / AFL++ 负责复现；eBPF 提供运行时旁证与强事件纠错。只有强动态证据才能进入“已确认”。</span>
        <span class="method-meta">{{ components.length }} 组件风险 · {{ ebpfTotal }} eBPF 事件</span>
      </div>

      <!-- Vulnerabilities -->
      <div class="rsec">
        <div class="rsech">
          <div class="rsectl">已确认漏洞 <span class="cbadge">{{ vulns.length }}</span></div>
          <div style="display:flex;gap:6px">
            <span class="dbadge b-ok" style="font-size:11px;padding:3px 10px">已确认 {{ confirmedCount }}</span>
            <span class="dbadge b-un" style="font-size:11px;padding:3px 10px">候选 {{ candidateCount }}</span>
          </div>
        </div>

        <div v-if="vulns.length === 0" class="empty">暂无运行时已确认漏洞</div>

        <FindingCard v-for="(v, index) in vulns" :key="v.id" :finding="v" :initially-open="index === 0" />
      </div>

      <div v-if="candidateVulns.length" class="rsec">
        <div class="rsech">
          <div class="rsectl">静态候选与当前未复现 <span class="cbadge">{{ candidateVulns.length }}</span></div>
        </div>
        <FindingCard v-for="v in candidateVulns" :key="v.id" :finding="v" />
      </div>

      <!-- Component risk (SBOM) -->
      <div class="rsec">
        <div class="rsech"><div class="rsectl">组件风险（SBOM）<span class="cbadge">{{ components.length }} 项</span></div></div>
        <div class="rtwrap">
          <table class="rtable">
            <thead><tr><th>组件</th><th>版本</th><th>CVE</th><th>CVSS</th><th>风险等级</th><th>风险说明</th></tr></thead>
            <tbody>
              <tr v-if="components.length === 0"><td colspan="6" style="color:var(--fog)">未发现已知 CVE 风险</td></tr>
              <tr v-for="(c, i) in components" :key="i">
                <td class="mono strong">{{ c.library_name }}</td>
                <td class="mono soft">{{ displayUnknown(c.version) }}</td>
                <td><a v-if="c.cve_id" class="cvea" :href="c.nvd_url || `https://nvd.nist.gov/vuln/detail/${c.cve_id}`" target="_blank">{{ c.cve_id }}</a><span v-else style="color:var(--fog)">—</span></td>
                <td><span class="cs" :class="cvssClass(c.cvss_score)">{{ c.cvss_score ?? '—' }}</span></td>
                <td><span class="dbadge" :class="'sev-' + c.severity">{{ severityLabel(c.severity) }}</span></td>
                <td style="color:var(--grv);max-width:340px">{{ summarizeDescription(c.description, c) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getTask, getTaskReport, exportPdf } from '@/api/tasks'
import { useTaskStore } from '@/stores/taskStore'
import FindingCard from '@/components/report/FindingCard.vue'
import type { AuditReport } from '@/types/api'
import { displayUnknown, severityLabel } from '@/utils/display'

const route = useRoute()
const router = useRouter()
const store = useTaskStore()
const taskId = route.params.id as string

const loading = ref(true)
const notReady = ref(false)
const report = ref<AuditReport | null>(null)
const pdfExporting = ref(false)

const components = computed(() => report.value?.components ?? [])
const vulns = computed(() => report.value?.vulnerabilities ?? [])
const candidateVulns = computed(() => report.value?.candidate_vulnerabilities ?? [])
const allFindings = computed(() => [...vulns.value, ...candidateVulns.value])
const confirmedCount = computed(() => vulns.value.length)
const candidateCount = computed(() => candidateVulns.value.length)
const notReproducedCount = computed(() => report.value?.summary.not_reproduced_count ?? candidateVulns.value.filter((v) => v.verify_status === 'not_reproduced').length)
const reviewCount = computed(() => report.value?.summary.candidate_count ?? candidateVulns.value.filter((v) => v.verify_status === 'unverified').length)
const verificationCoverage = computed(() => {
  const total = allFindings.value.length
  if (!total) return 0
  return Math.round((confirmedCount.value + notReproducedCount.value) / total * 100)
})
const ebpfTotal = computed(() => allFindings.value.reduce((sum, finding) => sum + finding.ebpf_logs.length, 0))
const scanSeconds = computed(() => {
  const t = report.value?.summary.total_time_seconds
  return t != null ? Math.round(t) : '—'
})
const durationText = computed(() => {
  const t = report.value?.summary.total_time_seconds
  if (t == null) return '—'
  return t < 60 ? `${t.toFixed(1)}s` : `${Math.floor(t / 60)}m ${Math.round(t % 60)}s`
})

function cvssClass(score: number | null) {
  if (score == null) return ''
  if (score >= 7) return 'hi'
  if (score >= 4) return 'med'
  return 'lo'
}

function summarizeDescription(desc: string | null, component?: { library_name: string; version: string | null; cve_id: string | null }): string {
  const name = component?.library_name || '该组件'
  const version = component?.version ? `版本 ${component.version}` : '版本未识别'
  const cve = component?.cve_id ? `已匹配 ${component.cve_id}` : '暂未匹配具体 CVE'
  const maxLength = 180
  if (!desc) return `${name} ${version}：${cve}。SBOM 命中只表示组件风险线索，仍需结合源码调用链与运行时证据复核。`
  const normalized = desc.startsWith(`${name} `)
  if (desc.length <= maxLength) {
    return normalized ? desc : `${name} ${version}：${desc}（${cve}）。SBOM 命中不等于漏洞已在本项目触发。`
  }

  // 提取关键信息：CVE、漏洞类型、版本
  const cveMatch = desc.match(/CVE-\d{4}-\d+/)
  const vulnTypes = desc.match(/buffer overflow|use after free|double free|injection|denial of service|memory leak|integer overflow|code execution/i)
  const versionMatch = desc.match(/version[s]?\s+([0-9.]+(?:\s+(?:through|to|before|and)\s+[0-9.]+)?)/i)

  const vulnCn: Record<string, string> = {
    'buffer overflow': '缓冲区溢出',
    'use after free': '释放后使用',
    'double free': '重复释放',
    'injection': '注入漏洞',
    'denial of service': '拒绝服务',
    'memory leak': '内存泄漏',
    'integer overflow': '整数溢出',
    'code execution': '代码执行'
  }

  const parts: string[] = []
  if (cveMatch) parts.push(cveMatch[0])
  if (vulnTypes) {
    const type = vulnTypes[0].toLowerCase()
    const cnName = vulnCn[type] || type
    parts.push(`${cnName}`)
  }
  if (versionMatch) parts.push(`影响: ${versionMatch[1]}`)

  if (parts.length > 0) {
    return `${normalized ? '' : `${name} ${version}：`}${parts.join(' · ')}；${desc.substring(0, maxLength)}…（${cve}）。请结合实际调用链复核。`
  }

  // 兜底：保留统一的组件上下文和判断边界
  return `${normalized ? '' : `${name} ${version}：`}${desc.substring(0, maxLength)}…（${cve}）。请结合实际调用链复核。`
}

async function handleExportPdf() {
  pdfExporting.value = true
  try {
    const resp = await exportPdf(taskId)
    const blob = new Blob([resp.data], { type: 'application/pdf' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `SC-SENTINEL_Report_${report.value?.summary.project_name ?? taskId}.pdf`
    a.click()
    URL.revokeObjectURL(url)
  } catch { /* 拦截器已处理 */ } finally {
    pdfExporting.value = false
  }
}

function goMonitor() {
  router.push({ name: 'monitor', params: { id: taskId } })
}

onMounted(async () => {
  loading.value = true
  try {
    const t = await getTask(taskId)
    store.setCurrentTask(t.data.data)
    if (t.data.data.status !== 'completed') {
      notReady.value = true
      return
    }
    const r = await getTaskReport(taskId)
    report.value = r.data.data
    store.setCurrentReport(r.data.data)
  } catch {
    notReady.value = true
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.page-report { max-width: 1120px; margin: 0 auto; padding: 72px 44px; }
.rload { text-align: center; padding: 120px 24px; color: var(--grv); font-size: 14px; }
.rhdr { display: grid; grid-template-columns: 1fr auto; gap: 40px; align-items: start; margin-bottom: 44px; padding-bottom: 32px; border-bottom: 1px solid var(--ch); }
.reyebrow { font-size: 11px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase; color: var(--w1); margin-bottom: 10px; }
.ph { font-family: var(--fd); font-size: 40px; letter-spacing: -.8px; line-height: 1.1; }
.rmeta { font-size: 13px; color: var(--grv); margin-top: 8px; }
.racts { display: flex; gap: 8px; }
.racts .bp { font-size: 12px; padding: 8px 16px; }
/* REP2 */
.smgrid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 44px; }
.smcard { background: #fff; border-radius: 16px; border: 1px solid var(--ch); box-shadow: var(--sc); padding: 20px 22px; position: relative; overflow: hidden; }
.smcard::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--w1), var(--amber)); }
.smlbl { font-size: 11px; color: var(--fog); font-weight: 600; margin-bottom: 8px; }
.smval { font-family: var(--fd); font-size: 38px; letter-spacing: -.8px; line-height: 1; }
.smval span { font-family: var(--fb); font-size: 12px; color: var(--fog); margin-left: 3px; }
.smsub { font-size: 11px; color: var(--grv); margin-top: 6px; }
.risk-card.risk-critical::before { background: var(--rc); }.risk-card.risk-high::before { background: var(--hi); }.risk-card.risk-medium::before { background: var(--blue); }.risk-card.risk-low::before { background: var(--ok); }
.method-note { display:grid; grid-template-columns:auto 1fr auto; gap:12px; align-items:center; padding:13px 16px; margin:-24px 0 44px; border:1px solid var(--ch); border-radius:12px; background:var(--pw); color:var(--grv); font-size:12px; line-height:1.55; }
.method-note strong { color:var(--obs); white-space:nowrap; }.method-meta { font-family:var(--fm); font-size:10px; color:var(--fog); white-space:nowrap; }
.rsec { margin-bottom: 44px; }
.rsech { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.rsectl { font-size: 16px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.cbadge { font-size: 11px; font-weight: 500; padding: 2px 9px; border-radius: 9999px; background: var(--pw); color: var(--grv); border: 1px solid var(--ch); }
.empty { background: #fff; border: 1px solid var(--ch); border-radius: 16px; box-shadow: var(--sc); padding: 28px; text-align: center; color: var(--fog); font-size: 13px; }
/* REP3 */
.vcard { background: #fff; border-radius: 16px; border: 1px solid var(--ch); box-shadow: var(--sc); margin-bottom: 12px; overflow: hidden; transition: box-shadow .2s; }
.vcard:hover { box-shadow: 0 0 0 1px rgba(255, 107, 53, .2), 0 4px 20px rgba(255, 107, 53, .1); }
.vcardh { padding: 16px 20px; display: flex; align-items: center; gap: 12px; cursor: pointer; }
.vtag { font-family: var(--fm); font-size: 10px; padding: 4px 9px; border-radius: 5px; background: var(--obs); color: #fff; flex-shrink: 0; }
.vtit { font-size: 13px; font-weight: 600; flex: 1; }
.vloc { font-family: var(--fm); font-size: 11px; color: var(--fog); }
.vchev { color: var(--fog); font-size: 13px; transition: transform .2s; }
.vchev.open { transform: rotate(180deg); }
.vbody { padding: 0 20px 18px; }
.cblock { background: #f8f6f3; border: 1px solid var(--ch); border-radius: 10px; padding: 13px 16px; font-family: var(--fm); font-size: 12px; line-height: 1.75; margin-bottom: 12px; overflow-x: auto; }
.cln { display: flex; gap: 14px; }
.cno { color: var(--fog); min-width: 30px; text-align: right; }
.ctx { color: var(--obs); white-space: pre; }
.cln.hl { background: rgba(255, 107, 53, .1); margin: 0 -16px; padding: 0 16px; border-radius: 4px; }
.cln.hl .ctx { color: #9a3a1e; font-weight: 500; }
.vfield { margin-bottom: 12px; }
.vfl { font-size: 10px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; color: var(--fog); margin-bottom: 5px; }
.vfv { font-size: 12.5px; color: var(--grv); line-height: 1.65; }
/* REP4 */
.ebpflog { background: #141210; border-radius: 10px; padding: 13px 16px; margin-bottom: 12px; border: 1px solid #2a2520; }
.ebh { display: flex; align-items: center; gap: 8px; font-size: 11px; color: #665f55; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid #221e19; }
.ebtag { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; background: #7c3aed; color: #fff; }
.erow { display: grid; grid-template-columns: 1.2fr 1.1fr 1fr 1.4fr; gap: 6px; font-family: var(--fm); font-size: 11px; padding: 4px 0; border-bottom: 1px solid #1a1715; }
.erow:last-child { border-bottom: none; }
.erow.ehead { font-size: 10px; color: #3d3730; margin-bottom: 4px; }
.ets { color: #6b6359; }
.eev { color: #ef4444; }
.efn { color: #34d399; }
.ead { color: #c084fc; word-break: break-all; }
.crashbox { background: #141210; border-radius: 10px; padding: 13px 16px; margin-bottom: 12px; border: 1px solid #2a2520; }
.crashbox pre { font-family: var(--fm); font-size: 11px; color: #f59e0b; line-height: 1.6; white-space: pre-wrap; word-break: break-all; max-height: 220px; overflow-y: auto; }
.advbox { display: flex; gap: 10px; padding: 13px 15px; border-radius: 10px; background: linear-gradient(135deg, rgba(255, 107, 53, .06), rgba(247, 166, 80, .04)); border: 1px solid rgba(255, 107, 53, .2); }
.advico { font-size: 14px; flex-shrink: 0; margin-top: 1px; }
.advtxt { font-size: 12.5px; color: var(--grv); line-height: 1.6; }
.advtxt strong { color: var(--obs); }
/* eBPF纠正高亮框 */
.corrbox { padding: 12px 15px; border-radius: 10px; background: linear-gradient(135deg, rgba(124, 58, 237, .08), rgba(192, 132, 252, .05)); border: 1px solid rgba(124, 58, 237, .25); margin-bottom: 12px; }
.corrh { font-size: 11px; font-weight: 700; color: #7c3aed; margin-bottom: 6px; }
.corrb { font-size: 12px; color: var(--grv); line-height: 1.6; }
.corrb code { font-family: var(--fm); font-size: 11px; padding: 2px 6px; background: rgba(124, 58, 237, .1); border-radius: 4px; color: #7c3aed; }
.b-ebpf { background: linear-gradient(135deg, #7c3aed, #a78bfa); color: #fff; font-weight: 600; }
/* REP5 */
.rtwrap { background: #fff; border-radius: 16px; border: 1px solid var(--ch); box-shadow: var(--sc); overflow: hidden; }
.rtable { width: 100%; border-collapse: collapse; }
.rtable th { text-align: left; padding: 10px 16px; font-size: 11px; font-weight: 700; color: var(--fog); letter-spacing: .4px; border-bottom: 1px solid var(--ch); }
.rtable td { padding: 12px 16px; border-bottom: 1px solid var(--ch); font-size: 13px; }
.rtable tr:last-child td { border-bottom: none; }
.rtable tr:hover td { background: var(--w4); }
.rtable .mono { font-family: var(--fm); font-size: 12px; }
.rtable .strong { font-weight: 600; }
.rtable .soft { color: var(--grv); }
.cvea { font-family: var(--fm); font-size: 11px; color: var(--blue); text-decoration: none; }
.cvea:hover { text-decoration: underline; }
.cs { font-family: var(--fm); font-size: 12px; }
.cs.hi { color: var(--rc); }
.cs.med { color: var(--hi); }
.cs.lo { color: var(--ok); }

@media (max-width: 900px) {
  .page-report { padding: 48px 18px; }
  .rhdr { grid-template-columns: 1fr; gap: 16px; }
  .smgrid { grid-template-columns: 1fr 1fr; }
  .method-note { grid-template-columns: 1fr; margin-top: -26px; }.method-meta { white-space:normal; }
}
</style>
