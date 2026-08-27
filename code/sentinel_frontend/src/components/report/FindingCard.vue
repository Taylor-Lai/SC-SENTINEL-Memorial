<template>
  <article class="vcard" :class="`grade-${finding.evidence_grade}`">
    <button class="vcardh" type="button" :aria-expanded="opened" @click="opened = !opened">
      <span class="vtag">{{ finding.cwe_id || vulnTag }}</span>
      <span class="vtit">{{ vulnTitle }}</span>
      <span class="vloc">{{ formatLocation(finding.file_path, finding.line_number) }}</span>
      <span v-if="finding.ebpf_corrected" class="pill correction" title="运行时强证据纠正了静态分类">⚡ 已纠正</span>
      <span class="pill" :class="statusClass">{{ statusLabel }}</span>
      <span class="vchev" :class="{ open: opened }">▾</span>
    </button>

    <div v-show="opened" class="vbody">
      <div class="evidence-bar">
        <span class="evidence-title">证据链</span>
        <span v-for="source in finding.evidence_sources" :key="source" class="source" :class="`source-${source}`">{{ sourceLabel(source) }}</span>
        <span class="grade">{{ gradeLabel }}</span>
      </div>

      <div v-if="finding.ebpf_corrected && finding.llm_original_type" class="corrbox">
        <strong>运行时分类纠正</strong>
        <span>静态阶段初判 <code>{{ finding.llm_original_type }}</code>，强运行时事件指向 <code>{{ finding.vuln_type }}</code>；原始结论被保留用于审计追踪。</span>
      </div>

      <div v-if="finding.code_context" class="cblock">
        <div v-for="(line, index) in codeLines" :key="index" class="cln" :class="{ hl: line.highlighted }">
          <span class="cno">{{ line.number }}</span><span class="ctx">{{ line.text }}</span>
        </div>
      </div>

      <div class="evidence-narrative">
        <div class="narrative-head">证据链 Evidence Chain</div>
        <div class="narrative-location">定位 Location <strong>{{ formatLocation(finding.file_path, finding.line_number) }}</strong></div>
        <div class="narrative-content" v-html="evidenceNarrative"></div>
      </div>

      <div v-if="finding.ebpf_logs.length" class="terminal">
        <div class="term-head"><span class="term-tag purple">eBPF</span><span>运行时事件 · 内核侧旁证</span></div>
        <div class="event-row event-head"><span>时间戳（ns）</span><span>事件</span><span>函数</span><span>内存地址</span></div>
        <div v-for="(event, index) in finding.ebpf_logs" :key="index" class="event-row">
          <span class="muted">{{ event.timestamp }}</span><span class="danger">{{ event.event_type }}</span>
          <span class="success">{{ event.function_name || '—' }}</span><span class="address">{{ event.memory_addr || '—' }}</span>
        </div>
      </div>

      <div v-if="finding.crash_output" class="terminal crash">
        <div class="term-head"><span class="term-tag red">运行时</span><span>ASan / AFL++ 输出</span></div>
        <pre>{{ finding.crash_output }}</pre>
      </div>

      <div class="fixbox">
        <span>修复建议 Remediation</span><p>{{ localizedFix }}</p>
      </div>
    </div>
  </article>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import type { Vulnerability } from '@/types/api'
import { displayUnknown, vulnerabilityLabel } from '@/utils/display'

const props = withDefaults(defineProps<{ finding: Vulnerability; initiallyOpen?: boolean }>(), { initiallyOpen: false })
const opened = ref(props.initiallyOpen)

const vulnTitle = computed(() => vulnerabilityLabel(props.finding.vuln_type))
const vulnTag = computed(() => props.finding.vuln_type.toUpperCase())
const statusLabel = computed(() => ({
  confirmed: '运行时已复现', unverified: '待验证', not_reproduced: '当前预算未复现', false_positive: '已排除'
}[props.finding.verify_status] || props.finding.verify_status))
const statusClass = computed(() => `status-${props.finding.verify_status}`)
const gradeLabel = computed(() => ({
  corroborated: 'A · 多源印证', runtime_confirmed: 'B · 单源复现', partial_evidence: 'C · 部分旁证',
  candidate: 'D · 静态候选', not_reproduced: '动态未复现', dismissed: '已排除'
}[props.finding.evidence_grade] || props.finding.evidence_grade))
const codeLines = computed(() => (props.finding.code_context || '').split('\n').filter(Boolean).map((raw) => {
  const matched = raw.match(/^\s*(\d+)\s*:\s?(.*)$/)
  const number = matched?.[1] || ''
  return { number, text: matched?.[2] || raw, highlighted: number === String(props.finding.line_number ?? '') }
}))

function formatLocation(filePath: string | null, lineNumber: number | null): string {
  const file = displayUnknown(filePath)
  if (!lineNumber) return file
  return `${file} : ${lineNumber}`
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

// Consolidate the original detector signal and reviewer-friendly explanation
// in one place, instead of rendering the same finding twice below the code.
const evidenceNarrative = computed(() => {
  const vuln = props.finding
  const type = vuln.vuln_type.toLowerCase()
  const file = vuln.file_path || 'unknown'
  const line = vuln.line_number || '?'
  const originalSignal = vuln.trigger_condition
    ? `<div class="original-signal"><b>Original signal:</b> <code>${escapeHtml(vuln.trigger_condition)}</code></div>`
    : ''

  if (type.includes('use_after_free') || type.includes('uaf')) {
    return `${originalSignal}<strong>Use-After-Free (UAF)</strong>：对象释放后仍沿原指针被访问，生命周期边界没有闭合。攻击者可借由可控输入触发 stale pointer 访问，造成崩溃、信息泄露，严重时可能影响控制流。<br/><em>建议重点复核 free 后的指针置空、错误分支与并发访问路径。</em>`
  }

  if (type.includes('double_free')) {
    return `${originalSignal}<strong>Double Free</strong>：同一堆对象可能沿两条清理路径重复释放，破坏 allocator 元数据。若释放时机可被输入控制，可能引发 heap corruption 或拒绝服务。<br/><em>建议核对 ownership、引用计数与所有 error cleanup 分支。</em>`
  }

  if (type.includes('buffer_overflow') || type.includes('overflow')) {
    return `${originalSignal}<strong>Buffer Overflow</strong>：复制长度或目标缓冲区容量缺少同一数据流内的严格校验，写入可能越过 destination boundary，覆盖相邻内存。<br/><em>关注 memcpy/strcpy 的 length 与 destination capacity 是否在复制前完成一致性校验。</em>`
  }

  if (type.includes('null_pointer') || type.includes('nullptr')) {
    return `${originalSignal}<strong>Null Pointer Dereference</strong>：对象创建或查找失败后缺少空值检查即被解引用，可能造成异常退出。<br/><em>重点检查初始化、分配和错误返回路径的 guard condition。</em>`
  }

  return `${originalSignal}<strong>${escapeHtml(vulnTitle.value)}</strong>：检测器在 <code>${escapeHtml(file)}:${line}</code> 附近发现潜在内存安全风险。当前结论为静态候选或运行时证据的综合结果，需结合输入边界、资源生命周期与调用链进一步复核。`
})

const localizedFix = computed(() => {
  const type = props.finding.vuln_type.toLowerCase()
  const original = props.finding.fix_suggestion?.trim()
  if (type.includes('use_after_free') || type.includes('uaf')) {
    return '统一对象所有权：释放后立即将指针置空，并确保所有后续访问先验证对象仍有效。对多分支清理逻辑采用单一释放出口或引用计数，补充释放后访问的回归测试。'
  }
  if (type.includes('double_free')) {
    return '为该对象明确唯一 owner，所有清理分支只释放一次；释放后置空，并在错误处理路径中使用统一 cleanup 标签或状态位，避免同一资源被重复回收。'
  }
  if (type.includes('overflow')) {
    return '在复制前同时校验 source length 与 destination capacity，拒绝超过上限的输入；使用带容量参数的安全封装，并让长度计算、缓冲区分配和复制操作使用同一受验证的 size 值。'
  }
  return original ? `建议：${original}` : '建议为风险点补充显式前置校验，并围绕边界输入、异常路径和资源释放路径增加回归测试。'
})

function sourceLabel(source: string) {
  return { static: '静态分析', asan: 'ASan', afl: 'AFL++', ebpf: 'eBPF' }[source] || source.toUpperCase()
}
</script>

<style scoped>
.vcard { background:#fff; border:1px solid var(--ch); border-radius:16px; box-shadow:var(--sf); margin-bottom:12px; overflow:hidden; border-left:4px solid var(--ch); }
.grade-corroborated,.grade-runtime_confirmed { border-left-color:var(--ok); }
.grade-partial_evidence,.grade-candidate { border-left-color:var(--hi); }
.grade-not_reproduced { border-left-color:var(--blue); }
.vcardh { width:100%; padding:16px 18px; display:flex; align-items:center; gap:10px; border:0; background:#fff; color:var(--obs); text-align:left; cursor:pointer; font-family:var(--fb); }
.vcardh:hover { background:var(--w5); }
.vtag { font-family:var(--fm); font-size:10px; padding:4px 8px; border-radius:5px; background:var(--obs); color:#fff; flex-shrink:0; }
.vtit { font-size:13px; font-weight:650; flex:1; }.vloc { font-family:var(--fm); font-size:11px; color:var(--fog); }
.pill { font-size:10px; font-weight:700; padding:3px 8px; border-radius:999px; white-space:nowrap; background:var(--pw); color:var(--grv); }
.status-confirmed { background:var(--obg); color:var(--ok); }.status-not_reproduced { background:var(--bbg); color:var(--blue); }.status-unverified { background:var(--hbg); color:var(--hi); }.correction { color:#7c3aed; background:#f3efff; }
.vchev { color:var(--fog); transition:transform .2s; }.vchev.open { transform:rotate(180deg); }.vbody { padding:0 18px 18px; }
.evidence-bar { display:flex; align-items:center; flex-wrap:wrap; gap:6px; padding:10px 12px; background:var(--pw); border-radius:9px; margin-bottom:12px; }
.evidence-title { font-size:10px; font-weight:700; color:var(--fog); margin-right:3px; }.source { font-family:var(--fm); font-size:9px; font-weight:700; padding:3px 7px; border:1px solid var(--ch); border-radius:4px; background:#fff; }.source-asan { color:#c2410c; }.source-afl { color:#b91c1c; }.source-ebpf { color:#7c3aed; }.grade { margin-left:auto; font-size:10px; font-weight:700; color:var(--grv); }
.corrbox { display:grid; gap:5px; padding:12px 14px; border:1px solid #ddd2fe; background:#f8f5ff; border-radius:9px; margin-bottom:12px; font-size:12px; color:var(--grv); }.corrbox strong { color:#7c3aed; }.corrbox code { color:#6d28d9; font-family:var(--fm); }
.cblock { background:#f8f6f3; border:1px solid var(--ch); border-radius:10px; padding:12px 15px; font-family:var(--fm); font-size:12px; line-height:1.75; margin-bottom:12px; overflow:auto; }.cln { display:flex; gap:14px; }.cno { color:var(--fog); min-width:32px; text-align:right; }.ctx { white-space:pre; }.cln.hl { background:rgba(255,107,53,.1); margin:0 -15px; padding:0 15px; }.cln.hl .ctx { color:#9a3a1e; font-weight:600; }
.evidence-narrative { margin-bottom:12px; padding:14px 15px; border:1px solid #d9e3ef; border-radius:10px; background:#f7fafc; color:var(--grv); line-height:1.75; font-size:12.5px; }.narrative-head { color:var(--obs); font-size:10px; font-weight:800; letter-spacing:.55px; margin-bottom:5px; }.narrative-location { font-family:var(--fm); font-size:11px; color:var(--fog); margin-bottom:8px; }.narrative-location strong { color:var(--obs); font-size:12px; }.narrative-content code { font-family:var(--fm); font-size:11px; color:#9a3a1e; }.original-signal { margin:0 0 9px; padding:8px 10px; border-left:3px solid var(--hi); background:#fff8eb; color:#6b5a3a; font:11px/1.55 var(--fm); word-break:break-word; }
.terminal { background:#141210; border:1px solid #2a2520; border-radius:10px; padding:13px 15px; margin-bottom:12px; }.term-head { display:flex; align-items:center; gap:8px; color:#777066; font-size:11px; padding-bottom:8px; margin-bottom:7px; border-bottom:1px solid #28231f; }.term-tag { color:#fff; font-size:9px; font-weight:800; padding:2px 7px; border-radius:4px; }.purple { background:#7c3aed; }.red { background:#c93b2a; }
.event-row { display:grid; grid-template-columns:1.2fr 1fr 1fr 1.3fr; gap:7px; padding:4px 0; font:10.5px var(--fm); border-bottom:1px solid #211d19; }.event-head { color:#5f5850; font-size:9px; }.muted { color:#777066; }.danger { color:#fb7185; }.success { color:#34d399; }.address { color:#c084fc; word-break:break-all; }.crash pre { color:#f59e0b; font:11px/1.6 var(--fm); max-height:240px; overflow:auto; white-space:pre-wrap; }
.fixbox { padding:15px 16px; border:1px solid rgba(255,107,53,.25); background:var(--w5); border-radius:10px; }.fixbox span { display:block; color:var(--w1); font-size:11px; font-weight:800; letter-spacing:.45px; margin-bottom:7px; }.fixbox p { margin:0; font-size:13px; color:var(--grv); line-height:1.75; }
@media(max-width:760px){.vloc{display:none}.pill.correction{display:none}.event-row{grid-template-columns:1fr 1fr}.event-head{display:none}.grade{width:100%;margin-left:0}.vcardh{align-items:flex-start;flex-wrap:wrap}}
</style>
