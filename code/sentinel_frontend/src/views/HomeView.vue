<template>
  <div class="page-home">
    <!-- HERO -->
    <div class="hero-wrap">
      <div class="hero">
        <div>
          <div class="hbadge reveal"><span class="hbdot" />开源软件供应链安全</div>
          <h1 class="htitle reveal reveal-delay-1">LLM suspects.<br /><span class="accent">eBPF confirms.</span></h1>
          <p class="hdesc reveal reveal-delay-2">SC-SENTINEL 是面向 C/C++ 供应链的证据驱动审计平台。五 Agent 精简流水线完成依赖扫描、代码审计、测试生成、动态验证与报告裁决；ASan、AFL++ 与 eBPF 各司其职，把静态候选转化为可复现、可追踪的运行时证据。</p>
          <div class="hactions reveal reveal-delay-3">
            <button class="bp bw" style="padding:11px 26px;font-size:14px" @click="router.push('/submit')">提交项目 →</button>
            <button class="bp bg" style="padding:11px 26px;font-size:14px" @click="router.push('/history')">查看任务</button>
          </div>
          <p class="hnote reveal reveal-delay-4">支持 .zip 上传 · GitHub 链接 · Docker 隔离沙箱 · 自动销毁 · eBPF 内核透明监控</p>
        </div>
        <div class="dcard-wrap reveal reveal-delay-2">
          <div class="dcard">
            <div class="dctop">
              <div class="dctop-row">
                <span class="dcname">vulnerable_server.zip</span>
                <div class="dclive"><span class="dldot" />Fuzzing · 65%</div>
              </div>
              <div class="dstages">
                <div class="ds"><div class="dsico done">✓</div><div class="dsin"><div class="dsn">Agent a：依赖识别智能体</div><div class="dss">SBOM 解析 · CVE 风险识别</div></div></div>
                <div class="ds"><div class="dsico done">✓</div><div class="dsin"><div class="dsn">Agent b：假设生成智能体</div><div class="dss">语义分析 · 候选漏洞假设</div></div></div>
                <div class="ds"><div class="dsico done">✓</div><div class="dsin"><div class="dsn">Agent c：静态复核智能体</div><div class="dss">规则预筛 · LLM 深度复核</div></div></div>
                <div class="ds"><div class="dsico run">⬡</div><div class="dsin"><div class="dsn">Agent d：验证工件智能体</div><div class="dss">Fuzzing 运行中 · eBPF 旁证采集</div><div class="dspbar"><div class="dspfill" /></div></div></div>
                <div class="ds"><div class="dsico wait">◎</div><div class="dsin"><div class="dsn">Agent e：报告生成智能体</div><div class="dss">等待动态证据归因与最终裁决</div></div></div>
              </div>
            </div>
            <div class="dcbody">
              <div class="dflabel">已确认发现</div>
              <div class="dfrow"><span class="dftag">UAF</span><span class="dffile">parser.c:247</span><span class="dbadge b-ok">● 运行时已复现</span></div>
              <div class="dfrow"><span class="dftag">HEAP-OVF</span><span class="dffile">network.c:891</span><span class="dbadge b-cr">严重</span></div>
              <div class="dfrow"><span class="dftag">DBL-FREE</span><span class="dffile">cache.c:134</span><span class="dbadge b-un">验证中…</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- FEATURES -->
    <div class="feat-strip">
      <div class="feat-bg" />
      <div class="feat-inner">
        <div class="fitem reveal"><div class="fnum">3<sub> 类证据源</sub></div><div class="ftit">三源动态证据闭环</div><div class="fdesc">ASan 提供精确错误类型，AFL++ 产出可复现输入，eBPF 在可用时提供内核侧事件旁证。报告明确展示每条结论实际具备的证据来源。</div></div>
        <div class="fitem reveal reveal-delay-1"><div class="fnum">5<sub> 个智能体</sub></div><div class="ftit">精简高效五 Agent 流水线</div><div class="fdesc">依赖扫描 → 代码审计 → 测试生成 → 动态验证 → 报告生成，全链路自动化追溯，零冗余设计。</div></div>
        <div class="fitem reveal reveal-delay-2"><div class="fnum">∞<sub> 隔离任务</sub></div><div class="ftit">Docker 隔离沙箱</div><div class="fdesc">每次 Fuzzing 在独立容器内执行，完成后自动销毁；bpftrace 探针运行在内核层，对被测程序完全透明。</div></div>
      </div>
    </div>

    <!-- PIPELINE -->
    <div class="pipe-section">
      <div class="eyebrow reveal">工作原理</div>
      <h2 class="sec-h reveal reveal-delay-1">五 Agent 精简流水线，<em>从依赖到内核</em></h2>
      <p class="sec-s reveal reveal-delay-2">1→5 单向流水线，每一步都留下可追溯 ID；LLM 封闭式判定，ASan + AFL++ + eBPF 三源印证。</p>
      <div class="pipe-cards reveal reveal-delay-3">
        <div class="pc"><div class="pc-num">01</div><div class="pc-tag ta">Agent a</div><div class="pc-name">依赖识别智能体</div><div class="pc-desc">解析 CMakeLists / Makefile / vcpkg / Conan，并行查询 OSV + NVD，输出 SBOM 与组件风险画像。</div></div>
        <div class="pc"><div class="pc-num">02</div><div class="pc-tag tp">Agent b</div><div class="pc-name">假设生成智能体</div><div class="pc-desc">基于源码切片和依赖上下文提出可解释的漏洞假设，标注 CWE 类型与候选位置。</div></div>
        <div class="pc"><div class="pc-num">03</div><div class="pc-tag tp">Agent c</div><div class="pc-name">静态复核智能体</div><div class="pc-desc">规则预筛结合 LLM 深度复核，确认数据流、边界条件与可达路径，降低误报。</div></div>
        <div class="pc"><div class="pc-num">04</div><div class="pc-tag te">Agent d</div><div class="pc-name">验证工件智能体</div><div class="pc-desc">生成并执行 ASan / AFL++ Harness，在 Docker 沙箱中采集崩溃输入与 eBPF 运行时旁证。</div></div>
        <div class="pc"><div class="pc-num">05</div><div class="pc-tag tr">Agent e</div><div class="pc-name">报告生成智能体</div><div class="pc-desc">汇总五个智能体的结构化结果，生成可下载 PDF 报告和可追溯证据链。</div></div>
      </div>
    </div>

    <!-- COMPARE -->
    <div class="cmp-section">
      <div class="cmp-inner">
        <div class="eyebrow reveal">为什么选择 SC-SENTINEL</div>
        <h2 class="sec-h reveal reveal-delay-1">不只是静态扫描，而是可触发的证据</h2>
        <p class="sec-s reveal reveal-delay-2" style="margin-bottom:40px">对比纯 LLM 代码审计，SC-SENTINEL 在每个核心维度都提供了更强的保障</p>
        <table class="cmp-table reveal reveal-delay-3">
          <thead><tr><th>维度</th><th>纯 LLM 代码审计</th><th>SC-SENTINEL</th></tr></thead>
          <tbody>
            <tr><td>结果可信度</td><td>LLM 推测，误报率高</td><td>区分静态候选、当前未复现与运行时确认，附 ASan / crash / eBPF 证据 <span class="tw-pill">✓</span></td></tr>
            <tr><td>LLM 使用方式</td><td>开放式问答，容易幻觉</td><td>假设驱动封闭式判定，规则交叉校验 <span class="tw-pill">✓</span></td></tr>
            <tr><td>分析视角</td><td>仅看源码文本</td><td>源码 + 运行时内核事件双视角 <span class="tw-pill">✓</span></td></tr>
            <tr><td>供应链感知</td><td>不感知依赖引入风险</td><td>OSV + NVD 双源查询，识别第三方 CVE 风险 <span class="tw-pill">✓</span></td></tr>
            <tr><td>eBPF 运用</td><td style="color:var(--fog)">无</td><td>uprobe 监控 malloc / free / printf，反向纠正 LLM 类型 <span class="tw-pill">✓</span></td></tr>
            <tr><td>验证手段</td><td style="color:var(--fog)">无</td><td>ASan + AFL++ + eBPF 三源归因，判定矩阵可解释 <span class="tw-pill">✓</span></td></tr>
            <tr><td>Harness 自动化</td><td style="color:var(--fog)">无</td><td>按 CWE 路由策略，ASan / AFL++ / libFuzzer 三套自动构建 <span class="tw-pill">✓</span></td></tr>
            <tr><td>可追溯性</td><td>结论黑盒，来源不可知</td><td>slice → hypothesis → finding → harness → evidence 全链路 ID <span class="tw-pill">✓</span></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

function checkReveal() {
  document.querySelectorAll('.page-home .reveal').forEach((el) => {
    const r = el.getBoundingClientRect()
    if (r.top < window.innerHeight - 60) el.classList.add('in')
  })
}

onMounted(() => {
  setTimeout(checkReveal, 80)
  window.addEventListener('scroll', checkReveal, { passive: true })
})
onUnmounted(() => window.removeEventListener('scroll', checkReveal))
</script>

<style scoped>
.hero-wrap { position: relative; overflow: hidden; padding: 0 44px; }
.hero { max-width: 1200px; margin: 0 auto; padding: 96px 0 88px; display: grid; grid-template-columns: 1fr 460px; gap: 72px; align-items: center; position: relative; z-index: 1; }
.hbadge { display: inline-flex; align-items: center; gap: 7px; padding: 5px 13px; border-radius: 9999px; border: 1px solid rgba(255, 107, 53, .3); background: rgba(255, 107, 53, .07); font-size: 11px; font-weight: 600; color: #c4430a; letter-spacing: .6px; text-transform: uppercase; margin-bottom: 28px; }
.hbdot { width: 6px; height: 6px; border-radius: 50%; background: var(--w1); animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: .4; transform: scale(.7); } }
.htitle { font-family: var(--fd); font-size: 62px; font-weight: 400; line-height: 1.04; letter-spacing: -1.2px; margin-bottom: 22px; }
.accent { background: linear-gradient(135deg, var(--w1) 0%, var(--amber) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.hdesc { font-size: 15.5px; line-height: 1.7; color: var(--grv); max-width: 480px; margin-bottom: 36px; }
.hactions { display: flex; gap: 10px; align-items: center; }
.hnote { font-size: 11.5px; color: var(--fog); margin-top: 14px; }
/* CHUNK2 */
.dcard-wrap { perspective: 1200px; }
.dcard { background: #fff; border-radius: 22px; box-shadow: 0 2px 2px rgba(0, 0, 0, .04), 0 12px 40px rgba(0, 0, 0, .12), 0 0 0 1px rgba(0, 0, 0, .06); overflow: hidden; transform: rotateY(-4deg) rotateX(2deg); transition: transform .5s cubic-bezier(.22, 1, .36, 1); }
.dcard-wrap:hover .dcard { transform: rotateY(0deg) rotateX(0deg); }
.dctop { background: linear-gradient(160deg, #161210 0%, #2c2016 100%); padding: 18px 20px 14px; border-bottom: 1px solid rgba(255, 255, 255, .07); }
.dctop-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.dcname { font-size: 13px; font-weight: 600; color: #fff; }
.dclive { display: flex; align-items: center; gap: 5px; font-size: 11px; color: rgba(255, 255, 255, .4); }
.dldot { width: 6px; height: 6px; border-radius: 50%; background: #34d399; animation: pulse 1.5s infinite; }
.dstages { padding: 4px 0 8px; }
.ds { display: flex; align-items: center; gap: 10px; padding: 7px 0; border-bottom: 1px solid rgba(255, 255, 255, .055); }
.ds:last-child { border-bottom: none; }
.dsico { width: 26px; height: 26px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 11px; flex-shrink: 0; }
.dsico.done { background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; }
.dsico.run { background: rgba(255, 255, 255, .1); color: rgba(255, 255, 255, .5); animation: blink 1.8s infinite; }
.dsico.wait { background: rgba(255, 255, 255, .05); color: rgba(255, 255, 255, .2); }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
.dsin { flex: 1; }
.dsn { font-size: 12px; font-weight: 500; color: rgba(255, 255, 255, .85); }
.dss { font-size: 11px; color: rgba(255, 255, 255, .36); margin-top: 1px; }
.dspbar { height: 2px; background: rgba(255, 255, 255, .08); border-radius: 9999px; margin-top: 5px; overflow: hidden; }
.dspfill { height: 100%; border-radius: 9999px; background: linear-gradient(90deg, var(--w1), var(--amber)); width: 65%; animation: grow 2s ease-out both; }
@keyframes grow { from { width: 0; } }
.dcbody { padding: 16px 20px 18px; }
.dflabel { font-size: 10px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase; color: var(--fog); margin-bottom: 10px; }
.dfrow { display: flex; align-items: center; gap: 8px; padding: 7px 0; border-bottom: 1px solid var(--ch); font-size: 12px; }
.dfrow:last-child { border-bottom: none; }
.dftag { font-family: var(--fm); font-size: 10px; padding: 3px 7px; border-radius: 4px; background: var(--obs); color: #fff; flex-shrink: 0; }
.dffile { color: var(--grv); flex: 1; font-family: var(--fm); font-size: 11px; }
/* CHUNK3 */
.feat-strip { border-top: 1px solid var(--ch); position: relative; overflow: hidden; }
.feat-bg { position: absolute; inset: 0; background: linear-gradient(180deg, var(--w4) 0%, transparent 100%); opacity: .8; }
.feat-inner { max-width: 1200px; margin: 0 auto; padding: 64px 44px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 52px; position: relative; z-index: 1; }
.fnum { font-family: var(--fd); font-size: 44px; line-height: 1; margin-bottom: 10px; background: linear-gradient(135deg, var(--w1), var(--amber)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.fnum sub { font-size: 15px; color: var(--grv); font-family: var(--fb); -webkit-text-fill-color: var(--grv); }
.ftit { font-size: 14px; font-weight: 600; margin-bottom: 6px; }
.fdesc { font-size: 13px; color: var(--grv); line-height: 1.6; }

.pipe-section { max-width: 1200px; margin: 0 auto; padding: 100px 44px; }
.eyebrow { font-size: 11px; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; color: var(--w1); margin-bottom: 14px; }
.sec-h { font-family: var(--fd); font-size: 46px; letter-spacing: -.9px; line-height: 1.1; margin-bottom: 14px; }
.sec-h em { font-style: italic; color: var(--grv); }
.sec-s { font-size: 15px; color: var(--grv); max-width: 520px; margin-bottom: 56px; line-height: 1.65; }
.pipe-cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1px; background: var(--ch); border-radius: 20px; overflow: hidden; box-shadow: var(--sc); }
.pc { background: #fff; padding: 26px 20px; position: relative; overflow: hidden; transition: all .25s; }
.pc::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--ch); transition: background .25s; }
.pc:hover::before { background: linear-gradient(90deg, var(--w1), var(--amber)); }
.pc:hover { background: var(--w4); }
.pc-num { font-family: var(--fd); font-size: 26px; color: var(--ch); margin-bottom: 12px; line-height: 1; }
.pc-tag { display: inline-flex; font-size: 10px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; padding: 3px 9px; border-radius: 9999px; margin-bottom: 12px; }
.ta { background: rgba(255, 107, 53, .1); color: #c4430a; }
.tp { background: rgba(139, 92, 246, .1); color: #5b21b6; }
.te { background: rgba(42, 95, 212, .1); color: #1a47b3; }
.tr { background: rgba(29, 138, 86, .1); color: #166842; }
.pc-name { font-size: 13.5px; font-weight: 600; margin-bottom: 8px; }
.pc-desc { font-size: 12px; color: var(--grv); line-height: 1.55; }
/* CHUNK4 */
.cmp-section { background: var(--pw); border-top: 1px solid var(--ch); border-bottom: 1px solid var(--ch); padding: 100px 0; }
.cmp-inner { max-width: 1200px; margin: 0 auto; padding: 0 44px; }
.cmp-table { width: 100%; border-collapse: collapse; border-radius: 16px; overflow: hidden; box-shadow: var(--sc); }
.cmp-table th { text-align: left; padding: 13px 20px; border-bottom: 1px solid var(--ch); font-size: 11px; font-weight: 700; letter-spacing: .4px; background: #fff; }
.cmp-table th:last-child { background: linear-gradient(160deg, #161210, #2c2016); color: #fff; }
.cmp-table td { padding: 13px 20px; border-bottom: 1px solid var(--ch); color: var(--grv); }
.cmp-table td:first-child { color: var(--obs); font-weight: 500; }
.cmp-table td:last-child { background: rgba(255, 107, 53, .04); color: var(--obs); font-weight: 500; }
.cmp-table tr:last-child td { border-bottom: none; }
.cmp-table tr:hover td { background: rgba(255, 107, 53, .03); }
.cmp-table tr:hover td:last-child { background: rgba(255, 107, 53, .08); }
.tw-pill { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 9999px; background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; }

@media (max-width: 1280px) {
  .pipe-cards { grid-template-columns: repeat(3, 1fr); }
}
@media (max-width: 980px) {
  .hero { grid-template-columns: 1fr; gap: 48px; padding: 64px 0; }
  .htitle { font-size: 46px; }
  .feat-inner { grid-template-columns: 1fr; gap: 36px; }
  .pipe-cards { grid-template-columns: 1fr 1fr; }
  .sec-h { font-size: 34px; }
}
@media (max-width: 560px) {
  .pipe-cards { grid-template-columns: 1fr; }
}
</style>
