# SC-SENTINEL 比赛答辩运行手册

## 1. 当前产品口径

SC-SENTINEL 是面向 C/C++ 软件供应链的证据驱动安全审计平台。系统使用七阶段链路：

1. Agent A：解析依赖与组件元数据，查询 OSV/NVD 风险；
2. Agent B：函数级语义切片和调用上下文提取；
3. Agent C：生成可解释漏洞假设；
4. Agent D：规则与受约束 LLM 交叉审计；
5. Agent E：按 CWE 生成 Harness 与种子；
6. Agent F：归因 ASan、AFL++ 和 eBPF 事件；
7. Agent G：汇总证据并输出裁决。

报告严格区分四种结论：

- `confirmed`：存在强运行时复现证据；
- `unverified`：静态候选，尚未完成有效动态验证；
- `not_reproduced`：已运行动态验证，但在当前时间和种子预算内未触发；
- `false_positive`：经人工或确定性规则明确排除。

“未复现”不等于“误报”。eBPF 是运行时旁证和强事件纠错来源之一，不替代 ASan 的内存错误诊断，也不承诺在非特权环境中可用。

## 2. 答辩前启动

```powershell
Copy-Item .env.example .env
# 编辑 .env：至少设置 POSTGRES_PASSWORD；配置 LLM 三项可启用语义审计
powershell -ExecutionPolicy Bypass -File scripts/preflight.ps1
docker compose --profile sandbox build
docker compose up -d
docker compose ps
```

访问入口：

- 前端：http://localhost:8080
- OpenAPI：http://localhost:18000/docs
- 健康检查：http://localhost:18000/health

首次构建后，确认 `db`、`redis`、`agent`、`api`、`worker`、`frontend` 均处于运行状态。`sandbox` 是按任务短暂启动的运行镜像，不需要常驻。

## 3. 稳定演示路径

生成仓库自带的确定性演示包：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_demo_bundle.ps1
```

在“新建审计”页面上传 `tmp/SC-SENTINEL-demo.zip`，建议演示顺序：

1. 展示扫描策略和动态验证说明；
2. 提交后展示真实 WebSocket 日志和流水线状态；
3. 报告页先讲风险评分，再展开第一条已确认的漏洞发现；
4. 指出代码定位、触发条件、ASan/AFL++ 输出和 eBPF 事件各自的职责；
5. 展示“未复现”（`not_reproduced`）与“候选问题”（`candidate`）的区别，强调系统没有把有限预算下的未触发伪装成误报；
6. 导出 PDF，说明 Web 报告和可交付报告使用同一数据库证据源。

正式答辩前至少完整跑通一次，并保留已完成任务。现场优先展示已完成报告，再新建任务演示实时链路，避免把网络或 LLM 响应时间变成单点故障。

## 4. 两种运行模式

| 模式 | LLM | 动态沙箱 | 适用场景 |
|---|---|---|---|
| 规则回退 | 未配置 | 可选 | 离线演示、环境自检、确定性基线 |
| 完整审计 | 已配置 | 推荐 | 正式评测、语义审计与动态证据闭环 |

普通 Docker Desktop 环境默认以非特权方式运行 ASan/AFL++。只有隔离的专用 Linux 演示机才应设置 `SANDBOX_ALLOW_PRIVILEGED=true` 来启用需要特权的 eBPF 兼容路径。

## 5. 验收清单

- 后端测试全部通过；
- 前端 `npm run build` 通过；
- `docker compose config` 通过；
- ZIP 路径穿越、符号链接、压缩炸弹和超限文件被拒绝；
- 取消任务后数据库状态持久化，后续阶段不再启动；
- 报告显示实际证据来源，不把 AFL++ 崩溃 统一标成“eBPF 已确认”；
- PDF 中文无方块、表格无截断、年份与赛事一致；
- 演示机关闭无关代理与高占用应用，Docker 预留至少 2 CPU / 4GB 内存。

## 6. 评委常见问题

**为什么不是单次 LLM 扫描？** 真实仓库上下文过长且输出不稳定。系统先切片、再生成假设、再做封闭式审计，并要求动态证据才能升级结论。

**eBPF 是否能直接证明所有内存漏洞？** 不能。ASan 负责精确错误诊断，AFL++ 负责探索输入和产出复现样本，eBPF 提供透明运行时事件旁证；三者互补。

**未触发为什么不算安全？** Fuzzing 受时间、种子和覆盖率限制。系统因此使用 `not_reproduced`，保留静态风险和后续复核入口。

**供应链能力体现在哪里？** Agent A 从构建文件、包管理清单和 include 信息识别组件，复用一次 OSV/NVD 查询结果贯穿后续审计与报告，避免重复查询和上下文不一致。
