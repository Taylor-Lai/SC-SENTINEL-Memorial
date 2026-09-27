# SC-SENTINEL 比赛答辩运行手册

本文保留比赛期间使用的演示准备流程与答辩说明，供复盘和同类项目参考。复现时请结合当前环境调整；以下命令均在 `code/` 目录执行。

## 1. 比赛时的方案说明

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

## 2. 演示环境准备

```powershell
# 首次配置时复制；已有 .env 请保留
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
- 就绪检查：http://localhost:18000/health/ready

首次构建后，确认 `db`、`redis`、`agent`、`api`、`worker`、`frontend` 均处于运行状态。`sandbox` 是按任务短暂启动的运行镜像，不需要常驻。

## 3. 演示流程参考

生成仓库自带的固定样本演示包：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_demo_bundle.ps1
```

在“新建审计”页面上传 `tmp/SC-SENTINEL-demo.zip`，建议演示顺序：

1. 展示扫描策略和动态验证说明；
2. 提交后展示真实 WebSocket 日志和流水线状态；
3. 报告页先说明风险统计，再展开一条发现，按实际验证状态解读，不预设一定存在已确认结果；
4. 指出代码定位、触发条件、ASan/AFL++ 输出和 eBPF 事件各自的职责；
5. 展示“未复现”（`not_reproduced`）与“未验证”（`unverified`）的区别，说明有限预算下未触发的问题仍需保留后续复核空间；
6. 导出 PDF，说明 Web 报告和可交付报告使用同一数据库证据源。

复现演示时，建议先完整跑通一次并保留已完成任务。展示时先打开已有报告，再新建任务观察实时链路，可以减少网络或 LLM 响应延迟对演示的影响。

## 4. 分析配置与运行条件

| 模式 | LLM | 动态沙箱 | 适用场景 |
|---|---|---|---|
| 规则回退 | 未配置 | 可选 | 规则基线、环境自检与流程学习 |
| LLM 增强 | 已配置 | 可选 | 结合语义分析研究候选问题 |

LLM 增强与动态验证是独立选项。规则回退仍可能查询外部 CVE 数据源，不代表全流程离线可用；动态验证结果也受编译环境、输入种子和时间预算影响。

默认 Docker Desktop 部署以非特权方式运行 ASan/AFL++。只有隔离的专用 Linux 演示机才应设置 `SANDBOX_ALLOW_PRIVILEGED=true` 来启用需要特权的 eBPF 兼容路径。

## 5. 演示前检查

- 后端测试全部通过；
- 前端 `npm run build` 通过；
- `docker compose config` 通过；
- ZIP 路径穿越、符号链接、压缩炸弹和超限文件被拒绝；
- 取消任务后数据库状态持久化，后续阶段不再启动；
- 报告显示实际证据来源，不把 AFL++ 崩溃 统一标成“eBPF 已确认”；
- PDF 中文无方块、表格无截断、年份与赛事一致；
- 演示机关闭无关代理与高占用应用，Docker 预留至少 2 CPU / 4GB 内存。

## 6. 答辩问题参考

**为什么不是单次 LLM 扫描？** 真实仓库上下文过长且输出不稳定。系统先切片、再生成假设、再做封闭式审计，并要求动态证据才能升级结论。

**eBPF 是否能直接证明所有内存漏洞？** 不能。ASan 负责精确错误诊断，AFL++ 负责探索输入和产出复现样本，eBPF 提供透明运行时事件旁证；三者互补。

**未触发为什么不算安全？** Fuzzing 受时间、种子和覆盖率限制。系统因此使用 `not_reproduced`，保留静态风险和后续复核入口。

**供应链能力体现在哪里？** Agent A 从构建文件、包管理清单和 include 信息识别组件，将识别结果传给后续审计与报告；有组件上下文时复用已有结果，减少重复查询并保持分析背景一致。

[返回代码导航](../README.md) · [查看架构说明](ARCHITECTURE.md)
