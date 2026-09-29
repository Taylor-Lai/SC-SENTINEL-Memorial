# SC-SENTINEL 比赛答辩运行手册

## 1. 当前产品口径

SC-SENTINEL 是基于多智能体的开源软件供应链二进制漏洞审计与验证系统，采用四层架构与五类智能体：

1. 依赖识别：解析组件和版本，关联 OSV/NVD 风险。
2. 漏洞假设：利用函数切片、调用关系和数据流线索生成假设。
3. 静态复核：结合规则与受约束 LLM 输出结构化发现。
4. 验证工件：生成 CWE 感知的 Harness 与种子，组织动态验证和证据归因。
5. 报告生成：汇总风险、运行证据和最终裁决。

三项核心技术为漏洞假设驱动的级联审计、CWE 感知的 Harness 自动生成、ASan/AFL++/eBPF 三源证据融合与类型纠偏。报告按 `confirmed`（已确认）、`need_review`（需复核）、`untriggered`（未触发）和 `unverified`（未验证）呈现动态状态。

## 2. 答辩前启动

```powershell
# 在 code/ 目录执行；首次配置时复制模板
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
- 健康检查：http://localhost:18000/health/ready

首次构建后，确认 `db`、`redis`、`agent`、`api`、`worker`、`frontend` 均处于运行状态。`sandbox` 是按任务短暂启动的运行镜像，不需要常驻。

## 3. 稳定演示路径

生成仓库自带的确定性演示包：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_demo_bundle.ps1
```

在“新建审计”页面上传 `tmp/SC-SENTINEL-demo.zip`，建议演示顺序：

1. 展示扫描策略和动态验证说明；
2. 提交后展示真实 WebSocket 日志和流水线状态；
3. 报告页先讲风险评分，再展开第一条 confirmed finding；
4. 指出代码定位、触发条件、ASan/AFL++ 输出和 eBPF 事件各自的职责；
5. 展示已确认、需复核、未触发与未验证的证据与处理方式；
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
- 报告显示实际证据来源，不把 AFL++ crash 统一标成“eBPF 已确认”；
- PDF 中文无方块、表格无截断、年份与赛事一致；
- 演示机关闭无关代理与高占用应用，Docker 预留至少 2 CPU / 4GB 内存。

## 6. 评委常见问题

**为什么不是单次 LLM 扫描？** 真实仓库上下文过长且输出不稳定。系统先切片、再生成假设、再做封闭式审计，并要求动态证据才能升级结论。

**eBPF 是否能直接证明所有内存漏洞？** 不能。ASan 负责精确错误诊断，AFL++ 负责探索输入和产出复现样本，eBPF 提供透明运行时事件旁证；三者互补。

**未触发为什么不算安全？** Fuzzing 受时间、种子和覆盖率限制。系统将其标记为未触发，保留静态风险和后续复核入口。

**供应链能力体现在哪里？** 依赖识别智能体从构建文件、包管理清单和 include 信息识别组件，复用一次 OSV/NVD 查询结果贯穿后续审计与报告，避免重复查询和上下文不一致。
