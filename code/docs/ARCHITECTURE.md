# 系统架构

SC-SENTINEL 采用前端展示、后端服务、多智能体审计和动态沙箱验证四层架构，形成依赖风险识别、漏洞审计、工件生成、动态验证和报告交付的完整闭环。

## 四层职责

| 层次 | 组成与职责 |
| --- | --- |
| 前端展示 | Vue 3 界面，提供任务提交、实时监控、历史查询与报告展示 |
| 后端服务 | FastAPI、TaskIQ Worker、Redis 与 PostgreSQL，负责接口、调度、进度和持久化 |
| 多智能体审计 | 依赖识别、漏洞假设、静态复核、验证工件和报告生成五类智能体 |
| 动态沙箱验证 | 源码任务在 Docker 沙箱执行 ASan、AFL++；专用环境可补充 eBPF 事件 |

## 审计数据流

1. 摄取项目源码与审计对象，识别依赖、版本和 CVE 风险。
2. 提取函数切片、调用关系与数据流线索，生成结构化漏洞假设。
3. 结合规则和受约束 LLM 静态复核，输出 Findings 与触发条件。
4. 依据 CWE 生成 Harness、种子、Makefile 与配置，完成质量门控。
5. 在隔离沙箱中分离编译目标代码与 Harness，执行 ASan 和 AFL++ 验证；专用环境可采集 eBPF 事件。
6. 关联已采集的运行证据，修正漏洞类型，生成 Web 与 PDF 报告。

切片、假设、Finding、Harness 与证据通过结构化标识关联。LLM 不可用时使用规则回退，任务进度通过 Redis 进度流与 WebSocket 传递。

上述六步对应源码 ZIP 与 Git 仓库路径。独立 ELF/PE 文件另走非执行式静态路径：校验文件格式，读取依赖库与导入符号，将危险 API 线索列为未验证候选并写入 Web/PDF 报告；这一路径不调用源码 Agent，也不生成 Harness 或进入动态沙箱。

## Harness 与证据闭环

Harness 包包含测试入口、构建文件、`harness_config.json`、说明、`seeds/` 与 `findings/`。目标代码独立编译，入口重命名限定于目标文件，保留 Harness 的测试入口。种子来源包括项目语料、上下文生成与 CWE 模板。

工件通过原型置信度、构建就绪、阻塞项、适配需求和编译检查等门控。ASan 提供错误类型与调用栈，AFL++ 提供触发样例和崩溃记录，启用时 eBPF 提供运行事件；证据按 Harness 和目标函数关联，完成强度分级与类型纠偏，同时保留原始模型判断供追踪。

| 对外报告验证状态 | 含义 |
| --- | --- |
| `confirmed`：已确认 | 强运行证据确认漏洞 |
| `unverified`：未验证 | 静态候选，尚未完成动态验证，需进一步复核 |
| `not_reproduced`：当前未复现 | 已执行动态验证，但当前预算内未触发目标漏洞 |
| `false_positive`：已排除 | 人工或确定性规则已排除的发现 |

Agent 的中间产物仍使用 `need_review`、`untriggered` 等字段值；对外任务报告以表中的后端 `verify_status` 为准。

## 部署与存储

API 与 Worker 通过内部网络访问 Agent，共享 `uploads_data` 卷传递源码和工件。Worker 使用 Docker Socket 启动任务沙箱，PostgreSQL 持久化任务和报告，Redis 承担队列与进度流。上传、报告和临时文件为运行数据，测试样本保存在 `sentinel_agent/samples/`。

部署命令见[Docker 指南](../DOCKER.md)，隔离策略见[安全说明](SECURITY.md)。完整设计依据[项目文档](../../materials/SC-SENTINEL-项目文档.pdf)与[答辩 PPT](../../materials/SC-SENTINEL-答辩PPT.pptx)。
