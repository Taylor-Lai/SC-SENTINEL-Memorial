# 接口集成说明

本文说明前端、后端与 Agent 之间的调用关系，便于阅读源码或单独连接已有服务。组件结构见 [系统架构](docs/ARCHITECTURE.md)，启动后可在 `http://localhost:18000/docs` 查看实际 OpenAPI 定义。

## 客户端调用顺序

创建任务和启动分析是两个步骤。前端先上传源码并获得 `task_id`，再用该 ID 提交审计，随后订阅进度并读取报告。

| 步骤 | 接口 | 说明 |
| --- | --- | --- |
| 创建任务 | `POST /api/v1/tasks` | 使用 multipart 表单上传 ZIP 或提交仓库地址 |
| 启动审计 | `POST /api/v1/audit/submit` | JSON 请求体为 `{"task_id": "已创建任务的 UUID"}` |
| 实时进度 | `WS /api/v1/ws/tasks/{task_id}/progress` | 接收阶段、进度与日志 |
| 查询进度 | `GET /api/v1/audit/status/{task_id}` | 实时连接之外的状态查询方式 |
| 历史列表 | `GET /api/v1/tasks` | 分页查询已有任务 |
| 任务详情 | `GET /api/v1/tasks/{task_id}` | 查询任务当前状态 |
| 审计报告 | `GET /api/v1/tasks/{task_id}/report` | 读取组件、漏洞、验证状态与证据 |
| PDF 导出 | `GET /api/v1/tasks/{task_id}/export-pdf` | 下载报告文件 |
| 取消任务 | `POST /api/v1/tasks/{task_id}/cancel` | 请求取消，结果应以接口响应和后续状态为准 |

创建任务时，`project_name` 为项目名称，`source_type` 为 `zip` 或 `github`。ZIP 模式提供 `file`；仓库模式提供 `source_path`。`is_dynamic` 使用字符串 `true` 或 `false`，`target_vulns` 如需填写则为 JSON 字符串数组。具体字段约束以 OpenAPI 为准。

API 路径中的 `github` 来源名称沿用早期实现，实际允许的托管域名由 [仓库访问策略](sentinel_backend/app/services/repository_policy.py) 决定。已离开等待状态的任务不能重复提交；需要再次分析时创建新任务。

## 响应与实时消息

普通业务成功响应包含 `code`、`message` 与 `data`。业务错误同时返回对应 HTTP 状态码；框架参数校验错误可能采用 FastAPI 的 `detail` 格式。PDF 导出是文件响应，不使用 JSON 包装。

WebSocket 进度消息包含 `stage`、`percent`、`message` 和 `log_stream`。客户端发送纯文本 `ping` 时，服务端回复纯文本 `pong`，应与 JSON 消息分别处理。连接时服务端会转发 Redis 中仍保留的进度事件，但 Redis 进度流有长度和过期限制，不应作为完整的永久审计日志。

前端调用实现见 [API 封装](sentinel_frontend/src/api/) 和 [WebSocket 逻辑](sentinel_frontend/src/composables/useWebSocket.ts)。

## 后端与 Agent 的内部接口

| 接口 | 请求内容 | 返回内容 |
| --- | --- | --- |
| `POST /api/agent-a/analyze` | 源码根目录，或依赖文件、include 与文件列表 | 组件风险、摘要与 Agent A 原始结果 |
| `POST /api/agent-b/audit` | 源码根目录、目标类型、已有组件上下文、是否生成 Harness | 静态发现、Harness 文件、阶段结果与初步报告 |
| `GET /health` | 无 | Agent 健康状态及 LLM 配置状态 |

`/api/agent-b/audit` 是后续分析流程的聚合接口，不只运行 Agent B。它不启动动态沙箱；Web 平台的动态执行由 Worker 另行完成。

源码根目录必须对 Worker 和 Agent 均可见，且处于 Agent 配置的 `AGENT_ALLOWED_SOURCE_ROOTS` 范围内。默认 Compose 将同一个 `uploads_data` 卷挂载到 `/app/uploads`，并设置该目录为允许根路径。手动部署时需要显式设置允许范围；未配置该变量时，当前实现不会施加这项根目录白名单限制。

请求和响应结构见 [service.py](sentinel_agent/service.py)，调用与结果保存见 [SBOM 任务](sentinel_backend/app/worker/sbom_task.py) 和 [静态审计任务](sentinel_backend/app/worker/llm_task.py)。

## 联调时的证据边界

组件 CVE 风险、静态候选与动态确认是不同层次的结果。调用成功或任务完成不代表所有候选问题均已复现，客户端应同时展示验证状态、证据来源和执行错误。

接口测试可以在 HTTP 边界使用模拟响应，端到端复现应由真实 Agent 分析固定样本，并明确区分测试替身与实际运行证据。演示登录不会为这些接口提供后端认证，外部部署需另行配置访问控制。

[返回代码导航](README.md)
