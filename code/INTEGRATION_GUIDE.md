# 接口集成说明

后端通过以下两个内部接口调用 Agent 服务：

- `POST /api/agent-a/analyze`：依赖与 CVE 分析。
- `POST /api/agent-b/audit`：静态审计流程与 Harness 生成。

共享源码目录必须位于 Agent 的 `AGENT_ALLOWED_SOURCE_ROOTS` 允许范围内。默认 Docker Compose 配置中，任务执行器与 Agent 均将 `uploads_data` 数据卷挂载到 `/app/uploads`。

客户端使用以下后端接口：

- `POST /api/v1/tasks`：创建源码记录；
- `POST /api/v1/audit/submit`：提交审计任务；
- `GET /api/v1/audit/status/{task_id}`：轮询任务状态，作为实时连接的备用方式；
- `WS /api/v1/ws/tasks/{task_id}/progress`：接收实时进度；
- `GET /api/v1/tasks/{task_id}/report`：获取结构化报告；
- `GET /api/v1/tasks/{task_id}/export-pdf`：导出 PDF。

生产代码不包含伪造 Agent 响应的分支。测试应在 HTTP 接口边界使用模拟响应，或让真实 Agent 分析固定测试样本。
