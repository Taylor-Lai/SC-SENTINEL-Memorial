# SENTINEL 后端

后端使用 FastAPI 提供控制接口，通过 TaskIQ 任务执行器调度审计流程。

## 目录结构

```text
app/api/          HTTP 与 WebSocket 接口
app/core/         配置、数据库、消息队列与报告基础设施
app/models/       持久化业务模型
app/schemas/      API 数据结构
app/services/     源码接收与沙箱适配
app/worker/       持久化流水线阶段与生命周期中间件
alembic/          数据库迁移
tests/            独立的单元测试与接口契约测试
```

依赖安装以 `requirements.txt` 为入口，其中 `constraints.txt` 固定本次归档验证过的解析版本；`pyproject.toml` 保留包元数据与测试、Lint 配置。旧 `poetry.lock` 未包含 TaskIQ 等当前依赖，已移除，避免把过期解析结果误用于复现。

统一部署入口为 [code/docker-compose.yaml](../docker-compose.yaml)，后端目录不单独维护重复的 Compose 配置。

## 本地开发

初次体验建议使用 [完整平台部署](../DOCKER.md)。以下命令仅启动后端进程，需先准备 PostgreSQL、Redis 和 Agent 服务。

在 `code/sentinel_backend/` 目录使用独立 Python 环境，并配置 `DATABASE_URL`、`REDIS_URL`、`ML_AGENT_A_URL` 与 `ML_AGENT_B_URL`。本地开发配置由该目录的 `.env` 或进程环境变量提供；Compose 使用的 `code/.env` 不会自动成为该目录的配置文件。数据库 URL 中的用户名、密码、端口和数据库名应与实际服务一致。

安装依赖、执行数据库迁移后启动 API：

```powershell
python -m pip install -r requirements.txt
python -m alembic upgrade head
python -m uvicorn app.main:app --host 127.0.0.1 --port 18000 --reload
```

在另一个终端切换到相同目录和 Python 环境，加载相同配置后启动任务执行器：

```powershell
python -m taskiq worker app.main:broker --workers 1
```

运行测试：

```powershell
python -m pip install pytest pytest-asyncio
python -m pytest
```

API 启动后可访问 `http://127.0.0.1:18000/docs` 查看接口。创建任务和启动审计是两个步骤，详见 [接口集成说明](../INTEGRATION_GUIDE.md)。本地手动运行动态验证还涉及 Docker Socket 和共享路径配置，优先使用 Compose 复现该流程。

长期部署需要设置 `AUTO_CREATE_TABLES=false`，在应用启动前执行 Alembic 迁移，限制 `CORS_ORIGINS`，并通过密钥管理服务注入数据库凭据。前端演示登录不提供后端身份认证，其他部署边界见 [安全模型](../docs/SECURITY.md)。

[返回代码导航](../README.md)
