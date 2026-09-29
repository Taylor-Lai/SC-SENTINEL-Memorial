# SC-SENTINEL Backend

后端以 FastAPI 提供任务与报告接口，使用 TaskIQ Worker 和 Redis 调度审计流程，PostgreSQL 保存业务结果。Worker 连接多智能体服务与动态沙箱，通过 WebSocket 推送任务日志和进度。

## 目录

```text
app/api/       HTTP 与 WebSocket 接口
app/core/      配置、数据库、队列与报告基础设施
app/models/    持久化业务模型
app/schemas/   接口数据结构
app/services/  源码摄取与沙箱适配
app/worker/    流水线与生命周期管理
alembic/       数据库迁移
tests/         单元与接口测试
```

## 部署

统一部署入口为上一级 `code/docker-compose.yaml`，环境配置见[Docker 指南](../DOCKER.md)。后端依赖以 `requirements.txt` 为部署安装入口，`pyproject.toml` 保持相同运行依赖约束。

## 本地开发

在本目录使用独立虚拟环境安装依赖，并配置 `DATABASE_URL`、`REDIS_URL` 和两个 Agent 接口地址。使用 Compose 的宿主机映射时，数据库端口为 5433、Redis 端口为 6380；Agent 的本地服务端口为 18001。

```powershell
python -m pip install -r requirements.txt
python -m alembic upgrade head
python -m uvicorn app.main:app --host 127.0.0.1 --port 18000 --reload
```

另开终端并使用相同环境配置启动 Worker：

```powershell
python -m taskiq worker app.main:broker --workers 1
```

测试：

```powershell
python -m pip install pytest pytest-asyncio
python -m pytest
```

部署时设置 `AUTO_CREATE_TABLES=false`，启动前执行 Alembic 迁移，配置准确的 `CORS_ORIGINS` 并保护数据库凭据。接口与共享卷约定见[集成说明](../INTEGRATION_GUIDE.md)。
