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

统一部署入口为 [code/docker-compose.yaml](../docker-compose.yaml)，后端目录不单独维护重复的 Compose 配置。

## 本地开发

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 18000 --reload
```

在另一个终端启动任务执行器：

```powershell
python -m taskiq worker app.main:broker --workers 1
```

运行测试：

```powershell
python -m pytest
```

生产部署需要设置 `AUTO_CREATE_TABLES=false`，在应用启动前执行 Alembic 迁移，限制 `CORS_ORIGINS`，并通过密钥管理服务注入数据库凭据。
