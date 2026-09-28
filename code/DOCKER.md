# Docker 部署与复现指南

本文用于在本地复现比赛归档版本。以下命令均在仓库的 `code/` 目录执行，默认部署入口为 [docker-compose.yaml](docker-compose.yaml)。

## 运行前准备

- 安装并启动支持 Linux 容器的 Docker Engine 或 Docker Desktop，以及 Docker Compose。
- 首次构建需要下载基础镜像与依赖；CVE 查询、远程仓库克隆和 LLM 调用也可能需要网络。
- 演示环境可从 2 CPU / 4 GB 内存起步，根据源码规模和动态验证负载增加资源。
- 完整平台由 Compose 管理，无需先在宿主机安装 Python 和 Node.js。

## 首次启动

### 1. 创建配置

仅在没有 `.env` 时复制模板，已有配置请保留：

```bash
cp .env.example .env
```

Windows PowerShell 对应命令为 `Copy-Item .env.example .env`。编辑 `.env`，至少设置 `POSTGRES_PASSWORD`，再按需要填写其他项：

| 配置 | 用途与要求 |
| --- | --- |
| `POSTGRES_PASSWORD` | 必填，用于首次数据库初始化及 API/Worker 连接；请自行设置并保留 |
| `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL` | 可选，启用 LLM 增强时三项均需填写，使用实际服务提供方的地址和模型标识 |
| `CORS_ORIGINS` | 允许的浏览器来源，默认 `http://localhost:8080`；多个来源以逗号分隔 |
| `SANDBOX_TIMEOUT_SECONDS` | 动态验证任务时间预算，Compose 默认 180 秒 |
| `SANDBOX_PACKAGE_TIMEOUT_SECONDS` | 单个 Harness 包的 AFL++ 运行预算，Compose 默认 30 秒 |
| `SANDBOX_ALLOW_PRIVILEGED` | 默认 `false`；仅在专用隔离 Linux 环境需要 eBPF 特权兼容路径时调整 |

LLM 三项可以留空，此时使用规则回退。后端直接运行时的默认超时与 Compose 不同，本表以 Compose 配置为准。数据库密码会被拼接进连接 URL，建议使用足够长的随机字母数字串，避免 URL 分隔符导致连接解析问题。

### 2. 构建并启动平台

```bash
docker compose up -d --build
docker compose ps -a
```

首次启动会构建镜像，并通过 `migrate` 服务执行 Alembic 数据库迁移。迁移成功退出后，API 和 Worker 才启动。`migrate` 显示成功退出是正常现象，其余常驻服务应运行，带健康检查的服务应达到 `healthy`。

构建与启动耗时取决于网络和机器配置。排查启动进度可运行：

```bash
docker compose logs -f
```

### 3. 按需准备动态验证

默认启动不会构建沙箱镜像。需要动态验证时，先执行：

```bash
docker compose --profile sandbox build sandbox
```

沙箱由 Worker 按任务创建，无需常驻。默认模式用于 ASan/AFL++ 验证；eBPF 是否可用取决于内核、工具链与权限，详见 [安全模型](docs/SECURITY.md)。

## 访问与首次体验

| 入口 | 地址 |
| --- | --- |
| Web 界面 | <http://localhost:8080> |
| 后端 API 文档 | <http://localhost:18000/docs> |
| 就绪检查 | <http://localhost:18000/health/ready> |

演示账号为 `sentinel-demo`，密码为 `sentinel2026`。这是前端演示访问控制，配置方式见 [前端说明](sentinel_frontend/README.md#演示登录)。Agent 不向宿主机映射端口，API 和 Worker 通过内部网络调用它。

第一次运行建议先使用小样本做静态审计，确认提交、进度与报告流程正常，再构建沙箱并新建动态任务。Windows 下可以生成仓库自带的演示包：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build_demo_bundle.ps1
```

在新建审计页面上传生成的 `tmp/SC-SENTINEL-demo.zip`。报告应按每条发现的实际状态阅读；生成 Harness 或完成任务不等于每条漏洞都已确认。演示步骤见 [比赛运行手册](docs/COMPETITION_RUNBOOK.md)。

## 日常使用与数据保留

```bash
# 启动已有服务
docker compose up -d

# 查看某个服务的日志
docker compose logs -f worker

# 重启 API
docker compose restart api

# 修改代码或构建配置后重新构建并启动
docker compose up -d --build

# 停止服务，保留命名数据卷
docker compose down
```

`postgres_data` 保存任务与报告记录，`uploads_data` 保存上传内容和后端管理的任务文件，`redis_data` 保存 Redis 数据。Agent 容器内生成的中间报告与 Harness 目录没有单独的数据卷；需要留存时应在重建容器前导出。

## 故障排查

| 现象 | 优先检查 |
| --- | --- |
| 无法连接 Docker | 运行 `docker info`，确认引擎已启动且使用 Linux 容器 |
| API 或 Worker 未启动 | 运行 `docker compose ps -a`，检查依赖服务健康状态和 `docker compose logs migrate` |
| 页面能打开但任务不推进 | 查看 `docker compose logs worker`、`docker compose logs agent`，确认队列与分析服务可用 |
| 只有规则结果或 LLM 调用失败 | 检查三项 LLM 配置、服务地址、模型标识与 Agent 日志 |
| 动态验证失败 | 确认沙箱镜像已构建，查看 Worker 日志和报告中的编译/执行错误 |
| 没有 eBPF 事件 | 先确认运行模式、内核及权限；没有该类事件不代表 ASan/AFL++ 没有执行 |

### 数据库密码不一致

已有数据库卷不会因修改 `.env` 而自动更改数据库密码。若误改了 `POSTGRES_PASSWORD`，恢复首次初始化使用的密码后执行 `docker compose up -d`。

需要保留数据且无法恢复原密码时，应先备份，再单独处理数据库账号恢复。不要把删除数据卷作为常规密码排障步骤。

### 端口冲突

Compose 默认映射前端 `8080:80`、API `18000:18000`、PostgreSQL `5433:5432` 和 Redis `6380:6379`。可按需调整冒号左侧的宿主机端口；容器间仍使用内部服务地址。修改前端访问端口后，同步调整 `CORS_ORIGINS`。

### 重新初始化演示环境

只有确认本地任务、报告及上传文件均可丢弃时，才运行以下命令。`-v` 会删除本项目的数据库、Redis 和上传文件数据卷：

```bash
docker compose down -v
docker compose up -d
```

## 本地调试

API 默认未启用热重载。若要挂载本地后端源码，在 Compose 的 API 服务中保留上传卷并追加源码挂载：

```yaml
services:
  api:
    volumes:
      - ./sentinel_backend:/app
      - uploads_data:/app/uploads
```

运行 `docker compose up -d --force-recreate api` 应用挂载。之后修改 Python 代码需执行 `docker compose restart api`。该挂载只作用于 API；Worker 或 Agent 代码的修改仍需重新构建对应镜像，或单独配置开发挂载。

进入 API 容器或数据库进行调试：

```bash
docker compose exec api bash
docker compose exec db psql -U sentinel_admin -d sentinel_db
```

若要脱离 Compose 开发，请分别阅读 [后端](sentinel_backend/README.md)、[Agent](sentinel_agent/README.md) 与 [前端](sentinel_frontend/README.md) 说明。

## 长期部署参考

归档配置面向本地复现。长期部署前需补充后端认证、权限控制、入口 TLS、数据备份与执行环境隔离，具体要求见 [安全模型](docs/SECURITY.md)。默认 Compose 已配置日志轮转，但数据保留期限和备份仍需自行安排。

[返回代码导航](README.md) · [返回项目主页](../README.md)
