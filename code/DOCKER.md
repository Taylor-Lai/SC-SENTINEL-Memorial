# SC-SENTINEL Docker 部署指南

## 环境与配置

使用支持 Linux 容器的 Docker 和 Docker Compose，以下命令均在 `code/` 目录执行。首次配置时复制模板：

```bash
cp .env.example .env
```

PowerShell 对应命令为 `Copy-Item .env.example .env`。已有配置时直接编辑 `.env`。

| 变量 | 配置说明 |
| --- | --- |
| `POSTGRES_PASSWORD` | 必填，使用强密码；保留数据库卷时保持与首次初始化一致。密码应使用 URL 安全字符，便于构造数据库连接地址 |
| `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL` | 可选，三项配套配置；留空时使用规则回退 |
| `CORS_ORIGINS` | 浏览器来源列表，默认 `http://localhost:8080`，多个来源用逗号分隔 |
| `SANDBOX_ALLOW_PRIVILEGED` | 默认 `false`；专用隔离 Linux eBPF 主机可开启特权模式 |
| `SANDBOX_TIMEOUT_SECONDS` | 单次动态验证时间预算，默认 180 秒 |
| `SANDBOX_PACKAGE_TIMEOUT_SECONDS` | 工件执行时间预算，默认 30 秒 |

LLM 配置注入 Agent，数据库连接配置注入迁移、API 和 Worker。前端演示账号见[前端说明](sentinel_frontend/README.md#演示登录)。

## 启动与停止

```bash
# 构建动态验证沙箱镜像
docker compose --profile sandbox build sandbox
# 构建并启动平台
docker compose up -d --build
# 检查状态与启动日志
docker compose ps -a
docker compose logs migrate api worker agent
```

静态审计可跳过沙箱镜像构建。`sandbox` 是镜像构建入口，Worker 按任务启动短期沙箱容器。数据库与 Redis 健康检查通过后执行迁移，迁移成功后启动 API 和 Worker，API 就绪后启动前端。`migrate` 正常完成时显示退出码 0。

| 入口 | 地址 |
| --- | --- |
| Web 界面 | <http://localhost:8080> |
| API 文档 | <http://localhost:18000/docs> |
| 就绪检查 | <http://localhost:18000/health/ready> |

```bash
# 日常启动
docker compose up -d
# 停止并保留数据
docker compose down
# 查看实时日志
docker compose logs -f
# 配置或镜像更新后重新创建服务
docker compose up -d --build
```

数据库、Redis 和上传工件保存在命名卷中。仅在明确需要清空全部项目数据时使用 `docker compose down -v`，执行前备份数据库和需要保留的工件。

## 故障排查

启动失败时先执行 `docker info`、`docker compose config --quiet` 和 `docker compose ps -a`，再查看对应服务日志。迁移失败重点检查数据库连接和 `migrate` 日志；动态验证失败检查 `worker` 日志及 `sentinel-sandbox:latest` 镜像。

数据库认证失败时，先将 `.env` 中的密码恢复为当前数据库卷初始化时的密码，再执行 `docker compose up -d` 重新创建连接配置发生变化的服务。已有数据库卷的密码不会因修改环境变量自动更新；需要轮换密码时，在数据库内同步更新角色密码和连接配置。

默认宿主机端口为前端 8080、API 18000、PostgreSQL 5433、Redis 6380。发生端口冲突时修改 Compose 中相应映射；调整前端访问端口时同步更新 `CORS_ORIGINS`。

## 开发模式

将下面内容保存为 `code/compose.override.yaml`，再执行 `docker compose up -d --build api` 启用 API 热重载：

```yaml
services:
  api:
    volumes:
      - ./sentinel_backend:/app
      - uploads_data:/app/uploads
    command: ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "18000", "--reload"]
```

挂载源代码时保留共享上传卷。结束开发模式后移除本地覆盖文件，再重新创建 API 服务。

## 部署运维

```bash
# 数据库备份
docker compose exec -T db pg_dump -U sentinel_admin sentinel_db > backup.sql
# 容器内调试
docker compose exec api bash
docker compose exec db psql -U sentinel_admin -d sentinel_db
docker compose exec redis redis-cli
```

固定保存数据库凭据，限制宿主机暴露端口，为公开入口配置认证与 TLS，定期备份数据。Compose 已配置日志轮转。Worker 使用 Docker Socket 调度沙箱；eBPF 特权模式部署在专用隔离主机，具体策略见[安全说明](docs/SECURITY.md)。
