# SENTINEL Docker 部署指南

## 快速启动

### 1. 首次启动（需要构建镜像）

```bash
# 创建 .env 配置文件（如果不存在）
cp .env.example .env

# 编辑 .env 填写必要的配置
# 必须配置：POSTGRES_PASSWORD
# 可选的 LLM 增强分析配置：LLM_API_KEY、LLM_BASE_URL、LLM_MODEL

# 构建并启动所有服务
docker compose up -d --build

# 等待所有服务就绪（大约30-60秒）
docker compose ps

# 查看日志
docker compose logs -f
```

### 2. 日常启动（镜像已存在）

```bash
docker compose up -d
```

### 3. 停止服务

```bash
# 停止服务但保留数据
docker compose down

# 停止服务并删除所有数据（包括数据库）
docker compose down -v
```

## 访问地址

- **前端界面**: http://localhost:8080
- **后端API文档**: http://localhost:18000/docs
- **健康检查**: http://localhost:18000/health/ready

## 常用命令

### 查看服务状态
```bash
docker compose ps
```

### 查看日志
```bash
# 所有服务日志
docker compose logs -f

# 特定服务日志
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f agent
docker compose logs -f migrate
```

### 重启特定服务
```bash
docker compose restart api
docker compose restart worker
```

### 重新构建镜像
```bash
# 重建所有服务
docker compose build

# 重建特定服务
docker compose build api
docker compose build agent

# 重建并重启
docker compose up -d --build
```

### 构建沙箱镜像（用于动态验证）
```bash
docker compose --profile sandbox build sandbox
```

## 故障排查

### 服务启动失败

1. **检查 Docker 是否运行**
   ```bash
   docker info
   ```

2. **查看失败服务的日志**
   ```bash
   docker compose logs migrate
   docker compose logs api
   ```

3. **检查容器状态**
   ```bash
   docker compose ps -a
   ```

### 数据库密码问题

如果遇到数据库密码认证失败，执行以下命令重置：

```bash
# 停止并删除所有数据（包括数据库）
docker compose down -v

# 重新启动
docker compose up -d
```

### 端口冲突

如果端口被占用，可以修改 `docker-compose.yaml` 中的端口映射：
- 前端: `8080:80`
- 后端API: `18000:18000`
- PostgreSQL: `5433:5432`
- Redis: `6380:6379`

### 清理所有资源

```bash
# 停止并删除容器、网络、卷
docker compose down -v

# 删除构建的镜像
docker rmi sentinel-agent:latest sentinel-backend:latest sentinel-frontend:latest sentinel-sandbox:latest

# 清理未使用的Docker资源
docker system prune -a
```

## 环境变量配置

在 `code/` 目录创建 `.env` 文件：

```env
# LLM 配置（可选，启用语义审计时填写）
LLM_API_KEY=your_api_key_here
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4

# 数据库密码（必须手动设置）
POSTGRES_PASSWORD=Sentinel_随机字符串

# CORS配置
CORS_ORIGINS=http://localhost:8080

# 沙箱配置
SANDBOX_ALLOW_PRIVILEGED=false
SANDBOX_TIMEOUT_SECONDS=180
SANDBOX_PACKAGE_TIMEOUT_SECONDS=30
```

## 开发模式

### 监听代码变化（热重载）

对于 Python 后端开发，可以挂载本地代码：

```yaml
# 在 docker-compose.yaml 中添加 volumes
services:
  api:
    volumes:
      - ./sentinel_backend:/app
```

然后重启服务：
```bash
docker compose up -d api
```

### 进入容器调试

```bash
# 进入API容器
docker compose exec api bash

# 进入数据库容器
docker compose exec db psql -U sentinel_admin -d sentinel_db

# 进入Redis
docker compose exec redis redis-cli
```

## 生产部署建议

1. **使用固定的POSTGRES_PASSWORD**，不要依赖自动生成
2. **配置防火墙**，只暴露必要的端口
3. **定期备份数据库**
   ```bash
   docker compose exec -T db pg_dump -U sentinel_admin sentinel_db > backup.sql
   ```
4. **监控容器健康状态**
   ```bash
   docker compose ps
   ```
5. **配置日志轮转**，避免日志文件过大
