# SC-SENTINEL

SC-SENTINEL 是面向 C/C++ 项目的供应链与内存安全审计平台。系统将依赖/CVE 识别、静态漏洞分析、Harness 生成、AFL++/ASan 动态验证和报告汇总组成可追踪的异步流水线。

## 代码结构

```text
sentinel_agent/       七阶段安全分析引擎、CVE 客户端和基准样本
sentinel_backend/     FastAPI、TaskIQ Worker、PostgreSQL、Redis、沙箱调度
sentinel_frontend/    Vue 3 管理界面
docs/                 架构、安全模型和运维说明
docker-compose.yaml   本地全栈编排的唯一入口
```

运行时生成的上传文件、Harness、报告和临时目录不纳入版本控制。漏洞测试样本保存在 `sentinel_agent/samples/`，其中 `level2_oracle/` 是结果评测基准。

## 审计流水线

```text
源码摄取
  → Agent A：依赖和 CVE 风险
  → Agent B：语义切片和数据流提示
  → Agent C：漏洞假设
  → Agent D：LLM/规则交叉审计
  → Agent E：Harness 生成与构建门控
  → Agent F：ASan/AFL++/eBPF 证据归因
  → Agent G：风险裁决和报告
```

后端通过 TaskIQ 和 Redis 调度阶段任务，使用 PostgreSQL 保存业务结果，通过 Redis Stream 向 WebSocket 客户端转发进度。

## 快速启动

### 1. 配置环境变量

```bash
# 复制配置模板
cp .env.example .env

# 编辑 .env 文件，填写必要的配置
# 必须设置：POSTGRES_PASSWORD（数据库密码）
# 可选配置：LLM_API_KEY, LLM_BASE_URL, LLM_MODEL（用于LLM增强分析）
```

### 2. 启动服务

```bash
# 首次启动（构建所有镜像）
docker compose up -d --build

# 日常启动（镜像已存在）
docker compose up -d

# 查看服务状态
docker compose ps

# 查看日志
docker compose logs -f
```

### 3. 停止服务

```bash
# 停止服务（保留数据）
docker compose down

# 停止服务并删除所有数据
docker compose down -v
```

启动后访问：

- 前端：http://localhost:8080
- 后端 OpenAPI：http://localhost:18000/docs
- 健康检查：http://localhost:18000/health/ready

**注意**：Agent 服务默认只在 Compose 内部网络暴露，不映射到宿主机。

LLM 配置是可选增强；未配置密钥时七阶段流水线自动使用确定性规则审计，不影响任务、报告和 PDF 功能。

更多Docker使用说明和故障排查，请参考 [DOCKER.md](./DOCKER.md)。

## 安全默认值

- 上传流最大 100MB；ZIP 同时限制文件数、单文件大小、解压总大小和压缩率。
- 远程源码只接受受信任代码托管域名。
- Fuzzing 沙箱默认无特权、无 capabilities、只读、断网并限制 CPU、内存和 PID。
- `SANDBOX_ALLOW_PRIVILEGED=false` 是默认值。只有隔离的专用 Linux eBPF 主机才应显式开启特权兼容模式。
- Agent 仅允许读取 `AGENT_ALLOWED_SOURCE_ROOTS` 下的源码。
- 后端不包含生产 Mock 数据；测试替身只能存在于测试层。

完整威胁模型见 [docs/SECURITY.md](docs/SECURITY.md)，组件关系见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
比赛现场的环境预检、演示路径、证据口径与验收清单见 [docs/COMPETITION_RUNBOOK.md](docs/COMPETITION_RUNBOOK.md)。

## 开发验证

后端：

```powershell
cd sentinel_backend
python -m pip install -r requirements.txt
python -m pip install pytest pytest-asyncio
python -m pytest
```

Agent 快速运行：

```powershell
cd sentinel_agent
python -m pip install -r requirements.txt
python main.py --project samples/vulnerable_project
```

前端：

```powershell
cd sentinel_frontend
npm ci
npm run build
```

## 部署说明

- Compose 启动时会先幂等执行 Alembic 完整迁移；API 和 Worker 仅在迁移成功后启动。
- Docker Compose 会从根目录 `.env` 读取本地数据库密码；请保留该文件，避免持久化数据库与连接配置不一致。
- 将 API 放在认证网关之后，并配置准确的 `CORS_ORIGINS`。
- 特权 eBPF Runner 应与 API/Worker 主机物理或虚拟隔离。
- 上线前必须跑 oracle 基准、后端测试和前端类型检查。
