# SC-SENTINEL

SC-SENTINEL 是基于多智能体的开源软件供应链二进制漏洞审计与验证系统，面向 C/C++ 源码、ELF/PE 可执行文件及共享库，构建从风险发现到运行验证和报告交付的审计闭环。

## 代码结构

```text
sentinel_agent/       五智能体审计引擎、CVE 客户端和测试样本
sentinel_backend/     FastAPI、TaskIQ Worker、存储与沙箱调度
sentinel_frontend/    Vue 3 任务提交、监控与报告界面
docs/                架构、安全与演示说明
scripts/             环境预检与演示包准备
docker-compose.yaml  本地全栈部署入口
```

运行产物不纳入版本控制。漏洞样本位于 `sentinel_agent/samples/`，其中 `level2_oracle/` 提供结果评测基准。

## 审计流程

五类智能体分别承担依赖识别、漏洞假设、静态复核、验证工件和报告生成。函数切片与数据流线索支撑假设生成，规则与受约束 LLM 完成静态复核，CWE 感知的 Harness 与种子生成支撑动态验证，ASan、AFL++ 和 eBPF 三源证据形成最终风险裁决。

报告按已确认、需复核、未触发、未验证四类动态状态呈现结果。各阶段通过切片、假设、Finding、Harness 和证据标识保持可追踪关联。后端使用 TaskIQ 与 Redis 调度任务，PostgreSQL 保存业务结果，WebSocket 推送进度与日志。

## 快速启动

以下命令均在本仓库的 `code/` 目录执行：

```bash
cp .env.example .env
# 编辑 .env，设置 POSTGRES_PASSWORD
# 配置 LLM_API_KEY、LLM_BASE_URL、LLM_MODEL 可启用 LLM 增强
docker compose --profile sandbox build sandbox
docker compose up -d --build
docker compose ps
```

PowerShell 使用 `Copy-Item .env.example .env` 复制模板。未配置 LLM 时使用规则回退。沙箱镜像用于动态验证，静态审计可直接启动主服务。

| 入口 | 地址 |
| --- | --- |
| 前端 | <http://localhost:8080> |
| OpenAPI | <http://localhost:18000/docs> |
| 就绪检查 | <http://localhost:18000/health/ready> |

`docker compose down` 停止服务并保留数据；查看日志使用 `docker compose logs -f`。Agent 通过内部网络访问，共享上传卷用于传递源码与工件。Compose 先执行 Alembic 迁移，成功后启动 API 和 Worker。

## 阅读入口

- [Docker 部署指南](DOCKER.md)：环境变量、启动与排障。
- [系统架构](docs/ARCHITECTURE.md)：四层架构、五智能体与证据闭环。
- [集成接口](INTEGRATION_GUIDE.md)：任务、进度与报告接口。
- [演示手册](docs/COMPETITION_RUNBOOK.md)：环境预检、样本与答辩流程。
- [安全说明](docs/SECURITY.md)：上传校验、沙箱策略与部署配置。
- [Agent](sentinel_agent/README.md)、[后端](sentinel_backend/README.md)、[前端](sentinel_frontend/README.md)：模块使用说明。

## 开发验证

各模块独立安装依赖；下面每组命令均从 `code/` 开始。

```powershell
cd sentinel_backend
python -m pip install -r requirements.txt
python -m pip install pytest pytest-asyncio
python -m pytest
```

```powershell
cd sentinel_agent
python -m pip install -r requirements.txt
python main.py --project samples/vulnerable_project
```

```powershell
cd sentinel_frontend
npm ci
npm run build
```
