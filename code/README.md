# 代码与阅读导航

这里保存 SC-SENTINEL 比赛版本的源码与技术文档。系统面向 C/C++ 项目，将依赖风险识别、静态漏洞分析、Harness 生成和可选动态验证组成异步审计流程。

## 从哪里开始

| 目的 | 入口 |
| --- | --- |
| 运行完整平台 | [Docker 部署指南](DOCKER.md) |
| 理解组件关系、阶段输入输出和证据判定 | [系统架构](docs/ARCHITECTURE.md) |
| 学习分析算法与命令行运行方式 | [分析引擎](sentinel_agent/README.md) |
| 查看任务调度、API 与存储实现 | [后端说明](sentinel_backend/README.md) · [接口集成](INTEGRATION_GUIDE.md) |
| 阅读页面和交互实现 | [前端说明](sentinel_frontend/README.md) |
| 了解运行隔离与部署限制 | [安全模型](docs/SECURITY.md) |
| 参考比赛演示准备 | [比赛运行手册](docs/COMPETITION_RUNBOOK.md) |

## 目录结构

```text
code/
├── sentinel_agent/       七阶段分析引擎、CVE 客户端与测试样本
├── sentinel_backend/     API、任务执行器、数据库模型与动态沙箱
├── sentinel_frontend/    Vue 页面、状态管理与报告展示
├── docs/                 架构、安全模型与比赛运行手册
├── scripts/              环境预检与演示包生成脚本
├── .env.example          本地部署配置模板
└── docker-compose.yaml   完整平台的统一部署入口
```

七个分析阶段由一个 Agent 服务承载，后端通过 TaskIQ 和 Redis 调度依赖分析、静态审计和动态验证任务。PostgreSQL 保存结果，Redis Stream 与 WebSocket 传递进度。

## 两种学习方式

**运行 Web 平台**：按部署指南准备数据库密码并启动 Compose，在浏览器中提交小型源码项目，观察从上传、分析到报告的完整过程。动态验证需要额外构建沙箱镜像。

**单独研究分析引擎**：按 Agent 说明运行命令行入口，查看各阶段的 JSON 输出与最终报告。命令行通过参数读取已有动态证据，不自动调用后端沙箱。

LLM 是可选增强，未配置时分析层使用规则回退。依赖查询仍可能访问外部 CVE 数据源；动态分析的构建和运行还取决于样本、工具链与系统环境。

## 样本与运行产物

测试样本位于 [sentinel_agent/samples/](sentinel_agent/samples/)。其中 `level2_testset/` 是待分析的可见项目，`level2_oracle/` 保存对应评测材料。先运行分析，再对照评测材料，避免把答案作为输入提供给分析引擎。

上传源码、生成的 Harness、运行日志和报告属于本地运行数据，不纳入版本控制。样本复用前请阅读 [第三方声明](../THIRD_PARTY_NOTICES.md)。

## 开发验证

以下每组命令都从 `code/` 目录开始，使用各自的 Python 或 Node.js 环境。后端与 Agent 建议分别创建虚拟环境，以免依赖版本相互影响。

后端测试：

```powershell
cd sentinel_backend
python -m pip install -r requirements.txt
python -m pip install pytest pytest-asyncio
python -m pytest
```

Agent 测试：

```powershell
cd sentinel_agent
python -m pip install -r requirements.txt
python -m pip install pytest
python -m pytest
```

前端类型检查与构建：

```powershell
cd sentinel_frontend
npm ci
npm run build
```

CI 还会检查后端代码风格，完整步骤见 [工作流配置](../.github/workflows/ci.yml)。测试和构建通过不等于完成了动态验证环境的端到端验收，复现时仍应运行一个样本并检查报告中的实际证据。

[返回项目主页](../README.md)
