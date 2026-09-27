# SENTINEL 分析引擎

分析引擎面向 C/C++ 源码，提供命令行和内部 HTTP 两种入口。七个分析阶段运行在同一服务中，处理依赖、源码、漏洞假设、Harness 与证据报告；生成产物保存在本地目录，不纳入版本控制。

## 目录结构

```text
agents/       各分析阶段
core/         扫描、LLM、数据结构与公共工具
cve/          依赖解析与漏洞数据查询客户端
prompts/      LLM 提示词
samples/      固定测试样本与评测基准
tools/        日志解析与连接检查工具
scripts/      可复现的流水线辅助脚本
main.py       命令行入口
service.py    内部 FastAPI 服务
```

## 命令行运行

以下命令在 `code/sentinel_agent/` 目录执行，建议使用独立的 Python 虚拟环境。先安装依赖：

```powershell
python -m pip install -r requirements.txt
```

使用自带小样本运行：

```powershell
python main.py --project samples/vulnerable_project
```

默认在 `outputs/` 保存阶段 JSON 和最终 JSON/Markdown 报告，在 `harness_packages/` 保存测试包。可通过 `--output` 和 `--harness` 自定义目录。

命令行不自动运行动态沙箱，已有的真实动态证据需要显式提供：

```powershell
python main.py `
  --project samples/vulnerable_project `
  --validation path/to/runtime-evidence
```

验证目录可以包含 `asan_validation_results.json`、`afl_result.json` 和 `ebpf_log.json`。流程不会自动加载仓库中附带的模拟动态证据。

## 服务运行

```powershell
python -m uvicorn service:app --host 127.0.0.1 --port 18001
```

通过 `AGENT_ALLOWED_SOURCE_ROOTS` 配置允许访问的源码路径，多个路径用逗号分隔。配置后，访问范围外路径的请求会收到 HTTP 403。默认 Docker Compose 将其设置为 `/app/uploads`，且不向宿主机映射 Agent 端口。

接口：

- `GET /health`：健康检查；
- `POST /api/agent-a/analyze`：依赖分析；
- `POST /api/agent-b/audit`：执行后续分析阶段、生成 Harness 与初步报告；接口名称保留历史命名，并非只运行 Agent B。

LLM 配置从 `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL`、`LLM_TIMEOUT` 等环境变量读取，客户端也会尝试加载当前工作目录的 `.env`。单独运行 Agent 时，应在 Agent 目录准备配置或设置进程环境变量；Compose 则从 `code/.env` 注入配置。未配置服务提供方时，分析层可使用确定性规则回退。CVE 查询仍可能需要网络，规则回退不等同于完整的离线模式。

## 阅读与评测

各阶段职责与对应文件见 [系统架构](../docs/ARCHITECTURE.md#七阶段分析流程)。阶段 E 对应历史文件名 `agent_d_harness.py`，以入口中的调用别名为准。

[二级可见样本](samples/level2_testset/) 用于提交分析；[评测基准](samples/level2_oracle/README.md) 包含答案和验证资料，仅用于运行后的对照。自动生成的 Harness 可能仍需适配，构建就绪标记也不等于已复现漏洞。

运行单元测试：

```powershell
python -m pip install pytest
python -m pytest
```

[返回代码导航](../README.md)
