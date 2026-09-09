# SENTINEL 分析引擎

Agent 是面向 C/C++ 源码的无状态分析服务，提供依赖分析与七阶段审计流程。生成的 Harness 和报告数据不纳入版本控制。

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

```powershell
python main.py --project samples/vulnerable_project
```

真实动态证据需要显式提供：

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
- `POST /api/agent-b/audit`：静态审计。

LLM 配置从 `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL`、`LLM_TIMEOUT` 等环境变量读取。未配置服务提供方时，分析层可使用确定性规则回退，不会伪造后端任务结果。
