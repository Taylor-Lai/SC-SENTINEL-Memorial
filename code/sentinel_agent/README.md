# SC-SENTINEL Agent

Agent 提供依赖识别、漏洞假设、静态复核、验证工件和报告生成五类智能体协作能力。通过函数切片与数据流线索生成假设，使用规则与受约束 LLM 复核，并生成 CWE 感知的 Harness 包，关联动态证据形成报告。

## 目录

```text
agents/       智能体分析步骤
core/         扫描、LLM、数据模型与工具
cve/          依赖解析与漏洞数据查询
prompts/      分析提示词
samples/      漏洞样本与评测基准
tools/        解析与连接检查工具
scripts/      流水线辅助脚本
main.py       命令行入口
service.py    内部服务入口
```

## 命令行

在本目录安装 `requirements.txt` 中的依赖后执行：

```powershell
python main.py --project samples/vulnerable_project
```

通过 `--validation` 指定动态验证证据目录：

```powershell
python main.py --project samples/vulnerable_project --validation path/to/runtime-evidence
```

证据文件包括 `asan_validation_results.json`、`afl_result.json` 与 `ebpf_log.json`，用于关联错误定位、触发样例和运行事件。

## 内部服务

```powershell
python -m uvicorn service:app --host 127.0.0.1 --port 18001
```

| 接口 | 用途 |
| --- | --- |
| `GET /health` | 健康检查 |
| `POST /api/agent-a/analyze` | 依赖与 CVE 分析 |
| `POST /api/agent-b/audit` | 静态审计与 Harness 生成 |

`AGENT_ALLOWED_SOURCE_ROOTS` 使用逗号分隔允许读取的源码目录。默认 Compose 设置为 `/app/uploads`，通过共享卷读取任务源码，服务端口仅在内部网络开放。

LLM 通过 `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL` 配置；未配置时使用确定性规则回退。Harness 包包括测试入口、构建文件、配置、种子与 Findings，采用目标代码与 Harness 分离编译，并通过原型确认、构建就绪和适配需求等质量门控。
