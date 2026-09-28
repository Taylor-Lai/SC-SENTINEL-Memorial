# 最终归档检查记录

检查日期：2026-09-28。本文记录纪念仓库收尾时的检查范围与已知边界，不作为生产环境安全认证。

## 归档结构

根目录保存项目介绍、许可与参与说明；`code/` 保存实现和复现指南；`materials/` 保存比赛文档与 PPT；`assets/` 保存合影与证书。现有三模块划分清楚，无需为了归档迁移代码或重建目录。

比赛方案材料保留原稿，源码说明以当前实现为准。源码相对最初比赛提交的修正见根目录 [更新日志](../../CHANGELOG.md)。

## 本次收尾修正

- 补全异步数据库依赖，限制 TaskIQ 兼容版本，并记录已验证的 Python 依赖解析基线。
- 移除未覆盖当前依赖的旧 Poetry 锁文件，明确 pip 安装入口。
- 补齐 `.env.local`、Agent 报告及 Harness 目录的忽略与镜像排除规则。
- Agent 扫描跳过符号链接和解析后位于项目目录之外的路径。
- 由拥有 Docker 访问权限的 Worker 响应持久化取消状态，避免 API 依赖未挂载的 Docker Socket；取消、阶段更新和最终完成使用数据库行锁，保护终态及取消原因。
- 将动态验证定时日志改为中性状态提示，实际证据以沙箱产物为准。
- 保留 CI，固定其 Linux 基础环境，增加 API 导入、文档链接与依赖基线检查。

Dependabot 定期版本升级 PR 已停止；该配置不等同于关闭 GitHub 安全提醒或独立的安全更新设置，见 [GitHub 配置说明](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/configure-version-updates)。

## 验证范围

- 后端 20 项测试、Lint、依赖一致性检查与 API 模块导入。
- Agent 测试、依赖一致性检查与服务模块导入；真实符号链接测试在 Windows 上可能因创建权限被跳过，由 Linux CI 验证。
- 前端锁文件安装、TypeScript 检查与生产构建。
- Docker Engine 29.8.0：前端、后端、Agent 与沙箱镜像构建成功，PostgreSQL 新卷迁移成功，API、Agent、数据库、Redis、前端健康检查通过。
- 使用独立 Compose 项目、容器名称和数据卷完成端到端验证，原有比赛容器和数据未重置；LLM API Key 留空，验证规则回退路径。
- 单文件堆溢出样本：上传、后台调度、Harness 编译、非特权沙箱执行、ASan 复现、报告查询、PDF 导出与 WebSocket 回放通过；动态报告记录 1 项确认，保留真实 AddressSanitizer 输出。
- 关闭触发分支的对照样本：AFL++ 运行约 30 秒后结束，报告为 1 项 `not_reproduced`、0 项确认，未把有限预算内的未复现当作安全证明。
- 动态任务取消：状态保持 `failed`，没有晚到 `done` 事件，对应沙箱容器和临时工作卷均已清理。
- 静态任务：报告保持 1 项候选、0 项确认，PDF 导出与 WebSocket 回放通过。
- 已跟踪 Markdown 的本地链接、代码块，以及文档所引用的图片与资料路径。
- 配置文件与目录说明的一致性，以及已跟踪文件中的常见密钥格式检查。

具体提交的 CI 状态以 [GitHub Actions](https://github.com/Taylor-Lai/SC-SENTINEL-Memorial/actions/workflows/ci.yml) 为准。密钥格式检查只覆盖常见模式，不代表对整个 Git 历史完成了秘密信息审计。

## 仍需理解的边界

本次验证了默认非特权 Docker 路径，未启用特权 eBPF 探针，也未调用收费 LLM 服务。小样本通过不等于所有 C/C++ 项目都可编译或所有漏洞都能复现；实际复现请按 [部署指南](../DOCKER.md) 逐步验证。

前端账号用于演示，后端尚无完整的用户认证与授权体系。容器隔离、外部 CVE/LLM 服务、自动生成 Harness 和规则覆盖都有各自限制，详见 [系统架构](ARCHITECTURE.md) 与 [安全模型](SECURITY.md)。

部分测试样本缺少完整来源、署名或许可证材料。本次没有补写无法确认的版权信息，也没有擅自改动比赛资料的授权范围；已有记录见 [第三方声明](../../THIRD_PARTY_NOTICES.md)。若后续需要单独再分发或授权复用这些样本，仍需维护者核实来源。

以比赛纪念和学习参考为目标，完成这些收尾修正后，可以结束常规整理；若转为长期服务或生产部署，应另行开展完整验收。

[返回项目主页](../../README.md) · [返回代码导航](../README.md)
