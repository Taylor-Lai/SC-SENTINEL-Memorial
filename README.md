# SC-SENTINEL Memorial

> 为一次并肩作战留下记录，也为后来者留下一条可以继续前行的路。

SC-SENTINEL 是一套面向 C/C++ 开源软件供应链的二进制漏洞审计与验证系统。项目以多智能体协作为核心，将依赖与 CVE 识别、静态漏洞分析、Harness 生成、AFL++ / ASan 动态验证、eBPF 证据归因和报告汇总组织成一条可追踪的自动化流水线。

本仓库既保存比赛版本的完整代码，也记录团队在第十九届全国大学生信息安全竞赛（作品赛）中的共同经历。我们希望它不仅是一份获奖项目归档，也能成为学弟学妹理解安全工程、继续改进系统和参加后续比赛的起点。

## 获奖记录

- 赛事：第十九届全国大学生信息安全竞赛（作品赛）暨第三届“长城杯”网数智安全大赛（作品赛）
- 作品：SC-Sentinel——基于多智能体的开源软件供应链二进制漏洞审计与验证系统
- 奖项：全国一等奖
- 学校：电子科技大学
- 时间：2026 年

![团队在颁奖现场的合影](assets/memories/team-at-award-ceremony.png)

![全国一等奖获奖证书](assets/memories/first-prize-certificate.png)

## 项目能做什么

SC-SENTINEL 面向待审计的 C/C++ 项目，依次完成：

1. 解析依赖并识别 CVE 风险；
2. 对源码进行语义切片和数据流分析；
3. 生成漏洞假设并进行规则与大模型交叉审计；
4. 自动生成 Harness，并通过构建门控检查；
5. 使用 ASan、AFL++ 与 eBPF 收集动态证据；
6. 综合静态与动态结果，给出风险裁决和审计报告。

## 系统组成

```text
code/
├── sentinel_agent/      七阶段安全分析引擎、CVE 客户端与测试样本
├── sentinel_backend/    FastAPI、TaskIQ、PostgreSQL、Redis 与沙箱调度
├── sentinel_frontend/   Vue 3 管理界面
├── docs/                架构、安全模型与比赛运行手册
└── docker-compose.yaml  本地全栈编排入口
```

整体审计链路：

```text
源码摄取
  → 依赖与 CVE 风险识别
  → 语义切片与漏洞假设
  → 静态交叉审计
  → Harness 生成与构建
  → ASan / AFL++ / eBPF 动态验证
  → 风险裁决与报告
```

## 快速开始

详细说明见 [`code/README.md`](code/README.md)。使用 Docker Compose 启动时：

```bash
cd code
cp .env.example .env
# 编辑 .env，至少设置 POSTGRES_PASSWORD
docker compose up -d --build
```

启动后可访问：

- 前端：<http://localhost:8080>
- 后端 OpenAPI：<http://localhost:18000/docs>
- 健康检查：<http://localhost:18000/health/ready>

## 给后来者

奖项是一个阶段的结果，真正值得留下的是把模糊想法做成完整系统的过程：拆分问题、验证假设、处理失败、反复联调，以及在截止日期前让每一个模块真正协同起来。

如果你正在阅读这个仓库，希望你不必照搬我们的答案。先理解系统为什么这样设计，再去质疑它、重构它、替换它，并让它在新的问题上走得更远。代码会过时，但认真做事、彼此信任和持续验证的习惯不会。

愿这份记录成为下一段旅程的起点。

## 说明

- 本仓库保存的是比赛结束时的纪念版本，实际部署前请重新审查依赖、密钥、网络边界和沙箱配置。
- 漏洞样本仅用于安全研究、教学和授权测试，请勿用于未获授权的目标。
- 项目原创代码采用 [Apache License 2.0](LICENSE)。测试样例区存在单独许可证与待核验来源，不受根许可证重新授权，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
- `assets/memories/` 中的照片、获奖证书以及 `code/SC-SENTINEL答辩ppt.pptx` 不属于 Apache-2.0 授权范围，未经权利人许可不得另行使用或传播。
- 贡献代码前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)；安全问题请按 [SECURITY.md](SECURITY.md) 中的方式私下报告。
