<h1 align="center">SC-SENTINEL</h1>

<p align="center">
  <strong>基于多智能体的开源软件供应链二进制漏洞审计与验证系统</strong>
</p>
<p align="center">
  全国大学生信息安全竞赛（作品赛）参赛项目<br>
  电子科技大学 · 2026 · 项目纪念与学习参考
</p>

<p align="center">
  <a href="https://github.com/Taylor-Lai/SC-SENTINEL-Memorial/actions/workflows/ci.yml"><img src="https://github.com/Taylor-Lai/SC-SENTINEL-Memorial/actions/workflows/ci.yml/badge.svg" alt="归档完整性检查状态"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/代码许可-Apache--2.0-blue" alt="代码许可：Apache-2.0"></a>
</p>

---

## 写在比赛之后

SC-SENTINEL 是我们在 2026 年全国大学生信息安全竞赛（作品赛）中完成的项目，尝试将多智能体分析与动态验证结合，用于开源软件供应链安全审计。

比赛结束后，我们把当时的源码、项目文档、答辩材料和现场照片整理在这里，留作纪念，也方便后来做类似项目的学弟学妹查阅和参考。

`code/` 完整保留本仓库首次上传时的内容。目录内的文档也是当时的原稿，其中的部署地址、开发备注和运行说明可能已过时；当前归档状态以本页和[归档检查记录](ARCHIVE_STATUS.md)为准。

这份记录里有我们做过的尝试，也有考虑不够周全的地方。如果其中的思路或实现能给你一些帮助，就很有意义了。

## 项目介绍

SC-SENTINEL 面向 C/C++ 开源项目，把供应链依赖分析、源码审计与动态验证串成一条流程。用户可以上传源码 ZIP 或提交受支持的仓库地址。系统识别依赖与相关 CVE，分析可疑代码，并为候选问题生成测试程序（Harness）。启用动态验证后，系统进一步尝试触发问题、收集运行时证据，最后汇总为可查看和导出的审计报告。

| 环节 | 做什么 |
| --- | --- |
| 依赖与风险识别 | 解析项目依赖，结合 OSV / NVD 查询组件及 CVE 风险 |
| 多阶段源码审计 | 提取代码上下文，生成漏洞假设，结合规则与 LLM 交叉审计 |
| 动态验证 | 生成 Harness，结合 ASan、AFL++ 与 eBPF 收集运行时证据 |
| 结果呈现 | 在 Web 界面查看任务进度、代码定位、验证结果，并导出报告 |

报告汇总静态发现、动态证据和验证状态，保留从候选问题到运行结果的追踪关系。组件关联了 CVE，并不代表当前项目已触发该漏洞；动态验证未触发问题，也不等于已经证明安全。

## 系统架构

按照比赛资料，系统采用前端展示、后端服务、多智能体审计和动态沙箱验证四层架构。后端服务包括 API 与任务执行器；PostgreSQL 保存任务与审计结果，Redis 承担异步任务队列和进度传递。

```mermaid
flowchart LR
    UI[Web 前端] --> API[后端 API]
    API --> Queue[Redis 任务队列]
    Queue --> Worker[任务执行器]
    Worker --> Agent[五智能体审计服务]
    Worker --> Sandbox[动态验证沙箱]
    API <--> DB[(PostgreSQL)]
    Worker --> DB
    Worker --> Progress[Redis 进度流]
    Progress --> API
    API -->|WebSocket 进度与日志| UI
```

比赛方案采用五类智能体协作模型：

| 智能体 | 主要职责 |
| --- | --- |
| 依赖识别 | 识别组件与版本，关联 CVE 风险 |
| 漏洞假设 | 利用函数切片、调用关系和数据流线索，生成候选 CWE 与触发条件 |
| 静态复核 | 结合规则与 LLM 复核漏洞假设，输出结构化发现 |
| 验证工件 | 生成 Harness、种子和构建文件，组织动态验证与证据归因 |
| 报告生成 | 汇总风险与证据，形成可追踪的审计报告 |

上述划分依据[答辩 PPT](materials/SC-SENTINEL-答辩PPT.pptx)第 7、10 页及[项目文档](materials/SC-SENTINEL-项目文档.pdf)第 2.2.1 节。PPT 中的“假设生成”对应文档中的“漏洞假设”；源码扫描、函数切片、种子生成、质量门控和日志解析属于内部工具，不单独计算为 Agent。原始代码文档保留了内部七阶段的旧命名，阅读时以比赛资料的五类职责划分理解整体方案。

静态审计可独立完成；动态验证由任务执行器调用沙箱，结合 ASan、AFL++ 和可用的 eBPF 事件补充证据。未配置 LLM 时可使用规则回退，eBPF 的可用性则取决于运行环境和权限。实现与运行路径可参考原始[架构说明](code/docs/ARCHITECTURE.md)。

## 从这里开始

可以按自己的目的选择入口，无需一次读完整个仓库。

| 你想了解什么 | 推荐入口 |
| --- | --- |
| 快速了解选题、方案和成果 | [答辩 PPT](materials/SC-SENTINEL-答辩PPT.pptx) |
| 系统阅读比赛方案与设计 | [项目文档 PDF](materials/SC-SENTINEL-项目文档.pdf) |
| 在自己的环境中运行项目 | [快速启动](#快速启动) → [部署指南](code/DOCKER.md) |
| 学习模块划分与系统协作 | [代码导航](code/README.md) · [架构说明](code/docs/ARCHITECTURE.md) |
| 研究分析流程与漏洞样本 | [Agent 说明](code/sentinel_agent/README.md) · [测试样本](code/sentinel_agent/samples/) |
| 参考现场演示与答辩准备 | [比赛演示手册](code/docs/COMPETITION_RUNBOOK.md) |

### 仓库结构

主要目录与入口如下：

```text
SC-SENTINEL-Memorial/
├── README.md                     项目介绍与阅读导航
├── ARCHIVE_STATUS.md             最终检查范围与原始版本的已知限制
├── .github/                      归档检查、Issue 与 PR 模板
├── scripts/                      归档完整性检查脚本
├── code/                         首次上传的原始源码与技术文档
│   ├── sentinel_agent/           多智能体审计引擎与漏洞测试样本
│   ├── sentinel_backend/         API、任务调度、存储与沙箱管理
│   ├── sentinel_frontend/        任务提交、实时进度与审计报告界面
│   ├── docs/                     架构说明、安全模型与演示手册
│   ├── scripts/                  环境预检与演示包准备脚本
│   └── docker-compose.yaml       本地部署入口
├── materials/                    项目文档 PDF 与答辩 PPT
└── assets/                       团队合影与获奖证书
```

## 比赛留念

项目参加了第十九届全国大学生信息安全竞赛（作品赛）暨第三届“长城杯”网数智安全大赛（作品赛），获得全国一等奖。这里保留了当时的合影与证书。

参赛作品：SC-Sentinel——基于多智能体的开源软件供应链二进制漏洞审计与验证系统。参赛高校：电子科技大学。

<p align="center">
  <a href="assets/team-at-award-ceremony.png">
    <img src="assets/team-at-award-ceremony.png" width="720" alt="SC-SENTINEL 团队在 2026 年全国大学生信息安全竞赛颁奖现场的合影">
  </a>
  <br>
  <sub>颁奖现场合影 · 2026 年 · 点击图片查看原图</sub>
</p>

<p align="center">
  <a href="assets/first-prize-certificate.png">
    <img src="assets/first-prize-certificate.png" width="600" alt="SC-SENTINEL 全国一等奖获奖证书，参赛高校为电子科技大学">
  </a>
  <br>
  <sub>获奖证书 · 点击图片查看原图</sub>
</p>

## 快速启动

下面保留原始版本的本地启动入口。请先阅读[已知运行限制](ARCHIVE_STATUS.md#已知运行限制)；当前版本未重新完成全链路运行验证，可能需要自行调整依赖或环境。准备好支持 Linux 容器的 Docker 与 Docker Compose 后执行：

```bash
git clone https://github.com/Taylor-Lai/SC-SENTINEL-Memorial.git
cd SC-SENTINEL-Memorial/code
cp .env.example .env
# 编辑 .env，至少设置 POSTGRES_PASSWORD
docker compose up -d --build
```

Windows PowerShell 可用 `Copy-Item .env.example .env` 复制配置文件。

如需运行动态验证，还需在 `code/` 目录执行 `docker compose --profile sandbox build sandbox` 构建沙箱镜像。默认启动命令不会构建该镜像，具体环境要求见 [部署指南](code/DOCKER.md)。

| 入口 | 地址 |
| --- | --- |
| Web 界面 | <http://localhost:8080> |
| 后端 API 文档 | <http://localhost:18000/docs> |
| 就绪检查 | <http://localhost:18000/health/ready> |

前端使用演示账号 `sentinel-demo` / `sentinel2026` 登录，具体说明见 [前端文档](code/sentinel_frontend/README.md#演示登录)。这是演示用页面访问控制，后端没有完整的用户认证与授权体系。

LLM 配置、动态验证环境及故障排查见 [运行说明](code/README.md) 和 [Docker 部署指南](code/DOCKER.md)。首次体验可以结合 [演示手册](code/docs/COMPETITION_RUNBOOK.md) 使用仓库自带的演示样本。

## 关于学习与复用

如果你准备尝试复现，可以先浏览答辩材料，再用一个小样本熟悉流程，对照报告查看各阶段的输入和输出。也可以只选取感兴趣的模块，结合自己的项目需要作调整。

仓库保留首次上传的源码，后续整理集中在仓库主页、资料导航与归档说明；整理期间尝试过的代码修正已撤回。扫描效率、动态验证的环境适配、规则覆盖和部署体验，都是可以继续探索的方向。项目文档与源码可以对照阅读：前者呈现比赛方案，后者记录当时的实现。

欢迎通过 [Issue](https://github.com/Taylor-Lai/SC-SENTINEL-Memorial/issues/new/choose) 反馈文档问题、复现经验或改进建议，也欢迎提交补充说明和教学示例。参与方式见 [贡献指南](CONTRIBUTING.md)。

## 维护状态

本仓库以纪念、教学和学习参考为主要用途，后续不安排常规功能开发，也不承诺持续适配新的依赖和运行环境。CI 仅检查原始代码完整性与仓库导航链接，不代表平台运行验证通过。Dependabot 定期版本升级 PR 已停止；安全提醒与私密报告的处理仍取决于维护者可投入的时间。

最终检查的范围、结果和未验证事项见 [归档检查记录](ARCHIVE_STATUS.md)。

## 归档与使用说明

- **版本来源**：`code/` 与本仓库首次上传提交 `ce5a1308b7daceb2de8f3b537fddbd325b31c7a0` 中的内容一致；原项目来源记录为 `main` 分支提交 `26bc50bbd9bb934a6822eafdb73b87dc08e632c9`。仓库整理记录见 [更新日志](CHANGELOG.md)。
- **代码许可**：原创代码采用 [Apache License 2.0](LICENSE)。
- **比赛资料**：照片、证书、项目文档与答辩 PPT 供项目记录和学习参考，不属于上述开源许可范围，详见 [NOTICE](NOTICE)。
- **第三方样本**：部分样本适用独立许可证或仍需核验来源，复用前请查看 [第三方声明](THIRD_PARTY_NOTICES.md)。
- **使用范围**：漏洞样本用于安全研究、教学和授权测试。此仓库为比赛版本归档，未按生产环境标准持续维护；安全问题请按 [安全报告说明](SECURITY.md) 私下反馈。
