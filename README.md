# SC-SENTINEL

[![CI](https://github.com/Taylor-Lai/SC-SENTINEL-Memorial/actions/workflows/ci.yml/badge.svg)](https://github.com/Taylor-Lai/SC-SENTINEL-Memorial/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

> 第十九届全国大学生信息安全竞赛（作品赛）全国一等奖作品

SC-SENTINEL 是我们在 2026 年作品赛中完成的一套 C/C++ 开源软件供应链安全审计系统。系统把依赖识别、源码分析、漏洞假设、Harness 生成和动态验证串成一条流程，尽量让发现的风险能够落到可复现的验证结果上。

比赛结束后，我们把最终提交的代码、答辩材料和照片整理到了这个仓库，方便以后复盘，也给想做类似题目的同学作个参考。

![团队在颁奖现场的合影](assets/team-at-award-ceremony.png)

## 获奖情况

- 赛事：第十九届全国大学生信息安全竞赛（作品赛）暨第三届“长城杯”网数智安全大赛（作品赛）
- 作品：SC-Sentinel——基于多智能体的开源软件供应链二进制漏洞审计与验证系统
- 奖项：全国一等奖
- 学校：电子科技大学
- 时间：2026 年

![全国一等奖获奖证书](assets/first-prize-certificate.png)

## 这个项目做了什么

简单来说，用户提交一个 C/C++ 项目后，SC-SENTINEL 会先分析它的依赖和相关 CVE，再对可能存在问题的代码进行切片和静态审计。对值得进一步确认的风险，系统会尝试生成 Harness，并结合 ASan、AFL++ 和 eBPF 做动态验证，最后汇总成审计结果。

```text
项目源码
  → 依赖与 CVE 风险识别
  → 语义切片与漏洞假设
  → 静态交叉审计
  → Harness 生成与构建
  → ASan / AFL++ / eBPF 动态验证
  → 风险裁决与报告
```

项目由三个主要部分组成：

- `sentinel_agent`：负责七阶段分析流程、CVE 查询、Harness 生成和动态验证；
- `sentinel_backend`：负责任务调度、接口、数据存储和沙箱管理；
- `sentinel_frontend`：用于提交任务、查看分析进度和审计结果。

更完整的实现说明放在 [`code/README.md`](code/README.md) 和 [`code/docs/ARCHITECTURE.md`](code/docs/ARCHITECTURE.md) 中。

## 仓库里有什么

```text
.
├── code/          比赛最终版本的源码和技术文档
├── materials/     项目文档与答辩 PPT
├── assets/        合影与获奖证书
└── README.md      你正在看的说明
```

比赛材料可以直接查看或下载：

- [项目文档（PDF）](materials/SC-SENTINEL-项目文档.pdf)
- [答辩 PPT（PPTX）](materials/SC-SENTINEL-答辩PPT.pptx)

如果只是想快速了解整个项目，先看项目文档和答辩 PPT 会比直接读代码轻松一些。

`code/` 对应原项目 `main` 分支提交 `26bc50bbd9bb934a6822eafdb73b87dc08e632c9`。

## 跑起来

完整的环境和部署说明见 [`code/README.md`](code/README.md)。使用 Docker Compose 时，最短的启动流程是：

```bash
cd code
cp .env.example .env
# 编辑 .env，至少设置 POSTGRES_PASSWORD
docker compose up -d --build
```

默认入口：

- 前端：<http://localhost:8080>
- 后端 OpenAPI：<http://localhost:18000/docs>
- 健康检查：<http://localhost:18000/health/ready>

这是比赛结束时的归档版本，环境、模型接口和部分依赖可能会随时间变化。如果准备继续开发，建议先跑通一条最短审计链路，再逐步替换或扩展其中的模块。

## 赛后复盘

这套系统最后跑通了从静态分析到动态验证的完整链路，但它仍然是一个在比赛周期内完成的版本。扫描耗时偏长，动态验证对运行环境比较敏感，规则覆盖和部署方式也还有改进空间。

如果准备从这个版本继续做，我们建议先把最短审计流程跑通，再分别处理性能、验证稳定性和规则扩展。项目文档里写的是比赛时的完整方案，代码则保留了当时真正实现的状态，两者对照着看会更清楚。

## 使用说明

原创代码采用 [Apache License 2.0](LICENSE)。照片、证书、项目文档和答辩 PPT 不在开源许可范围内；测试样例中也有采用其他许可证或仍需核验来源的内容，具体见 [NOTICE](NOTICE) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

漏洞样本仅用于安全研究、教学和授权测试。项目并未按生产环境标准进行持续维护，实际部署前请重新检查依赖、密钥、网络边界和沙箱配置。

想继续完善项目，可以阅读 [贡献说明](CONTRIBUTING.md)；发现安全问题，请按 [安全报告说明](SECURITY.md) 私下联系。
