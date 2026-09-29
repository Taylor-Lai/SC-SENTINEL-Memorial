# 归档说明

整理日期：2026-09-29。

## 项目介绍

SC-SENTINEL 是基于多智能体的开源软件供应链二进制漏洞审计与验证系统。仓库项目介绍统一依据[项目文档](materials/SC-SENTINEL-项目文档.pdf)与[答辩 PPT](materials/SC-SENTINEL-答辩PPT.pptx)，采用四层架构与五智能体级联审计模型。

五类智能体包括依赖识别、漏洞假设、静态复核、验证工件和报告生成。核心技术涵盖漏洞假设驱动的级联审计、CWE 感知的 Harness 自动生成，以及 ASan、AFL++、eBPF 三源证据融合与漏洞类型纠偏。

## 归档内容

| 位置 | 内容 |
| --- | --- |
| 根目录 | 项目介绍、贡献指南、更新日志、引用信息与许可说明 |
| `code/` | 比赛源码、依赖清单、部署配置、技术文档与测试样本 |
| `materials/` | 63 页项目文档与 19 页答辩 PPT（展示版、源文件） |
| `assets/` | 团队合影与全国一等奖获奖证书 |
| `.github/` | 归档检查工作流、Issue 与 PR 模板 |
| `scripts/` | 归档完整性与文档导航检查脚本 |

`code/` 的核心源码保留首次上传提交 `ce5a1308b7daceb2de8f3b537fddbd325b31c7a0` 的内容；模块文档、Docker 配置与依赖兼容约束完成同步整理，移除缺少 TaskIQ 依赖的旧 Poetry 锁文件，统一使用 pip 安装清单。`code/SC-SENTINEL答辩ppt.pptx` 与 `materials/SC-SENTINEL-答辩PPT.pptx` 为展示版演示文稿的两个副本，资料阅读入口统一放在 `materials/`，PPT 源文件以 Git LFS 单独保存。

## 整理与检查

- 依据项目文档与 PPT 统一项目名称、智能体职责、总体架构和核心技术介绍。
- 整理主页文案、系统架构图、学习导航、比赛图片与资料入口。
- 按明确的部署与文档整理清单核对文件集合，其余原始文件逐一检查 Git 内容哈希。
- 检查仓库说明中的本地链接、章节锚点、图片和材料路径。
- 保留三模块源码结构，排除本地环境、运行产物与临时文件。

在仓库根目录执行 `python scripts/check_archive.py` 可完成源码归档与文档导航检查。脚本使用 Python 标准库与 Git；运行时需保留首次上传提交的历史，CI 采用完整历史检出。

整理记录见[更新日志](CHANGELOG.md)，资料归属见[NOTICE](NOTICE)，第三方组件声明见[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

[返回项目主页](README.md)
