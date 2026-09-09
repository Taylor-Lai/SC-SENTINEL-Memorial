# 第三方声明

仓库级 Apache License 2.0 仅适用于 SC-SENTINEL 的原创代码与文档。下列测试样本在完成来源核验前，不纳入该授权范围。具有独立有效许可声明的文件或目录，继续遵循其自身许可。

## 附带的测试组件

| 相对于 `code/sentinel_agent/samples/` 的路径 | 组件 | 许可证 |
| --- | --- | --- |
| `level1_testset/` | SENTINEL 一级漏洞测试集 | MIT |
| `level2_testset/01_textkit/` | microjson / 基于 cJSON 的测试组件 | MIT |
| `level2_testset/02_imagepipe/` | pngreader 测试组件 | zlib |
| `level2_testset/03_fieldbus/` | modlite 测试组件 | LGPL |
| `level2_testset/03_fieldbus_fixed/` | 修复后的 modlite 测试组件 | LGPL |
| `level2_testset/04_astcore/` | astlite 测试组件 | MIT |
| `level2_testset/05_chunkstream/` | httpdecode 测试组件 | MIT |
| `level2_testset/06_audiodec/` | sndmini 测试组件 | LGPL |
| `level2_testset/07_imagecodec/` | minivp8 测试组件 | BSD-3-Clause |
| `level2_testset/08_proxyroute/` | sockmini 测试组件 | MIT |
| `level2_testset/09_resolver/` | resmini 测试组件 | BSD-2-Clause |
| `level2_testset/10_authframe/` | ntlmlite 测试组件 | MIT |
| `level2_testset/11_tunnelctl/` | httptunnel 测试组件 | MIT |
| `level2_testset/12_sshscan/` | sshmini 测试组件 | BSD-2-Clause |
| `level2_testset/14_logutil/` | sudolite 测试组件 | ISC |

`level1_testset/` 与 `01_textkit/` 目录包含完整的 MIT 许可证文本。多数其他二级样本目录目前只有一行许可证名称，缺少完整条款与署名信息。上表仅记录这些标注，标注本身不足以构成完整的许可材料。

公开发布或再分发前，维护者必须对每个受影响目录完成下列事项之一：

1. 补充上游来源、准确版本、版权所有者与完整许可证文本；
2. 确认组件完全原创，并在获得所有贡献者同意后选择许可证；
3. 从公开分发内容中移除该组件。

完成核验前，不应将这些样本视为已按 Apache-2.0 授权，也不应单独再分发。

## 依赖清单

Python、JavaScript、容器与 C/C++ 依赖清单引用了独立分发的软件包。各软件包的版权归其作者所有，并遵循各自许可证。再分发构建产物前，应生成最新依赖清单，核验实际解析版本的许可条款。

## 纪念资料

[NOTICE](NOTICE) 中列出的照片、获奖证书、演示文稿与项目文档不属于开源软件，不纳入 Apache-2.0 授权范围。复用时可能需要取得相关权利人的许可。
