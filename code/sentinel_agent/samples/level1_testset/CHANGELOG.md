# 更新日志

这里记录 Sentinel-Bench 一级基准的主要变更。格式参考 [更新日志规范](https://keepachangelog.com/en/1.1.0/)，版本遵循 [语义化版本规范](https://semver.org/)。

## [1.0.0] - 2025-04-12

### 新增

- 20 个单文件 CWE 测试样本，覆盖 CWE-121、CWE-122、CWE-134、CWE-415、CWE-416 五类漏洞。
- 公共 `ctf_input.h` 头文件，提供文件与标准输入处理。
- 按漏洞类别划分的 `seeds/` 种子集。
- 支持 `-DENABLE_ASAN=ON` 与 `-DENABLE_AFL=ON` 的 CMake 构建。
- 提供 `normal`、`asan`、`afl`、`test`、`clean` 目标的 POSIX Makefile。
- [CWE 检测矩阵](docs/CWE_MATRIX.md)。

### 安全说明

整个测试集故意保留漏洞。集成前请阅读 [许可证](LICENSE) 与 [安全说明](SECURITY.md)。
