# Sentinel-Bench 一级基准：单文件 CWE 测试集

[![许可证](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![版本](https://img.shields.io/badge/version-1.0.0-green.svg)](VERSION)
[![CWE 覆盖范围](https://img.shields.io/badge/CWE-121%2F122%2F134%2F415%2F416-orange.svg)](docs/CWE_MATRIX.md)

本测试集包含 20 个独立的 C 程序，每个程序展示一种明确的内存安全漏洞。组织方式参考 `google/fuzzbench` 与 `oss-fuzz`：各样本接受一个文件参数或标准输入，可单独使用 ASan 编译，或通过 AFL++ 插桩进行崩溃复现。

这是 Sentinel-Bench 分级基准中的第一级：

| 级别 | 形式 | 用途 |
| --- | --- | --- |
| 1 | 单文件 CTF 样本 | 检出率与 Harness 生成测试 |
| 2 | 多文件 CVE 复现模型 | 端到端审计流程验证 |

## CWE 覆盖范围

| CWE | 漏洞类型 | 样本 |
| --- | --- | --- |
| CWE-416 | 释放后使用 | `uaf_direct.c`、`uaf_cross_function.c`、`uaf_array_slot.c`、`uaf_struct_field.c` |
| CWE-415 | 重复释放 | `double_free_direct.c`、`double_free_alias.c`、`double_free_cleanup.c`、`double_free_error_path.c` |
| CWE-122 | 堆缓冲区溢出 | `heap_overflow_strcpy.c`、`heap_overflow_memcpy_len.c`、`heap_overflow_off_by_one.c`、`heap_overflow_integer_trunc.c` |
| CWE-121 | 栈缓冲区溢出 | `stack_overflow_strcpy.c`、`stack_overflow_sprintf.c`、`stack_overflow_index.c`、`stack_overflow_loop.c` |
| CWE-134 | 格式化字符串漏洞 | `format_string_printf.c`、`format_string_fprintf.c`、`format_string_snprintf.c`、`format_string_syslog_like.c` |

完整对应关系见 [CWE 检测矩阵](docs/CWE_MATRIX.md)。

## 构建

```bash
# 普通构建（全部 20 个目标）
make

# 使用 AddressSanitizer 构建，确认崩溃
make asan

# 使用 AFL++ 插桩构建，进行模糊测试
make afl

# 运行回归冒烟测试
make test
```

也可以使用 CMake：

```bash
mkdir build && cd build
cmake .. -DENABLE_ASAN=ON
make -j$(nproc)
ctest
```

## 使用方法

```bash
# 直接运行
./uaf_direct seeds/uaf/default.bin

# AFL++ 模糊测试
afl-fuzz -i seeds/uaf -o out -- ./uaf_direct_afl @@
```

未提供文件时，各目标会回退到标准输入及 `ctf_input.h` 中定义的内置默认触发字符串。

## 使用说明

这些程序是故意包含漏洞的人工样本，用于评估静态分析器、模糊测试工具与 Harness 生成器。它们参考常见的软件缺陷类型，并非对某个真实 CVE 的原样复现。

请勿将这些代码链接、部署或复制到任何联网服务中。

## 许可证

MIT，见 [LICENSE](LICENSE)。
