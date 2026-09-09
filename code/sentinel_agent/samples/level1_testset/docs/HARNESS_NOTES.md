# Harness 生成说明

每个测试样本都使用统一入口：

```c
int main(int argc, char **argv);   /* 将 argv[1] 作为文件路径读取 */
```

公共头文件 `ctf_input.h` 提供：

| 辅助函数 | 用途 |
| --- | --- |
| `read_challenge_input(argc, argv, &n)` | 从文件或标准输入读取最多 4 KB 数据 |
| `has_byte(buf, n, c)` | 分支条件：输入是否包含字节 `c` |
| `byte_or(buf, n, idx, fallback)` | 安全读取指定位置的字节，越界时返回默认值 |

统一入口使 Harness 生成阶段可以复用同一模板，以 `fuzzer_test_one_input` 风格包装 `main`，无需为每个样本定制。原样本说明将该阶段称为 Agent D；当前七阶段流程中对应 Agent E。建议映射如下：

| CWE 类别 | 策略标识 | 种子目录 |
| --- | --- | --- |
| CWE-416 | `flag_path_trigger` | `seeds/uaf/` |
| CWE-415 | `flag_path_trigger` | `seeds/double_free/` |
| CWE-122 | `oversized_string_input` | `seeds/heap/` |
| CWE-121 | `oversized_string_input` | `seeds/stack/` |
| CWE-134 | `format_string_payload` | `seeds/fmt/` |

执行 `make afl` 后，生成的二进制程序位于 `build/<name>_afl`，支持 AFL++ 的 `@@` 参数替换。
