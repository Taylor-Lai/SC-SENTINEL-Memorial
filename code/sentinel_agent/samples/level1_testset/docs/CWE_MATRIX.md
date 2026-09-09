# CWE 检测矩阵：Sentinel-Bench 一级基准

每行对应一个测试样本。“检测工具”列表示使用 `seeds/<class>/poc.bin` 作为输入时，预期能够检测到该问题的运行时工具。

## CWE-416 — 释放后使用

| 样本                  | 触发方式                                            | 检测工具 |
|----------------------------|----------------------------------------------------|-----------|
| `uaf_direct.c`             | 对堆对象依次输入字节 `'D'` 与 `'S'`，先释放再解引用 | ASan      |
| `uaf_cross_function.c`     | 辅助函数释放对象后，调用者继续使用         | ASan      |
| `uaf_array_slot.c`         | 槽位释放后，通过索引再次访问并打印       | ASan      |
| `uaf_struct_field.c`       | 所属结构体释放后，解引用其内部字段      | ASan      |

## CWE-415 — 重复释放

| 样本                    | 触发方式                                            | 检测工具 |
|------------------------------|----------------------------------------------------|-----------|
| `double_free_direct.c`       | 连续两个代码块释放同一指针        | glibc / ASan |
| `double_free_alias.c`        | 同一分配对象的两个别名均被释放           | glibc / ASan |
| `double_free_cleanup.c`      | 清理路径再次释放正常路径已释放的指针 | glibc / ASan |
| `double_free_error_path.c`   | 错误分支释放后，继续执行时再次释放  | glibc / ASan |

## CWE-122 — 堆缓冲区溢出

| 样本                            | 触发方式                                       | 检测工具 |
|--------------------------------------|-----------------------------------------------|-----------|
| `heap_overflow_strcpy.c`             | 使用 `strcpy` 将可控输入复制到 16 字节堆缓冲区  | ASan      |
| `heap_overflow_memcpy_len.c`         | `memcpy` 长度来自输入且未经检查         | ASan      |
| `heap_overflow_off_by_one.c`         | 循环越过分配边界多写一个字节          | ASan      |
| `heap_overflow_integer_trunc.c`      | 分配前将大小截断为 8 位     | ASan      |

## CWE-121 — 栈缓冲区溢出

| 样本                       | 触发方式                                       | 检测工具 |
|---------------------------------|-----------------------------------------------|-----------|
| `stack_overflow_strcpy.c`       | 使用 `strcpy` 将可控输入复制到 32 字节栈缓冲区 | ASan      |
| `stack_overflow_sprintf.c`      | 使用 `sprintf("%s", input)` 写入小型栈缓冲区   | ASan      |
| `stack_overflow_index.c`        | 计算得到的索引越过栈数组末尾    | ASan      |
| `stack_overflow_loop.c`         | 由输入长度控制且未限制边界的复制循环    | ASan      |

## CWE-134 — 格式化字符串漏洞

| 样本                          | 触发方式                                       | 检测工具 |
|------------------------------------|-----------------------------------------------|-----------|
| `format_string_printf.c`           | `printf(user_input)`                          | 静态分析    |
| `format_string_fprintf.c`          | `fprintf(stderr, user_input)`                 | 静态分析    |
| `format_string_snprintf.c`         | `snprintf(buf, n, user_input)`                | 静态分析    |
| `format_string_syslog_like.c`      | 日志宏将不可信输入作为格式化字符串传递  | 静态分析    |

说明：ASan 不一定能捕获格式化字符串漏洞。这些样本主要用于评估静态分析流程的检出率，原样本说明中对应 Agent C。
