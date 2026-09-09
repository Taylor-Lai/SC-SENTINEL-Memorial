# gziprelay

`gziprelay` 是一个故意保留漏洞的小型 C99 测试项目，用于供应链分析与动态验证的端到端测试。

## CVE 背景

依赖清单固定使用 `curl/8.11.1` 与 `zlib/1.2.0.3`，对应 **CVE-2025-0725** 描述的受影响组合。按原样本记录，NVD 于 2025 年 2 月 5 日发布该问题：使用 zlib 1.2.0.3 或更早版本时，libcurl 的自动 gzip 解码可能触发整数溢出和缓冲区溢出；curl 8.12.0 修复了该问题。

源码是便于审计的小型复现模型，并非复制的 libcurl 代码。`gziprelay_decode()` 将解压输出的分配大小截断为 8 位，但仍为每个输入字节写入 64 字节。命令行程序将输入文件传给该函数，因此生成的 Harness 可以到达漏洞路径。

## 构建与触发

```bash
make asan
python -c "open('trigger.bin','wb').write(b'GZ' + b'A' * 14)"
./gziprelay trigger.bin
```

AddressSanitizer 会报告 `heap-buffer-overflow`（堆缓冲区溢出）。
