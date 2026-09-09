# minivp8

minivp8 是用于本地解析与诊断的小型 C99 组件。用于图像元数据实验的小型 VP8L 风格 Huffman 表加载器。

## 功能

- 一个静态库，附带小型命令行程序。
- 除 C 标准库外，无其他必需的运行时依赖。
- 支持 POSIX make 或 CMake 构建。
- 支持通过文件参数或标准输入读取数据。

## 构建

```bash
make
make test
```

也支持使用 CMake：

```bash
cmake -B build
cmake --build build -j
ctest --test-dir build
```

## 使用方法

```bash
./webp_huff sample.input
```

作为库使用时，可以包含 `webp_huff.h` 并调用其中声明的公共解析接口。

## 许可证

BSD-3-Clause.
