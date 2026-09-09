# pngreader

pngreader 是用于本地解析与诊断的小型 C99 组件。用于预览与元数据提取的轻量 PNG 数据块加载器。

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
./png_loader sample.input
```

作为库使用时，可以包含 `png_loader.h` 并调用其中声明的公共解析接口。

## 许可证

libpng 风格许可证（原标注：`libpng-style`）。
