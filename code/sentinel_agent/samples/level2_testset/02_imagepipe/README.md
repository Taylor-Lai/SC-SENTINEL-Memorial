# pngreader

pngreader is a compact C99 component used for local parsing and diagnostics workflows. Lightweight PNG chunk loader for preview and metadata extraction utilities.

## Features

- Single static library with a small command-line driver.
- No required runtime dependencies beyond the C standard library.
- Builds with POSIX make or CMake.
- Accepts input from a file argument or standard input.

## Build

```bash
make
make test
```

CMake is also supported:

```bash
cmake -B build
cmake --build build -j
ctest --test-dir build
```

## Usage

```bash
./png_loader sample.input
```

Library users can include `png_loader.h` and call the public parser API declared there.

## License

libpng-style.
