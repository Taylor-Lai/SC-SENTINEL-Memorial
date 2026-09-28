# minivp8

minivp8 is a compact C99 component used for local parsing and diagnostics workflows. Small VP8L-style Huffman table loader for image metadata experiments.

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
./webp_huff sample.input
```

Library users can include `webp_huff.h` and call the public parser API declared there.

## License

BSD-3-Clause.
