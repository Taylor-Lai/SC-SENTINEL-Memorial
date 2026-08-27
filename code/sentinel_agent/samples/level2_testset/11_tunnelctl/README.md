# httptunnel

httptunnel is a compact C99 component used for local parsing and diagnostics workflows. HTTP CONNECT proxy response handler for tunnel setup tools.

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
./proxy_tunnel sample.input
```

Library users can include `proxy_tunnel.h` and call the public parser API declared there.

## License

MIT.
