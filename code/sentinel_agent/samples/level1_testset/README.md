# Sentinel-Bench Level 1: Single-File CWE Microbenchmarks

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](VERSION)
[![CWE Coverage](https://img.shields.io/badge/CWE-121%2F122%2F134%2F415%2F416-orange.svg)](docs/CWE_MATRIX.md)

A curated micro-benchmark suite of 20 self-contained C programs, each
demonstrating one well-defined memory-safety vulnerability class. The suite
is modeled after the format of `google/fuzzbench` and `oss-fuzz`
benchmarks: every challenge accepts a single file argument (or stdin) and
is intended to be compiled stand-alone with ASan or instrumented with
AFL++ for crash reproduction.

This is **Level 1** of the Sentinel-Bench benchmark hierarchy:

| Level | Shape                    | Purpose                                     |
|-------|--------------------------|---------------------------------------------|
| 1     | Single-file CTF targets  | Detection-rate / harness-generation testing |
| 2     | Multi-file CVE replicas  | End-to-end audit pipeline validation        |

---

## CWE Coverage

| CWE     | Vulnerability Class       | Variants                                                                                          |
|---------|---------------------------|---------------------------------------------------------------------------------------------------|
| CWE-416 | Use-After-Free            | `uaf_direct.c`, `uaf_cross_function.c`, `uaf_array_slot.c`, `uaf_struct_field.c`                  |
| CWE-415 | Double Free               | `double_free_direct.c`, `double_free_alias.c`, `double_free_cleanup.c`, `double_free_error_path.c`|
| CWE-122 | Heap Buffer Overflow      | `heap_overflow_strcpy.c`, `heap_overflow_memcpy_len.c`, `heap_overflow_off_by_one.c`, `heap_overflow_integer_trunc.c` |
| CWE-121 | Stack Buffer Overflow     | `stack_overflow_strcpy.c`, `stack_overflow_sprintf.c`, `stack_overflow_index.c`, `stack_overflow_loop.c` |
| CWE-134 | Format String Vulnerability | `format_string_printf.c`, `format_string_fprintf.c`, `format_string_snprintf.c`, `format_string_syslog_like.c` |

See [docs/CWE_MATRIX.md](docs/CWE_MATRIX.md) for the full detection matrix.

---

## Build

```bash
# Plain build (all 20 targets)
make

# AddressSanitizer build (for crash confirmation)
make asan

# AFL++ instrumented build (for fuzzing)
make afl

# Run regression smoke tests
make test
```

Or with CMake:

```bash
mkdir build && cd build
cmake .. -DENABLE_ASAN=ON
make -j$(nproc)
ctest
```

---

## Usage

```bash
# Direct invocation
./uaf_direct seeds/uaf/default.bin

# AFL++ fuzzing
afl-fuzz -i seeds/uaf -o out -- ./uaf_direct_afl @@
```

If no file is supplied each target falls back to stdin and a built-in
default trigger string (defined in `ctf_input.h`).

---

## Disclaimer

These programs are **synthetic** and intentionally vulnerable. They are
designed for benchmarking static analyzers, fuzzers, and harness
generators. They do not reproduce specific real-world CVEs verbatim, but
their patterns are taken from common production bug classes.

Do not link, deploy, or copy this code into any networked service.

---

## License

MIT — see [LICENSE](LICENSE).
