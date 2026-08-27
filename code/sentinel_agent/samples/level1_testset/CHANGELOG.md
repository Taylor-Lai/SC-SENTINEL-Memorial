# Changelog

All notable changes to **Sentinel-Bench Level 1** are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the suite follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2025-04-12

### Added
- 20 single-file CWE microbenchmarks across 5 vulnerability classes
  (CWE-121, CWE-122, CWE-134, CWE-415, CWE-416).
- Shared `ctf_input.h` harness header providing file/stdin input plumbing.
- `seeds/` corpus partitioned by vulnerability class.
- CMake build supporting `-DENABLE_ASAN=ON` and `-DENABLE_AFL=ON`.
- POSIX Makefile with `normal`, `asan`, `afl`, `test`, `clean` targets.
- CWE detection matrix in `docs/CWE_MATRIX.md`.

### Security
- The entire suite is intentionally vulnerable. See [LICENSE](LICENSE)
  and [SECURITY.md](SECURITY.md) before integrating.
