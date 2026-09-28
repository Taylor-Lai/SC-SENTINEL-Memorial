# Security Policy

## Intentionally Vulnerable Code

**Every program in this directory contains at least one deliberate
memory-safety bug.** The suite exists solely to evaluate the detection
capability of static analyzers, fuzzers, sanitizers, and audit tooling.

Do **NOT**:

- Deploy any binary from this suite to a production environment.
- Expose any of these programs over a network socket.
- Reuse the source patterns in real applications.
- Run untrusted input files through these binaries on a machine that
  holds sensitive data.

## Reporting Vulnerabilities

Because every bug here is intentional, traditional CVE-style reporting
does not apply. If you discover a vulnerability **not represented in the
[CWE matrix](docs/CWE_MATRIX.md)** (i.e. an unintended bug), please file
an issue describing the pattern and the affected file.

## Supported Versions

| Version | Supported            |
|---------|----------------------|
| 1.0.x   | :white_check_mark:   |
| < 1.0   | :x:                  |
